//! `keyring gh export <dir>` and `keyring gh import [<dir-or-file>]` — sync
//! GitHub CLI (`gh`) credentials between OS keyrings and headless machines.
//!
//! Why this exists:
//! GitHub enforces a 10-token cap per user per OAuth application (`GitHub CLI`).
//! Running `gh auth login` independently on each VM mints a fresh `gho_...`
//! OAuth token and silently revokes the oldest token once the cap is exceeded,
//! breaking `gh` on other machines (`The token in keyring is invalid`).
//!
//! How `gh` (`cli/cli`) stores credentials:
//! - Config directory resolution (`cli/go-gh`):
//!   1. `$GH_CONFIG_DIR`
//!   2. `$XDG_CONFIG_HOME/gh`
//!   3. `%AppData%\GitHub CLI` (Windows)
//!   4. `~/.config/gh`
//! - Keyring entries via `zalando/go-keyring`:
//!   - Service name: `gh:<hostname>` (e.g. `gh:github.com`)
//!   - Per-user account: `<username>` (e.g. `alice`)
//!   - Active-user mirror account: `""` (empty username, written by
//!     `AuthConfig.setActiveCredential` in `cli/cli`)
//!   - On macOS, `zalando/go-keyring` prefixes stored values with
//!     `go-keyring-base64:` + standard Base64 and invokes `/usr/bin/security`
//!     so `/usr/bin/security` owns the Keychain item ACL.
//!   - On Windows, `zalando/go-keyring` uses GenericCredential with
//!     `TargetName = "gh:<hostname>:<username>"` and raw UTF-8 bytes.
//!   - On Linux, `zalando/go-keyring` uses Secret Service (`service` and
//!     `username` attributes) with raw UTF-8 bytes.
const std = @import("std");
const builtin = @import("builtin");
const keyring_zig = @import("keyring_zig");
const msal_cache = @import("msal_cache.zig");
const keychain = @import("keychain.zig");
const wincred = @import("wincred.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const hosts_filename = "hosts.yml";
const base64_prefix = "go-keyring-base64:";
const hex_prefix = "go-keyring-encoded:";

pub const SecretError = error{
    EntryNotFound,
    NoStorageAccess,
    Locked,
    StorageFailure,
    OutOfMemory,
};

pub const SecretStore = struct {
    get: *const fn (gpa: Allocator, service: []const u8, account: []const u8) SecretError![]u8,
    set: *const fn (gpa: Allocator, service: []const u8, account: []const u8, value: []const u8) SecretError!void,
};

const live_secret_store: SecretStore = .{
    .get = liveSecretGet,
    .set = liveSecretSet,
};

/// Test-only overrides so unit tests never touch the real user config or OS keyring.
var secret_store_override: ?SecretStore = null;
var gh_config_dir_override: ?[]const u8 = null;

fn activeSecretStore() SecretStore {
    return secret_store_override orelse live_secret_store;
}

pub const KeyValue = struct {
    key: []const u8,
    value: []const u8,
};

pub const UserConfig = struct {
    username: []const u8,
    oauth_token: ?[]const u8 = null,
};

pub const HostConfig = struct {
    hostname: []const u8,
    git_protocol: ?[]const u8 = null,
    active_user: ?[]const u8 = null,
    oauth_token: ?[]const u8 = null,
    users: std.ArrayListUnmanaged(UserConfig) = .empty,
    extra_fields: std.ArrayListUnmanaged(KeyValue) = .empty,

    pub fn findUserIndex(self: *const HostConfig, username: []const u8) ?usize {
        for (self.users.items, 0..) |u, idx| {
            if (std.mem.eql(u8, u.username, username)) return idx;
        }
        return null;
    }

    pub fn upsertUser(self: *HostConfig, gpa: Allocator, username: []const u8, oauth_token: ?[]const u8) !void {
        if (self.findUserIndex(username)) |idx| {
            if (oauth_token) |tok| {
                self.users.items[idx].oauth_token = try gpa.dupe(u8, tok);
            }
            return;
        }
        try self.users.append(gpa, .{
            .username = try gpa.dupe(u8, username),
            .oauth_token = if (oauth_token) |tok| try gpa.dupe(u8, tok) else null,
        });
    }
};

pub const FormatMode = enum {
    /// Emit plaintext `oauth_token` entries under each user and at host level
    /// for the active user (for `keyring gh export` / headless machines).
    plaintext,
    /// Omit `oauth_token` entries so `gh` reads tokens from the OS keyring.
    keyring,
};

/// Run `keyring gh export <dir>`.
pub fn runExport(
    gpa: Allocator,
    dest_dir_path: []const u8,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const config_dir = resolveGhConfigDir(a) orelse {
        try stderr.writeAll("keyring: gh export: could not resolve gh config directory (HOME not set)\n");
        try stderr.flush();
        return 1;
    };

    const hosts_path = try std.fs.path.join(a, &.{ config_dir, hosts_filename });
    const content = readFileIfExists(a, hosts_path) orelse {
        try stderr.print(
            "keyring: gh export: no GitHub CLI config found at {s} (run 'gh auth login' first)\n",
            .{hosts_path},
        );
        try stderr.flush();
        return 3;
    };

    const hosts = try parseHostsYaml(a, content);
    if (hosts.items.len == 0) {
        try stderr.print("keyring: gh export: no hosts configured in {s}\n", .{hosts_path});
        try stderr.flush();
        return 3;
    }

    const store = activeSecretStore();
    var exported_hosts: usize = 0;
    var exported_users: usize = 0;
    var missing_users: usize = 0;
    var saw_locked = false;
    var saw_no_access = false;

    for (hosts.items) |*host| {
        const service = try keyringServiceName(a, host.hostname);
        var host_had_token = false;

        for (host.users.items) |*user| {
            const is_active = if (host.active_user) |active|
                std.mem.eql(u8, active, user.username)
            else
                false;

            if (resolveUserToken(a, store, service, user.username, is_active, user.oauth_token, host.oauth_token)) |tok| {
                user.oauth_token = tok;
                if (is_active) {
                    host.oauth_token = tok;
                }
                exported_users += 1;
                host_had_token = true;
            } else |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Locked => {
                    saw_locked = true;
                    missing_users += 1;
                },
                error.NoStorageAccess => {
                    saw_no_access = true;
                    missing_users += 1;
                },
                else => {
                    missing_users += 1;
                },
            }
        }

        // Ensure host.oauth_token reflects the active user's resolved token.
        if (host.active_user) |active| {
            if (host.findUserIndex(active)) |idx| {
                if (host.users.items[idx].oauth_token) |tok| {
                    host.oauth_token = tok;
                }
            }
        }

        if (host_had_token) exported_hosts += 1;
    }

    if (exported_users == 0) {
        if (saw_locked) {
            try stderr.writeAll("keyring: gh export: keyring is locked (run 'keyring unlock' first)\n");
            try stderr.flush();
            return 1;
        }
        if (saw_no_access) {
            try stderr.writeAll("keyring: gh export: no storage access to OS keyring\n");
            try stderr.flush();
            return 4;
        }
        try stderr.print(
            "keyring: gh export: no GitHub tokens found in keyring or {s}\n",
            .{hosts_path},
        );
        try stderr.flush();
        return 3;
    }

    const rendered = try formatHostsYaml(a, hosts.items, .plaintext);
    const out_path = try std.fs.path.join(a, &.{ dest_dir_path, hosts_filename });
    writePrivateFile(dest_dir_path, hosts_filename, rendered) catch |err| {
        try stderr.print("keyring: gh export: failed to write {s}: {s}\n", .{ out_path, @errorName(err) });
        try stderr.flush();
        return 4;
    };

    try stdout.print("Exported GitHub CLI credentials to {s}:\n", .{dest_dir_path});
    for (hosts.items) |host| {
        for (host.users.items) |user| {
            if (user.oauth_token != null) {
                const active_suffix = if (host.active_user != null and std.mem.eql(u8, host.active_user.?, user.username))
                    " (active)"
                else
                    "";
                try stdout.print("  {s}: {s}{s}\n", .{ host.hostname, user.username, active_suffix });
            }
        }
    }
    if (missing_users > 0) {
        try stderr.print(
            "keyring: gh export: warning: skipped {d} account(s) with no token in keyring\n",
            .{missing_users},
        );
        try stderr.flush();
    }
    try stdout.print(
        "\nCopy to a headless machine:\n  scp {s} <host>:~/.config/gh/hosts.yml\n" ++
            "Or import into another machine's keyring:\n  keyring gh import {s}\n",
        .{ out_path, dest_dir_path },
    );
    try stdout.flush();
    return 0;
}

/// Run `keyring gh import [<dir-or-file>]`.
///
/// When `source_arg` is:
/// - `null`: reads local `<gh_config_dir>/hosts.yml` (migrating plaintext
///   `oauth_token` entries into the OS keyring in place).
/// - `"-"`: reads `hosts.yml` content from `stdin`.
/// - a directory path (or path containing `hosts.yml`): reads `<dir>/hosts.yml`.
/// - a file path: reads that file directly.
pub fn runImport(
    gpa: Allocator,
    source_arg: ?[]const u8,
    stdin: *Io.Reader,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const config_dir = resolveGhConfigDir(a) orelse {
        try stderr.writeAll("keyring: gh import: could not resolve gh config directory (HOME not set)\n");
        try stderr.flush();
        return 1;
    };
    const local_hosts_path = try std.fs.path.join(a, &.{ config_dir, hosts_filename });

    const source_content = try loadImportSource(a, source_arg, local_hosts_path, stdin, stderr) orelse {
        return 3;
    };

    const imported_hosts = try parseHostsYaml(a, source_content);
    if (imported_hosts.items.len == 0) {
        try stderr.writeAll("keyring: gh import: no hosts found in input\n");
        try stderr.flush();
        return 3;
    }

    const store = activeSecretStore();
    var imported_users: usize = 0;

    for (imported_hosts.items) |host| {
        const service = try keyringServiceName(a, host.hostname);
        for (host.users.items) |user| {
            const token = user.oauth_token orelse continue;
            store.set(a, service, user.username, token) catch |err| {
                try stderr.print(
                    "keyring: gh import: failed to store token for {s} ({s}) in keyring: {s}\n",
                    .{ user.username, host.hostname, @errorName(err) },
                );
                try stderr.flush();
                return switch (err) {
                    error.NoStorageAccess => 4,
                    else => 1,
                };
            };
            imported_users += 1;

            const is_active = if (host.active_user) |active|
                std.mem.eql(u8, active, user.username)
            else
                false;
            if (is_active) {
                store.set(a, service, "", token) catch |err| {
                    try stderr.print(
                        "keyring: gh import: failed to store active token for {s} in keyring: {s}\n",
                        .{ host.hostname, @errorName(err) },
                    );
                    try stderr.flush();
                    return switch (err) {
                        error.NoStorageAccess => 4,
                        else => 1,
                    };
                };
            }
        }
    }

    if (imported_users == 0) {
        try stderr.writeAll("keyring: gh import: no oauth_token entries found to import\n");
        try stderr.flush();
        return 3;
    }

    // Load existing local hosts.yml (if present) and merge imported hosts/users.
    var merged_hosts = if (readFileIfExists(a, local_hosts_path)) |existing_yaml|
        try parseHostsYaml(a, existing_yaml)
    else
        std.ArrayListUnmanaged(HostConfig).empty;

    try mergeHosts(a, &merged_hosts, imported_hosts.items);

    const rendered = try formatHostsYaml(a, merged_hosts.items, .keyring);
    writePrivateFile(config_dir, hosts_filename, rendered) catch |err| {
        try stderr.print("keyring: gh import: failed to write {s}: {s}\n", .{ local_hosts_path, @errorName(err) });
        try stderr.flush();
        return 4;
    };

    try stdout.print("Imported {d} GitHub CLI account(s) into keyring and updated {s}:\n", .{
        imported_users,
        local_hosts_path,
    });
    for (imported_hosts.items) |host| {
        for (host.users.items) |user| {
            if (user.oauth_token != null) {
                const active_suffix = if (host.active_user != null and std.mem.eql(u8, host.active_user.?, user.username))
                    " (active)"
                else
                    "";
                try stdout.print("  {s}: {s}{s}\n", .{ host.hostname, user.username, active_suffix });
            }
        }
    }
    try stdout.flush();
    return 0;
}

fn loadImportSource(
    gpa: Allocator,
    source_arg: ?[]const u8,
    local_hosts_path: []const u8,
    stdin: *Io.Reader,
    stderr: *Io.Writer,
) !?[]u8 {
    const arg = source_arg orelse {
        if (readFileIfExists(gpa, local_hosts_path)) |content| return content;
        try stderr.print("keyring: gh import: file not found: {s}\n", .{local_hosts_path});
        try stderr.flush();
        return null;
    };

    if (std.mem.eql(u8, arg, "-")) {
        var writer = Io.Writer.Allocating.init(gpa);
        errdefer writer.deinit();
        _ = stdin.streamRemaining(&writer.writer) catch {
            try stderr.writeAll("keyring: gh import: failed to read stdin\n");
            try stderr.flush();
            return null;
        };
        return try writer.toOwnedSlice();
    }

    // Check if `arg/hosts.yml` exists (directory argument).
    const candidate_in_dir = try std.fs.path.join(gpa, &.{ arg, hosts_filename });
    if (readFileIfExists(gpa, candidate_in_dir)) |content| return content;

    // Otherwise treat `arg` as a direct file path.
    if (readFileIfExists(gpa, arg)) |content| return content;

    try stderr.print("keyring: gh import: file not found: {s}\n", .{arg});
    try stderr.flush();
    return null;
}

fn resolveUserToken(
    gpa: Allocator,
    store: SecretStore,
    service: []const u8,
    username: []const u8,
    is_active: bool,
    user_plaintext_token: ?[]const u8,
    host_plaintext_token: ?[]const u8,
) SecretError![]u8 {
    // 1. Keyring entry for `gh:<hostname>` / `<username>`.
    var last_err: SecretError = error.EntryNotFound;
    if (store.get(gpa, service, username)) |tok| {
        if (tok.len > 0) return tok;
        gpa.free(tok);
    } else |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        last_err = err;
    }

    // 2. Active-user mirror slot `gh:<hostname>` / `""`.
    if (is_active) {
        if (store.get(gpa, service, "")) |tok| {
            if (tok.len > 0) return tok;
            gpa.free(tok);
        } else |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            if (last_err == error.EntryNotFound) last_err = err;
        }
    }

    // 3. Plaintext `oauth_token` in `hosts.yml` (user-level, then host-level for active user).
    if (user_plaintext_token) |tok| {
        if (tok.len > 0) return gpa.dupe(u8, tok);
    }
    if (is_active) {
        if (host_plaintext_token) |tok| {
            if (tok.len > 0) return gpa.dupe(u8, tok);
        }
    }

    return last_err;
}

pub fn keyringServiceName(gpa: Allocator, hostname: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "gh:{s}", .{hostname});
}

/// Decode a secret read from an OS keyring, stripping `zalando/go-keyring`'s
/// `go-keyring-base64:` or `go-keyring-encoded:` prefix if present.
pub fn decodeKeyringSecret(gpa: Allocator, raw: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (std.mem.startsWith(u8, trimmed, base64_prefix)) {
        const encoded = trimmed[base64_prefix.len..];
        const dec_len = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch
            return gpa.dupe(u8, trimmed);
        const out = try gpa.alloc(u8, dec_len);
        errdefer gpa.free(out);
        std.base64.standard.Decoder.decode(out, encoded) catch {
            gpa.free(out);
            return gpa.dupe(u8, trimmed);
        };
        return out;
    }
    if (std.mem.startsWith(u8, trimmed, hex_prefix)) {
        const encoded = trimmed[hex_prefix.len..];
        if (encoded.len % 2 != 0) return gpa.dupe(u8, trimmed);
        const out = try gpa.alloc(u8, encoded.len / 2);
        errdefer gpa.free(out);
        _ = std.fmt.hexToBytes(out, encoded) catch {
            gpa.free(out);
            return gpa.dupe(u8, trimmed);
        };
        return out;
    }
    return gpa.dupe(u8, trimmed);
}

/// Encode a raw token with `zalando/go-keyring`'s `go-keyring-base64:` prefix
/// used on macOS Keychain.
pub fn encodeDarwinKeyringSecret(gpa: Allocator, token: []const u8) ![]u8 {
    const enc_len = std.base64.standard.Encoder.calcSize(token.len);
    const out = try gpa.alloc(u8, base64_prefix.len + enc_len);
    @memcpy(out[0..base64_prefix.len], base64_prefix);
    _ = std.base64.standard.Encoder.encode(out[base64_prefix.len..], token);
    return out;
}

/// Parse a `hosts.yml` file into an ordered list of `HostConfig` entries.
pub fn parseHostsYaml(gpa: Allocator, content: []const u8) !std.ArrayListUnmanaged(HostConfig) {
    var hosts: std.ArrayListUnmanaged(HostConfig) = .empty;
    errdefer hosts.deinit(gpa);

    var current_host: ?*HostConfig = null;
    var in_users = false;
    var users_indent: usize = 0;
    var user_entry_indent: ?usize = null;
    var current_user_idx: ?usize = null;

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        const line_no_cr = std.mem.trimEnd(u8, raw_line, "\r");
        const trimmed = std.mem.trim(u8, line_no_cr, " \t");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        const indent = countIndent(line_no_cr);
        const kv = splitYamlKeyValue(trimmed) orelse continue;

        if (indent == 0) {
            if (current_host) |h| try finalizeHost(gpa, h);
            try hosts.append(gpa, .{
                .hostname = try gpa.dupe(u8, kv.key),
            });
            current_host = &hosts.items[hosts.items.len - 1];
            in_users = false;
            user_entry_indent = null;
            current_user_idx = null;
            continue;
        }

        const host = current_host orelse continue;

        if (in_users and indent <= users_indent) {
            in_users = false;
            user_entry_indent = null;
            current_user_idx = null;
        }

        if (in_users) {
            if (user_entry_indent == null or indent <= user_entry_indent.?) {
                user_entry_indent = indent;
                try host.users.append(gpa, .{
                    .username = try gpa.dupe(u8, kv.key),
                });
                current_user_idx = host.users.items.len - 1;
            } else if (current_user_idx) |u_idx| {
                if (std.mem.eql(u8, kv.key, "oauth_token") and ! isEmptyYamlValue(kv.value)) {
                    host.users.items[u_idx].oauth_token = try gpa.dupe(u8, kv.value);
                }
            }
            continue;
        }

        // Host-level key.
        if (std.mem.eql(u8, kv.key, "users")) {
            in_users = true;
            users_indent = indent;
            user_entry_indent = null;
            current_user_idx = null;
        } else if (std.mem.eql(u8, kv.key, "git_protocol")) {
            if (!isEmptyYamlValue(kv.value)) {
                host.git_protocol = try gpa.dupe(u8, kv.value);
            }
        } else if (std.mem.eql(u8, kv.key, "user")) {
            if (!isEmptyYamlValue(kv.value)) {
                host.active_user = try gpa.dupe(u8, kv.value);
            }
        } else if (std.mem.eql(u8, kv.key, "oauth_token")) {
            if (!isEmptyYamlValue(kv.value)) {
                host.oauth_token = try gpa.dupe(u8, kv.value);
            }
        } else {
            try host.extra_fields.append(gpa, .{
                .key = try gpa.dupe(u8, kv.key),
                .value = try gpa.dupe(u8, kv.value),
            });
        }
    }

    if (current_host) |h| try finalizeHost(gpa, h);
    return hosts;
}

fn finalizeHost(gpa: Allocator, host: *HostConfig) !void {
    if (host.active_user) |active| {
        if (host.findUserIndex(active)) |idx| {
            if (host.users.items[idx].oauth_token == null and host.oauth_token != null) {
                host.users.items[idx].oauth_token = try gpa.dupe(u8, host.oauth_token.?);
            }
        } else {
            try host.users.append(gpa, .{
                .username = try gpa.dupe(u8, active),
                .oauth_token = if (host.oauth_token) |tok| try gpa.dupe(u8, tok) else null,
            });
        }
    } else if (host.users.items.len > 0) {
        host.active_user = try gpa.dupe(u8, host.users.items[0].username);
        if (host.users.items[0].oauth_token == null and host.oauth_token != null) {
            host.users.items[0].oauth_token = try gpa.dupe(u8, host.oauth_token.?);
        }
    }
}

/// Merge `imported` hosts into `target`, preserving existing hosts and users
/// that are not overwritten.
pub fn mergeHosts(
    gpa: Allocator,
    target: *std.ArrayListUnmanaged(HostConfig),
    imported: []const HostConfig,
) !void {
    for (imported) |inc| {
        var found_host: ?*HostConfig = null;
        for (target.items) |*existing| {
            if (std.mem.eql(u8, existing.hostname, inc.hostname)) {
                found_host = existing;
                break;
            }
        }

        if (found_host == null) {
            try target.append(gpa, .{
                .hostname = try gpa.dupe(u8, inc.hostname),
            });
            found_host = &target.items[target.items.len - 1];
        }

        const dst = found_host.?;
        if (inc.git_protocol) |proto| {
            dst.git_protocol = try gpa.dupe(u8, proto);
        } else if (dst.git_protocol == null) {
            dst.git_protocol = try gpa.dupe(u8, "https");
        }

        if (inc.active_user) |active| {
            dst.active_user = try gpa.dupe(u8, active);
        }

        for (inc.users.items) |u| {
            try dst.upsertUser(gpa, u.username, u.oauth_token);
        }

        for (inc.extra_fields.items) |extra| {
            var updated = false;
            for (dst.extra_fields.items) |*dst_extra| {
                if (std.mem.eql(u8, dst_extra.key, extra.key)) {
                    dst_extra.value = try gpa.dupe(u8, extra.value);
                    updated = true;
                    break;
                }
            }
            if (!updated) {
                try dst.extra_fields.append(gpa, .{
                    .key = try gpa.dupe(u8, extra.key),
                    .value = try gpa.dupe(u8, extra.value),
                });
            }
        }

        if (dst.active_user == null and dst.users.items.len > 0) {
            dst.active_user = try gpa.dupe(u8, dst.users.items[0].username);
        }
    }
}

/// Serialize `hosts` into `hosts.yml` YAML format.
pub fn formatHostsYaml(gpa: Allocator, hosts: []const HostConfig, mode: FormatMode) ![]u8 {
    var out = Io.Writer.Allocating.init(gpa);
    errdefer out.deinit();

    for (hosts) |host| {
        try out.writer.print("{s}:\n", .{host.hostname});
        const proto = host.git_protocol orelse "https";
        try out.writer.print("    git_protocol: {s}\n", .{proto});

        if (host.users.items.len > 0) {
            try out.writer.writeAll("    users:\n");
            for (host.users.items) |user| {
                switch (mode) {
                    .plaintext => {
                        if (user.oauth_token) |tok| {
                            try out.writer.print(
                                "        {s}:\n            oauth_token: {s}\n",
                                .{ user.username, tok },
                            );
                        } else {
                            try out.writer.print("        {s}:\n", .{user.username});
                        }
                    },
                    .keyring => {
                        try out.writer.print("        {s}:\n", .{user.username});
                    },
                }
            }
        }

        if (host.active_user) |active| {
            try out.writer.print("    user: {s}\n", .{active});
        }

        if (mode == .plaintext) {
            const active_tok = host.oauth_token orelse blk: {
                if (host.active_user) |active| {
                    if (host.findUserIndex(active)) |idx| {
                        break :blk host.users.items[idx].oauth_token;
                    }
                }
                break :blk null;
            };
            if (active_tok) |tok| {
                try out.writer.print("    oauth_token: {s}\n", .{tok});
            }
        }

        for (host.extra_fields.items) |extra| {
            try out.writer.print("    {s}: {s}\n", .{ extra.key, extra.value });
        }
    }

    return out.toOwnedSlice();
}

fn countIndent(line: []const u8) usize {
    var n: usize = 0;
    for (line) |c| {
        if (c == ' ') {
            n += 1;
        } else if (c == '\t') {
            n += 4;
        } else {
            break;
        }
    }
    return n;
}

fn splitYamlKeyValue(trimmed: []const u8) ?KeyValue {
    const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse return null;
    const raw_key = std.mem.trim(u8, trimmed[0..colon], " \t");
    if (raw_key.len == 0) return null;
    const raw_val = std.mem.trim(u8, trimmed[colon + 1 ..], " \t");
    return .{
        .key = unquoteYamlScalar(raw_key),
        .value = unquoteYamlScalar(raw_val),
    };
}

fn unquoteYamlScalar(raw: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, raw, " \t");
    if (trimmed.len >= 2 and
        ((trimmed[0] == '"' and trimmed[trimmed.len - 1] == '"') or
            (trimmed[0] == '\'' and trimmed[trimmed.len - 1] == '\'')))
    {
        return trimmed[1 .. trimmed.len - 1];
    }
    // Strip unquoted inline comments (` #...`).
    for (trimmed, 0..) |c, idx| {
        if (c == '#' and idx > 0 and (trimmed[idx - 1] == ' ' or trimmed[idx - 1] == '\t')) {
            return std.mem.trimEnd(u8, trimmed[0..idx], " \t");
        }
    }
    return trimmed;
}

fn isEmptyYamlValue(val: []const u8) bool {
    return val.len == 0 or std.mem.eql(u8, val, "{}") or std.mem.eql(u8, val, "null") or std.mem.eql(u8, val, "~");
}

/// Resolve the GitHub CLI configuration directory following `cli/go-gh`:
/// 1. `$GH_CONFIG_DIR`
/// 2. `$XDG_CONFIG_HOME/gh`
/// 3. `%AppData%\GitHub CLI` (on Windows)
/// 4. `~/.config/gh`
pub fn resolveGhConfigDir(gpa: Allocator) ?[]u8 {
    if (gh_config_dir_override) |override| {
        return gpa.dupe(u8, override) catch null;
    }
    if (getEnvVarOwned(gpa, "GH_CONFIG_DIR")) |dir| {
        if (dir.len > 0) return dir;
        gpa.free(dir);
    }
    if (getEnvVarOwned(gpa, "XDG_CONFIG_HOME")) |xdg| {
        defer gpa.free(xdg);
        if (xdg.len > 0) {
            return std.fs.path.join(gpa, &.{ xdg, "gh" }) catch null;
        }
    }
    if (builtin.os.tag == .windows) {
        if (getEnvVarOwned(gpa, "AppData")) |appdata| {
            defer gpa.free(appdata);
            if (appdata.len > 0) {
                return std.fs.path.join(gpa, &.{ appdata, "GitHub CLI" }) catch null;
            }
        }
    }
    const home = msal_cache.getHome(gpa) orelse return null;
    defer gpa.free(home);
    return std.fs.path.join(gpa, &.{ home, ".config", "gh" }) catch null;
}

fn liveSecretGet(gpa: Allocator, service: []const u8, account: []const u8) SecretError![]u8 {
    if (builtin.os.tag == .macos) {
        if (keychain.get(gpa, service, account)) |raw| {
            defer gpa.free(raw);
            return decodeKeyringSecret(gpa, raw) catch return error.OutOfMemory;
        } else |err| switch (err) {
            error.EntryNotFound => return error.EntryNotFound,
            error.OutOfMemory => return error.OutOfMemory,
            error.NoStorageAccess, error.StorageFailure => {
                // Fall back to `/usr/bin/security` if the item's ACL only permits
                // `/usr/bin/security` without prompting.
                if (macosSecurityGet(gpa, service, account)) |raw| {
                    defer gpa.free(raw);
                    return decodeKeyringSecret(gpa, raw) catch return error.OutOfMemory;
                } else |sec_err| return sec_err;
            },
        }
    }

    if (builtin.os.tag == .windows) {
        const target = std.fmt.allocPrint(gpa, "{s}:{s}", .{ service, account }) catch
            return error.OutOfMemory;
        defer gpa.free(target);
        if (wincred.get(gpa, target)) |raw| {
            defer gpa.free(raw);
            return decodeKeyringSecret(gpa, raw) catch return error.OutOfMemory;
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {},
        }
    }

    const raw = keyring_zig.getAlloc(gpa, service, account) catch |err| return switch (err) {
        error.EntryNotFound => error.EntryNotFound,
        error.Locked => error.Locked,
        error.OutOfMemory => error.OutOfMemory,
        else => error.NoStorageAccess,
    };
    defer gpa.free(raw);
    return decodeKeyringSecret(gpa, raw) catch return error.OutOfMemory;
}

fn liveSecretSet(gpa: Allocator, service: []const u8, account: []const u8, value: []const u8) SecretError!void {
    if (builtin.os.tag == .macos) {
        const encoded = encodeDarwinKeyringSecret(gpa, value) catch return error.OutOfMemory;
        defer gpa.free(encoded);
        if (macosSecuritySet(gpa, service, account, encoded)) |_| {
            return;
        } else |_| {
            return keychain.set(service, account, encoded) catch |err| switch (err) {
                error.NoStorageAccess => error.NoStorageAccess,
                error.OutOfMemory => error.OutOfMemory,
                else => error.StorageFailure,
            };
        }
    }

    if (builtin.os.tag == .windows) {
        const target = std.fmt.allocPrint(gpa, "{s}:{s}", .{ service, account }) catch
            return error.OutOfMemory;
        defer gpa.free(target);
        return wincred.set(gpa, target, account, value) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.StorageFailure,
        };
    }

    return keyring_zig.setAlloc(gpa, service, account, value) catch |err| switch (err) {
        error.Locked => error.Locked,
        error.OutOfMemory => error.OutOfMemory,
        else => error.NoStorageAccess,
    };
}

fn macosSecurityGet(gpa: Allocator, service: []const u8, account: []const u8) SecretError![]u8 {
    var threaded = Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const argv = [_][]const u8{
        "/usr/bin/security",
        "find-generic-password",
        "-s",
        service,
        "-wa",
        account,
    };
    const result = std.process.run(gpa, io, .{
        .argv = &argv,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    }) catch return error.NoStorageAccess;
    errdefer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code != 0) {
            gpa.free(result.stdout);
            if (code == 44) return error.EntryNotFound;
            return error.NoStorageAccess;
        },
        else => {
            gpa.free(result.stdout);
            return error.NoStorageAccess;
        },
    }
    return result.stdout;
}

/// Write a generic password using `/usr/bin/security -i` (matching
/// `zalando/go-keyring` on macOS) so `/usr/bin/security` owns the Keychain item
/// ACL and `gh` can read it without triggering a Keychain GUI prompt.
fn macosSecuritySet(gpa: Allocator, service: []const u8, account: []const u8, encoded_value: []const u8) SecretError!void {
    var threaded = Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cmd = buildSecurityAddCommand(gpa, service, account, encoded_value) catch
        return error.OutOfMemory;
    defer gpa.free(cmd);

    var child = std.process.spawn(io, .{
        .argv = &.{ "/usr/bin/security", "-i" },
        .stdin = .pipe,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return error.StorageFailure;

    if (child.stdin) |stdin_file| {
        stdin_file.writeStreamingAll(io, cmd) catch {
            stdin_file.close(io);
            child.stdin = null;
            _ = child.wait(io) catch {};
            return error.StorageFailure;
        };
        stdin_file.close(io);
        child.stdin = null;
    }

    const term = child.wait(io) catch return error.StorageFailure;
    if (term != .exited or term.exited != 0) return error.StorageFailure;
}

pub fn buildSecurityAddCommand(
    gpa: Allocator,
    service: []const u8,
    account: []const u8,
    encoded_value: []const u8,
) ![]u8 {
    var out = Io.Writer.Allocating.init(gpa);
    errdefer out.deinit();
    try out.writer.writeAll("add-generic-password -U -s ");
    try writeSingleQuotedShellArg(&out.writer, service);
    try out.writer.writeAll(" -a ");
    try writeSingleQuotedShellArg(&out.writer, account);
    try out.writer.writeAll(" -w ");
    try writeSingleQuotedShellArg(&out.writer, encoded_value);
    try out.writer.writeByte('\n');
    return out.toOwnedSlice();
}

fn writeSingleQuotedShellArg(writer: *Io.Writer, value: []const u8) !void {
    try writer.writeByte('\'');
    for (value) |c| {
        if (c == '\'') {
            try writer.writeAll("'\\''");
        } else {
            try writer.writeByte(c);
        }
    }
    try writer.writeByte('\'');
}

fn readFileIfExists(gpa: Allocator, path: []const u8) ?[]u8 {
    const io = Io.Threaded.global_single_threaded.io();
    return Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(4 * 1024 * 1024)) catch null;
}

fn writePrivateFile(dir_path: []const u8, filename: []const u8, data: []const u8) !void {
    const io = Io.Threaded.global_single_threaded.io();
    try makePathPrivate(io, dir_path);

    var dir = try Io.Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);

    if (builtin.os.tag != .windows and builtin.os.tag != .wasi) {
        dir.setPermissions(io, .fromMode(0o700)) catch {};
    }

    const file = try dir.createFile(io, filename, .{
        .truncate = true,
        .permissions = if (builtin.os.tag == .windows or builtin.os.tag == .wasi)
            .default_file
        else
            .fromMode(0o600),
    });
    defer file.close(io);

    if (builtin.os.tag != .windows and builtin.os.tag != .wasi) {
        file.setPermissions(io, .fromMode(0o600)) catch {};
    }

    try file.writeStreamingAll(io, data);
}

fn makePathPrivate(io: Io, path: []const u8) !void {
    var end: usize = 0;
    while (end < path.len) {
        const rest = path[end..];
        const rel_sep = std.mem.indexOfAny(u8, rest, "/\\");
        const next_end = if (rel_sep) |idx| end + idx else path.len;
        if (next_end > 0) {
            const prefix = path[0..next_end];
            Io.Dir.cwd().createDir(
                io,
                prefix,
                if (builtin.os.tag == .windows or builtin.os.tag == .wasi)
                    .default_dir
                else
                    .fromMode(0o700),
            ) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => if (next_end == path.len) return err,
            };
        }
        end = next_end + 1;
    }
}

fn getEnvVarOwned(gpa: Allocator, name: []const u8) ?[]u8 {
    if (builtin.os.tag == .wasi) return null;
    if (builtin.os.tag == .windows) {
        var map = std.process.Environ.createMap(.{ .block = .global }, gpa) catch return null;
        defer map.deinit();
        if (map.get(name)) |value| return gpa.dupe(u8, value) catch null;
        return null;
    }
    var i: usize = 0;
    while (std.c.environ[i]) |entry| : (i += 1) {
        const item = std.mem.span(entry);
        if (item.len > name.len and item[name.len] == '=' and std.mem.eql(u8, item[0..name.len], name)) {
            return gpa.dupe(u8, item[name.len + 1 ..]) catch null;
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const FakeStore = struct {
    var entries: std.StringHashMapUnmanaged([]const u8) = .empty;
    var backing_gpa: Allocator = undefined;

    fn reset(gpa: Allocator) void {
        var it = entries.iterator();
        while (it.next()) |e| {
            gpa.free(e.key_ptr.*);
            gpa.free(e.value_ptr.*);
        }
        entries.deinit(gpa);
        entries = .empty;
        backing_gpa = gpa;
    }

    fn makeKey(gpa: Allocator, service: []const u8, account: []const u8) ![]u8 {
        return std.fmt.allocPrint(gpa, "{s}\x00{s}", .{ service, account });
    }

    fn get(gpa: Allocator, service: []const u8, account: []const u8) SecretError![]u8 {
        const key = makeKey(gpa, service, account) catch return error.OutOfMemory;
        defer gpa.free(key);
        const val = entries.get(key) orelse return error.EntryNotFound;
        return decodeKeyringSecret(gpa, val) catch return error.OutOfMemory;
    }

    fn set(gpa: Allocator, service: []const u8, account: []const u8, value: []const u8) SecretError!void {
        _ = gpa;
        const key = makeKey(backing_gpa, service, account) catch return error.OutOfMemory;
        if (entries.fetchRemove(key)) |old| {
            backing_gpa.free(old.key);
            backing_gpa.free(old.value);
        }
        const dup_val = backing_gpa.dupe(u8, value) catch {
            backing_gpa.free(key);
            return error.OutOfMemory;
        };
        entries.put(backing_gpa, key, dup_val) catch {
            backing_gpa.free(key);
            backing_gpa.free(dup_val);
            return error.OutOfMemory;
        };
    }

    const store: SecretStore = .{
        .get = get,
        .set = set,
    };
};

test "decodeKeyringSecret handles go-keyring-base64, go-keyring-encoded, and raw tokens" {
    const gpa = std.testing.allocator;

    const encoded_b64 = try encodeDarwinKeyringSecret(gpa, "gho_testToken123");
    defer gpa.free(encoded_b64);
    try std.testing.expectEqualStrings("go-keyring-base64:Z2hvX3Rlc3RUb2tlbjEyMw==", encoded_b64);

    const decoded_b64 = try decodeKeyringSecret(gpa, "go-keyring-base64:Z2hvX3Rlc3RUb2tlbjEyMw==\n");
    defer gpa.free(decoded_b64);
    try std.testing.expectEqualStrings("gho_testToken123", decoded_b64);

    const decoded_hex = try decodeKeyringSecret(gpa, "go-keyring-encoded:67686f5f686578\n");
    defer gpa.free(decoded_hex);
    try std.testing.expectEqualStrings("gho_hex", decoded_hex);

    const decoded_raw = try decodeKeyringSecret(gpa, "  gho_plainToken  \n");
    defer gpa.free(decoded_raw);
    try std.testing.expectEqualStrings("gho_plainToken", decoded_raw);
}

test "parseHostsYaml and formatHostsYaml round-trip multi-user and plaintext configs" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const mac_yaml =
        \\github.com:
        \\    git_protocol: https
        \\    users:
        \\        alice:
        \\        bob:
        \\        carol:
        \\    user: alice
        \\
    ;
    const hosts = try parseHostsYaml(a, mac_yaml);
    try std.testing.expectEqual(@as(usize, 1), hosts.items.len);
    const h = hosts.items[0];
    try std.testing.expectEqualStrings("github.com", h.hostname);
    try std.testing.expectEqualStrings("https", h.git_protocol.?);
    try std.testing.expectEqualStrings("alice", h.active_user.?);
    try std.testing.expectEqual(@as(usize, 3), h.users.items.len);
    try std.testing.expectEqualStrings("alice", h.users.items[0].username);
    try std.testing.expectEqualStrings("bob", h.users.items[1].username);
    try std.testing.expectEqualStrings("carol", h.users.items[2].username);

    const rendered_keyring = try formatHostsYaml(a, hosts.items, .keyring);
    try std.testing.expectEqualStrings(mac_yaml, rendered_keyring);
}

test "runExport writes plaintext hosts.yml with 0600 permissions from keyring" {
    const gpa = std.testing.allocator;
    FakeStore.reset(gpa);
    defer FakeStore.reset(gpa);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = Io.Threaded.global_single_threaded.io();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const root = root_buf[0..root_len];

    const config_dir = try std.fs.path.join(gpa, &.{ root, "gh-config" });
    defer gpa.free(config_dir);
    const export_dir = try std.fs.path.join(gpa, &.{ root, "gh-export" });
    defer gpa.free(export_dir);

    const initial_hosts =
        \\github.com:
        \\    git_protocol: https
        \\    users:
        \\        alice:
        \\        bob:
        \\    user: alice
        \\
    ;
    try writePrivateFile(config_dir, hosts_filename, initial_hosts);

    try FakeStore.set(gpa, "gh:github.com", "alice", "go-keyring-base64:Z2hvX2FsaWNlX3Rva2Vu");
    try FakeStore.set(gpa, "gh:github.com", "bob", "gho_bob_token");

    secret_store_override = FakeStore.store;
    defer secret_store_override = null;
    gh_config_dir_override = config_dir;
    defer gh_config_dir_override = null;

    var stdout = Io.Writer.Allocating.init(gpa);
    defer stdout.deinit();
    var stderr = Io.Writer.Allocating.init(gpa);
    defer stderr.deinit();

    const code = try runExport(gpa, export_dir, &stdout.writer, &stderr.writer);
    try std.testing.expectEqual(@as(u8, 0), code);
    try std.testing.expectEqualStrings("", stderr.written());
    try std.testing.expect(std.mem.indexOf(u8, stdout.written(), "alice (active)") != null);
    // Never print the raw token in stdout.
    try std.testing.expect(std.mem.indexOf(u8, stdout.written(), "gho_alice_token") == null);

    const exported_path = try std.fs.path.join(gpa, &.{ export_dir, hosts_filename });
    defer gpa.free(exported_path);
    const exported_yaml = readFileIfExists(gpa, exported_path).?;
    defer gpa.free(exported_yaml);

    const expected_exported =
        \\github.com:
        \\    git_protocol: https
        \\    users:
        \\        alice:
        \\            oauth_token: gho_alice_token
        \\        bob:
        \\            oauth_token: gho_bob_token
        \\    user: alice
        \\    oauth_token: gho_alice_token
        \\
    ;
    try std.testing.expectEqualStrings(expected_exported, exported_yaml);

    if (builtin.os.tag != .windows and builtin.os.tag != .wasi) {
        var f = try Io.Dir.cwd().openFile(io, exported_path, .{});
        defer f.close(io);
        const stat = try f.stat(io);
        try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o777);
    }
}

test "runImport stores tokens in keyring, updates active slot, and preserves other local users" {
    const gpa = std.testing.allocator;
    FakeStore.reset(gpa);
    defer FakeStore.reset(gpa);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = Io.Threaded.global_single_threaded.io();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const root = root_buf[0..root_len];

    const config_dir = try std.fs.path.join(gpa, &.{ root, "gh-config" });
    defer gpa.free(config_dir);
    const import_dir = try std.fs.path.join(gpa, &.{ root, "from-remote" });
    defer gpa.free(import_dir);

    // Local config has 3 users; we import a fresh token for alice from a remote machine.
    const existing_local_hosts =
        \\github.com:
        \\    git_protocol: https
        \\    users:
        \\        alice:
        \\        bob:
        \\        carol:
        \\    user: alice
        \\
    ;
    try writePrivateFile(config_dir, hosts_filename, existing_local_hosts);

    const remote_hosts =
        \\github.com:
        \\    users:
        \\        alice:
        \\            oauth_token: gho_freshFromRemote
        \\    git_protocol: https
        \\    user: alice
        \\    oauth_token: gho_freshFromRemote
        \\
    ;
    try writePrivateFile(import_dir, hosts_filename, remote_hosts);

    secret_store_override = FakeStore.store;
    defer secret_store_override = null;
    gh_config_dir_override = config_dir;
    defer gh_config_dir_override = null;

    var empty_stdin = Io.Reader.fixed("");
    var stdout = Io.Writer.Allocating.init(gpa);
    defer stdout.deinit();
    var stderr = Io.Writer.Allocating.init(gpa);
    defer stderr.deinit();

    const code = try runImport(gpa, import_dir, &empty_stdin, &stdout.writer, &stderr.writer);
    try std.testing.expectEqual(@as(u8, 0), code);
    try std.testing.expectEqualStrings("", stderr.written());

    // Both per-user and active-user ("") keyring slots must hold the new token.
    const user_tok = try FakeStore.get(gpa, "gh:github.com", "alice");
    defer gpa.free(user_tok);
    try std.testing.expectEqualStrings("gho_freshFromRemote", user_tok);

    const active_tok = try FakeStore.get(gpa, "gh:github.com", "");
    defer gpa.free(active_tok);
    try std.testing.expectEqualStrings("gho_freshFromRemote", active_tok);

    // Local hosts.yml must preserve bob and carol and strip oauth_token.
    const local_hosts_path = try std.fs.path.join(gpa, &.{ config_dir, hosts_filename });
    defer gpa.free(local_hosts_path);
    const updated_yaml = readFileIfExists(gpa, local_hosts_path).?;
    defer gpa.free(updated_yaml);
    try std.testing.expectEqualStrings(existing_local_hosts, updated_yaml);
}

test "buildSecurityAddCommand escapes single quotes safely" {
    const gpa = std.testing.allocator;
    const cmd = try buildSecurityAddCommand(gpa, "gh:github.com", "al'ice", "go-keyring-base64:abc=");
    defer gpa.free(cmd);
    try std.testing.expectEqualStrings(
        "add-generic-password -U -s 'gh:github.com' -a 'al'\\''ice' -w 'go-keyring-base64:abc='\n",
        cmd,
    );
}
