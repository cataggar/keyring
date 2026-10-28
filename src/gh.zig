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
const ado = @import("ado.zig");
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
    delete: *const fn (gpa: Allocator, service: []const u8, account: []const u8) SecretError!void,
};

const live_secret_store: SecretStore = .{
    .get = liveSecretGet,
    .set = liveSecretSet,
    .delete = liveSecretDelete,
};

/// Test-only overrides so unit tests never touch the real user config or OS keyring.
var secret_store_override: ?SecretStore = null;
var gh_config_dir_override: ?[]const u8 = null;

pub fn setTestOverrides(store: ?SecretStore, config_dir: ?[]const u8) void {
    secret_store_override = store;
    gh_config_dir_override = config_dir;
}

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
                if (std.mem.eql(u8, kv.key, "oauth_token") and !isEmptyYamlValue(kv.value)) {
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
        // Call `/usr/bin/security` first: `zalando/go-keyring` (used by `gh`) and
        // `liveSecretSet` both create `gh:<host>` items via `/usr/bin/security`, so
        // `/usr/bin/security` owns the Keychain item ACL. Calling `SecItemCopyMatching`
        // directly from the `keyring` binary first triggers a blocking macOS GUI
        // Keychain prompt on items owned by `/usr/bin/security`.
        if (macosSecurityGet(gpa, service, account)) |raw| {
            defer gpa.free(raw);
            return decodeKeyringSecret(gpa, raw) catch return error.OutOfMemory;
        } else |sec_err| switch (sec_err) {
            error.EntryNotFound => return error.EntryNotFound,
            error.OutOfMemory => return error.OutOfMemory,
            error.NoStorageAccess, error.StorageFailure, error.Locked => {
                if (keychain.get(gpa, service, account)) |raw| {
                    defer gpa.free(raw);
                    return decodeKeyringSecret(gpa, raw) catch return error.OutOfMemory;
                } else |err| return switch (err) {
                    error.EntryNotFound => error.EntryNotFound,
                    error.OutOfMemory => error.OutOfMemory,
                    error.NoStorageAccess => error.NoStorageAccess,
                    error.StorageFailure => error.StorageFailure,
                };
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

fn liveSecretDelete(gpa: Allocator, service: []const u8, account: []const u8) SecretError!void {
    if (builtin.os.tag == .macos) {
        if (macosSecurityDelete(gpa, service, account)) return;
        return keychain.delete(service, account) catch |err| switch (err) {
            error.EntryNotFound => error.EntryNotFound,
            error.OutOfMemory => error.OutOfMemory,
            else => error.StorageFailure,
        };
    }

    if (builtin.os.tag == .windows) {
        const target = std.fmt.allocPrint(gpa, "{s}:{s}", .{ service, account }) catch
            return error.OutOfMemory;
        defer gpa.free(target);
        return wincred.delete(gpa, target) catch |err| switch (err) {
            error.EntryNotFound => error.EntryNotFound,
            error.OutOfMemory => error.OutOfMemory,
            else => error.StorageFailure,
        };
    }

    return keyring_zig.deleteAlloc(gpa, service, account) catch |err| switch (err) {
        error.EntryNotFound => error.EntryNotFound,
        error.Locked => error.Locked,
        error.OutOfMemory => error.OutOfMemory,
        else => error.NoStorageAccess,
    };
}

fn macosSecurityDelete(gpa: Allocator, service: []const u8, account: []const u8) bool {
    var threaded = Io.Threaded.init(gpa, .{ .environ = ado.currentProcessEnviron() });
    defer threaded.deinit();
    const io = threaded.io();

    const argv = [_][]const u8{
        "/usr/bin/security",
        "delete-generic-password",
        "-s",
        service,
        "-a",
        account,
    };
    const result = std.process.run(gpa, io, .{
        .argv = &argv,
        .stdout_limit = .limited(16 * 1024),
        .stderr_limit = .limited(16 * 1024),
    }) catch return false;
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn macosSecurityGet(gpa: Allocator, service: []const u8, account: []const u8) SecretError![]u8 {
    var threaded = Io.Threaded.init(gpa, .{ .environ = ado.currentProcessEnviron() });
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
    var threaded = Io.Threaded.init(gpa, .{ .environ = ado.currentProcessEnviron() });
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
    _ = try Io.Dir.cwd().createDirPathStatus(io, dir_path, dirPermissions());

    var dir = try Io.Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);

    const file = try dir.createFile(io, filename, .{
        .truncate = true,
        .permissions = filePermissions(),
    });
    defer file.close(io);

    if (builtin.os.tag != .windows and builtin.os.tag != .wasi) {
        file.setPermissions(io, filePermissions()) catch {};
    }

    try file.writeStreamingAll(io, data);
}

fn dirPermissions() Io.File.Permissions {
    return if (builtin.os.tag == .windows or builtin.os.tag == .wasi) .default_dir else .fromMode(0o700);
}

fn filePermissions() Io.File.Permissions {
    return if (builtin.os.tag == .windows or builtin.os.tag == .wasi) .default_file else .fromMode(0o600);
}

fn getEnvVarOwned(gpa: Allocator, name: []const u8) ?[]u8 {
    if (env_override_fn) |override_fn| {
        if (override_fn(name)) |val| return gpa.dupe(u8, val) catch null;
        return null;
    }
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
// GitHub host classification, endpoints, Git credential lookup & OAuth login
// ---------------------------------------------------------------------------

pub const default_oauth_client_id = "178c6fc778ccc68e1d6a";
pub const default_oauth_client_secret = "34ddeff2b558a23d38fba8a6de74f086ede1cc0b";
pub const gcm_oauth_client_id = "0120e057bd645470c1ed";
pub const gcm_oauth_client_secret = "18867509d956965542b521a529a79bb883344c90";
pub const default_oauth_scopes = "repo read:org gist workflow";
pub const token_username = "x-access-token";

pub const HostClass = enum {
    dotcom,
    /// GitHub Enterprise Cloud with data residency (`<tenant>.ghe.com`).
    tenancy,
    /// On-premises GitHub Enterprise Server (`<host>`).
    enterprise,
};

pub const Endpoints = struct {
    canonical_host: []u8,
    host_class: HostClass,
    oauth_base_url: []u8,
    api_base_url: []u8,
    callback_path: []const u8,
    callback_host: []const u8,

    pub fn deinit(self: *const Endpoints, gpa: Allocator) void {
        gpa.free(self.canonical_host);
        gpa.free(self.oauth_base_url);
        gpa.free(self.api_base_url);
    }
};

pub const LoginMode = enum {
    auto,
    web,
    device,
};

pub const LoginOptions = struct {
    hostname: []const u8 = "github.com",
    scopes: []const u8 = default_oauth_scopes,
    mode: LoginMode = .auto,
};

pub const GitCredential = struct {
    username: []u8,
    token: []u8,
    from_env: bool = false,
    stored_in_keyring: bool = true,

    pub fn deinit(self: *const GitCredential, gpa: Allocator) void {
        gpa.free(self.username);
        gpa.free(self.token);
    }
};

pub const AuthError = error{
    InvalidHostname,
    AuthenticationFailed,
    NetworkFailure,
    NoStorageAccess,
    Locked,
    StorageFailure,
    OutOfMemory,
};

pub const HttpTransport = struct {
    postFormJson: *const fn (gpa: Allocator, url: []const u8, form_body: []const u8) AuthError![]u8,
    getJsonWithToken: *const fn (gpa: Allocator, url: []const u8, token: []const u8) AuthError![]u8,
};

const live_http_transport: HttpTransport = .{
    .postFormJson = livePostFormJson,
    .getJsonWithToken = liveGetJsonWithToken,
};

var http_transport_override: ?HttpTransport = null;
var browser_open_override: ?*const fn (gpa: Allocator, stderr: *Io.Writer, url: []const u8) AuthError!void = null;
var env_override_fn: ?*const fn (name: []const u8) ?[]const u8 = null;
var poll_sleep_override: ?*const fn (seconds: u32) void = null;

fn activeHttpTransport() HttpTransport {
    return http_transport_override orelse live_http_transport;
}

/// Normalize a GitHub hostname (`github.com`, `gist.github.com`, `example.ghe.com`,
/// `gist.example.ghe.com`, `api.example.ghe.com`, or a URL/authority) to its
/// canonical lowercase hostname used as the key in `hosts.yml` and `gh:<host>`.
pub fn normalizeHostnameAlloc(gpa: Allocator, raw_input: []const u8) AuthError![]u8 {
    var s = std.mem.trim(u8, raw_input, " \t\r\n/");
    if (std.mem.indexOf(u8, s, "://")) |scheme_idx| {
        s = s[scheme_idx + 3 ..];
    }
    if (std.mem.indexOfAny(u8, s, "/?#")) |path_idx| {
        s = s[0..path_idx];
    }
    if (std.mem.lastIndexOfScalar(u8, s, '@')) |at_idx| {
        s = s[at_idx + 1 ..];
    }
    if (std.mem.indexOfScalar(u8, s, ':')) |colon_idx| {
        s = s[0..colon_idx];
    }
    s = std.mem.trim(u8, s, " \t.");
    if (s.len == 0 or std.mem.indexOfAny(u8, s, " \t\r\n/\\") != null) {
        return error.InvalidHostname;
    }

    const lowered = try gpa.dupe(u8, s);
    errdefer gpa.free(lowered);
    _ = std.ascii.lowerString(lowered, lowered);

    var stripped: []const u8 = lowered;
    if (std.mem.startsWith(u8, stripped, "gist.") and
        std.mem.indexOfScalar(u8, stripped["gist.".len..], '.') != null)
    {
        stripped = stripped["gist.".len..];
    } else if (std.mem.startsWith(u8, stripped, "api.")) {
        const after_api = stripped["api.".len..];
        if (std.mem.eql(u8, after_api, "github.com") or
            (after_api.len > ".ghe.com".len and std.mem.endsWith(u8, after_api, ".ghe.com")))
        {
            stripped = after_api;
        }
    }

    if (stripped.ptr == lowered.ptr and stripped.len == lowered.len) {
        return lowered;
    }
    const result = try gpa.dupe(u8, stripped);
    gpa.free(lowered);
    return result;
}

pub fn classifyHost(canonical_host: []const u8) HostClass {
    if (std.ascii.eqlIgnoreCase(canonical_host, "github.com")) return .dotcom;
    if (canonical_host.len > ".ghe.com".len and std.ascii.endsWithIgnoreCase(canonical_host, ".ghe.com")) {
        return .tenancy;
    }
    return .enterprise;
}

/// Resolve the canonical host, OAuth base URL, and REST API base URL for a
/// GitHub host (`github.com`, `<tenant>.ghe.com`, or GitHub Enterprise Server).
pub fn resolveEndpoints(gpa: Allocator, raw_host: []const u8) AuthError!Endpoints {
    const canonical = try normalizeHostnameAlloc(gpa, raw_host);
    errdefer gpa.free(canonical);

    const class = classifyHost(canonical);
    const oauth_base = try std.fmt.allocPrint(gpa, "https://{s}", .{canonical});
    errdefer gpa.free(oauth_base);

    const api_base = switch (class) {
        .dotcom => try gpa.dupe(u8, "https://api.github.com"),
        .tenancy => try std.fmt.allocPrint(gpa, "https://api.{s}", .{canonical}),
        .enterprise => try std.fmt.allocPrint(gpa, "https://{s}/api/v3", .{canonical}),
    };

    return .{
        .canonical_host = canonical,
        .host_class = class,
        .oauth_base_url = oauth_base,
        .api_base_url = api_base,
        .callback_path = if (class == .enterprise) "/" else "/callback",
        .callback_host = if (class == .enterprise) "localhost" else "127.0.0.1",
    };
}

/// Return true if `raw_host` is a known GitHub host (`github.com`, `gist.github.com`,
/// `*.ghe.com`, `gist.*.ghe.com`, `github.<domain>`, or a host configured in
/// `<gh_config_dir>/hosts.yml`).
pub fn isGitHubHost(gpa: Allocator, raw_host: []const u8) bool {
    const canonical = normalizeHostnameAlloc(gpa, raw_host) catch return false;
    defer gpa.free(canonical);

    const class = classifyHost(canonical);
    if (class == .dotcom or class == .tenancy) return true;
    if (std.mem.startsWith(u8, canonical, "github.") and
        std.mem.indexOfScalar(u8, canonical["github.".len..], '.') != null)
    {
        return true;
    }

    const config_dir = resolveGhConfigDir(gpa) orelse return false;
    defer gpa.free(config_dir);
    const hosts_path = std.fs.path.join(gpa, &.{ config_dir, hosts_filename }) catch return false;
    defer gpa.free(hosts_path);
    const yaml = readFileIfExists(gpa, hosts_path) orelse return false;
    defer gpa.free(yaml);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const hosts = parseHostsYaml(arena_state.allocator(), yaml) catch return false;
    for (hosts.items) |h| {
        if (std.ascii.eqlIgnoreCase(h.hostname, canonical)) return true;
    }
    return false;
}

/// Look up an existing credential for `raw_host` from environment variables,
/// OS keyring (`gh:<canonical_host>`), or `<gh_config_dir>/hosts.yml`.
///
/// When `requested_username` is provided (and is not `"x-access-token"`), only
/// a credential matching that username is returned; unrelated accounts on the
/// same host are never substituted.
pub fn lookupStoredCredential(
    gpa: Allocator,
    raw_host: []const u8,
    requested_username: ?[]const u8,
) AuthError!?GitCredential {
    const canonical = try normalizeHostnameAlloc(gpa, raw_host);
    defer gpa.free(canonical);

    const class = classifyHost(canonical);
    const specific_user = if (requested_username) |u| blk: {
        const trimmed = std.mem.trim(u8, u, " \t\r\n");
        if (trimmed.len == 0 or std.ascii.eqlIgnoreCase(trimmed, token_username)) break :blk null;
        break :blk trimmed;
    } else null;

    // 1. Environment variable overrides (`GH_TOKEN` / `GITHUB_TOKEN` on dotcom,
    //    `GH_ENTERPRISE_TOKEN` / `GH_TOKEN` on `*.ghe.com` and GHES) when no
    //    specific username was requested.
    if (specific_user == null) {
        const env_names: []const []const u8 = switch (class) {
            .dotcom => &.{ "GH_TOKEN", "GITHUB_TOKEN" },
            .tenancy, .enterprise => &.{ "GH_ENTERPRISE_TOKEN", "GH_TOKEN" },
        };
        for (env_names) |env_name| {
            if (getEnvVarOwned(gpa, env_name)) |tok| {
                const trimmed = std.mem.trim(u8, tok, " \t\r\n");
                if (trimmed.len > 0) {
                    const owned_tok = try gpa.dupe(u8, trimmed);
                    gpa.free(tok);
                    errdefer gpa.free(owned_tok);
                    return .{
                        .username = try gpa.dupe(u8, token_username),
                        .token = owned_tok,
                        .from_env = true,
                    };
                }
                gpa.free(tok);
            }
        }
    }

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const service = try keyringServiceName(a, canonical);
    const store = activeSecretStore();

    var maybe_host_cfg: ?HostConfig = null;
    if (resolveGhConfigDir(a)) |config_dir| {
        const hosts_path = try std.fs.path.join(a, &.{ config_dir, hosts_filename });
        if (readFileIfExists(a, hosts_path)) |yaml| {
            const hosts = try parseHostsYaml(a, yaml);
            for (hosts.items) |h| {
                if (std.ascii.eqlIgnoreCase(h.hostname, canonical)) {
                    maybe_host_cfg = h;
                    break;
                }
            }
        }
    }

    if (specific_user) |wanted_user| {
        var canonical_user: []const u8 = wanted_user;
        var user_yaml_tok: ?[]const u8 = null;
        var host_yaml_tok: ?[]const u8 = null;
        var is_active = false;

        if (maybe_host_cfg) |h| {
            for (h.users.items) |u| {
                if (std.ascii.eqlIgnoreCase(u.username, wanted_user)) {
                    canonical_user = u.username;
                    user_yaml_tok = u.oauth_token;
                    break;
                }
            }
            if (h.active_user) |active| {
                if (std.ascii.eqlIgnoreCase(active, canonical_user)) {
                    is_active = true;
                    host_yaml_tok = h.oauth_token;
                }
            }
        }

        if (resolveUserToken(gpa, store, service, canonical_user, is_active, user_yaml_tok, host_yaml_tok)) |tok| {
            errdefer gpa.free(tok);
            return .{
                .username = try gpa.dupe(u8, canonical_user),
                .token = tok,
            };
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        }
    }

    if (maybe_host_cfg) |h| {
        if (h.active_user) |active| {
            var user_yaml_tok: ?[]const u8 = null;
            if (h.findUserIndex(active)) |idx| {
                user_yaml_tok = h.users.items[idx].oauth_token;
            }
            if (resolveUserToken(gpa, store, service, active, true, user_yaml_tok, h.oauth_token)) |tok| {
                errdefer gpa.free(tok);
                return .{
                    .username = try gpa.dupe(u8, active),
                    .token = tok,
                };
            } else |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {},
            }
        }
    }

    // Fallback: check the active-user mirror slot `gh:<canonical>` / `""`.
    if (store.get(gpa, service, "")) |tok| {
        if (tok.len > 0) {
            errdefer gpa.free(tok);
            const fallback_user = if (maybe_host_cfg) |h| (h.active_user orelse token_username) else token_username;
            return .{
                .username = try gpa.dupe(u8, fallback_user),
                .token = tok,
            };
        }
        gpa.free(tok);
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {},
    }

    return null;
}

/// Store a GitHub token for `(raw_host, username)` into the OS keyring (`gh:<host>`)
/// and update `<gh_config_dir>/hosts.yml` so both `git` and `gh` share the login.
///
/// When the OS keyring is unavailable (for example on a headless Linux machine
/// with no Secret Service daemon), falls back to storing `oauth_token` in
/// `<gh_config_dir>/hosts.yml` (mode `0600`), matching `gh auth login`.
/// Returns true when stored in both the OS keyring and `hosts.yml`, or false
/// when persisted in `hosts.yml` only.
pub fn saveUserCredential(
    gpa: Allocator,
    raw_host: []const u8,
    username: []const u8,
    token: []const u8,
) AuthError!bool {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const canonical = try normalizeHostnameAlloc(a, raw_host);
    const service = try keyringServiceName(a, canonical);
    const store = activeSecretStore();

    const stored_in_keyring: bool = blk: {
        store.set(a, service, username, token) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Locked => return error.Locked,
            error.NoStorageAccess, error.StorageFailure, error.EntryNotFound => break :blk false,
        };
        store.set(a, service, "", token) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Locked => return error.Locked,
            error.NoStorageAccess, error.StorageFailure, error.EntryNotFound => break :blk false,
        };
        break :blk true;
    };

    const config_dir = resolveGhConfigDir(a) orelse return error.NoStorageAccess;
    const local_hosts_path = try std.fs.path.join(a, &.{ config_dir, hosts_filename });

    var merged_hosts = if (readFileIfExists(a, local_hosts_path)) |existing_yaml|
        try parseHostsYaml(a, existing_yaml)
    else
        std.ArrayListUnmanaged(HostConfig).empty;

    const yaml_token: ?[]const u8 = if (stored_in_keyring) null else token;
    var incoming_host = HostConfig{
        .hostname = canonical,
        .git_protocol = "https",
        .active_user = username,
        .oauth_token = yaml_token,
    };
    try incoming_host.users.append(a, .{
        .username = username,
        .oauth_token = yaml_token,
    });
    const incoming_slice = [_]HostConfig{incoming_host};
    try mergeHosts(a, &merged_hosts, &incoming_slice);

    for (merged_hosts.items) |*h| {
        if (!std.ascii.eqlIgnoreCase(h.hostname, canonical)) continue;
        h.oauth_token = if (yaml_token) |tok| try a.dupe(u8, tok) else null;
        if (h.findUserIndex(username)) |u_idx| {
            h.users.items[u_idx].oauth_token = if (yaml_token) |tok| try a.dupe(u8, tok) else null;
        }
    }

    const rendered = formatHostsYaml(a, merged_hosts.items, .plaintext) catch return error.OutOfMemory;
    writePrivateFile(config_dir, hosts_filename, rendered) catch return error.StorageFailure;
    return stored_in_keyring;
}

/// Persist a Git credential supplied via `git credential approve` (`keyring git credential store`)
/// into the OS keyring (`gh:<host>`) and `<gh_config_dir>/hosts.yml`.
///
/// Ignores empty credentials and synthetic `"x-access-token"` usernames (such as
/// credentials originating from `GH_TOKEN` / `GITHUB_TOKEN` environment variables).
/// Skips redundant keyring/file writes when the exact token is already stored for
/// `(raw_host, username)`.
pub fn storeGitCredential(
    gpa: Allocator,
    raw_host: []const u8,
    raw_username: ?[]const u8,
    raw_password: ?[]const u8,
) AuthError!void {
    const user_in = raw_username orelse return;
    const pass_in = raw_password orelse return;
    const username = std.mem.trim(u8, user_in, " \t\r\n");
    const token = std.mem.trim(u8, pass_in, " \t\r\n");
    if (username.len == 0 or token.len == 0) return;
    if (std.ascii.eqlIgnoreCase(username, token_username)) return;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const canonical = try normalizeHostnameAlloc(a, raw_host);
    const service = try keyringServiceName(a, canonical);
    const store = activeSecretStore();

    if (isCredentialAlreadyStored(a, store, canonical, service, username, token)) {
        return;
    }

    _ = try saveUserCredential(gpa, canonical, username, token);
}

fn isCredentialAlreadyStored(
    a: Allocator,
    store: SecretStore,
    canonical_host: []const u8,
    service: []const u8,
    username: []const u8,
    token: []const u8,
) bool {
    const config_dir = resolveGhConfigDir(a) orelse return false;
    const local_hosts_path = std.fs.path.join(a, &.{ config_dir, hosts_filename }) catch return false;
    const existing_yaml = readFileIfExists(a, local_hosts_path) orelse return false;
    const hosts = parseHostsYaml(a, existing_yaml) catch return false;

    for (hosts.items) |h| {
        if (!std.ascii.eqlIgnoreCase(h.hostname, canonical_host)) continue;
        const user_idx = h.findUserIndex(username) orelse return false;
        const active = h.active_user orelse return false;
        const is_active = std.mem.eql(u8, active, username);

        if (store.get(a, service, username)) |stored_user_tok| {
            if (!std.mem.eql(u8, stored_user_tok, token)) return false;
            if (is_active) {
                const mirror_tok = store.get(a, service, "") catch return false;
                if (!std.mem.eql(u8, mirror_tok, token)) return false;
            }
            return true;
        } else |err| switch (err) {
            error.NoStorageAccess, error.StorageFailure, error.EntryNotFound => {
                const yaml_user_tok = h.users.items[user_idx].oauth_token orelse return false;
                if (!std.mem.eql(u8, yaml_user_tok, token)) return false;
                if (is_active) {
                    const yaml_host_tok = h.oauth_token orelse yaml_user_tok;
                    if (!std.mem.eql(u8, yaml_host_tok, token)) return false;
                }
                return true;
            },
            else => return false,
        }
    }
    return false;
}

/// Remove a stored GitHub token for `raw_host` (called on `git credential erase`).
/// When `requested_username` is provided, only that user's token is erased;
/// otherwise the active user's token on `raw_host` is erased.
pub fn eraseStoredCredential(
    gpa: Allocator,
    raw_host: []const u8,
    requested_username: ?[]const u8,
) AuthError!bool {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const canonical = try normalizeHostnameAlloc(a, raw_host);
    const service = try keyringServiceName(a, canonical);
    const store = activeSecretStore();

    const specific_user = if (requested_username) |u| blk: {
        const trimmed = std.mem.trim(u8, u, " \t\r\n");
        if (trimmed.len == 0 or std.ascii.eqlIgnoreCase(trimmed, token_username)) break :blk null;
        break :blk trimmed;
    } else null;

    var removed = false;
    var active_user_for_host: ?[]const u8 = null;

    if (resolveGhConfigDir(a)) |config_dir| {
        const local_hosts_path = try std.fs.path.join(a, &.{ config_dir, hosts_filename });
        if (readFileIfExists(a, local_hosts_path)) |existing_yaml| {
            const hosts = try parseHostsYaml(a, existing_yaml);
            var yaml_dirty = false;
            for (hosts.items) |*h| {
                if (!std.ascii.eqlIgnoreCase(h.hostname, canonical)) continue;
                active_user_for_host = h.active_user;
                const target_u = specific_user orelse h.active_user;
                if (target_u) |tu| {
                    for (h.users.items) |*u| {
                        if (std.ascii.eqlIgnoreCase(u.username, tu) and u.oauth_token != null) {
                            u.oauth_token = null;
                            yaml_dirty = true;
                        }
                    }
                    if (h.active_user != null and std.ascii.eqlIgnoreCase(h.active_user.?, tu) and h.oauth_token != null) {
                        h.oauth_token = null;
                        yaml_dirty = true;
                    }
                }
            }
            if (yaml_dirty) {
                const rendered = formatHostsYaml(a, hosts.items, .plaintext) catch return error.OutOfMemory;
                writePrivateFile(config_dir, hosts_filename, rendered) catch {};
                removed = true;
            }
        }
    }

    if (specific_user) |tu| {
        if (store.delete(a, service, tu)) |_| {
            removed = true;
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {},
        }
        if (active_user_for_host == null or std.ascii.eqlIgnoreCase(active_user_for_host.?, tu)) {
            store.delete(a, service, "") catch {};
        }
    } else {
        if (active_user_for_host) |active| {
            if (store.delete(a, service, active)) |_| {
                removed = true;
            } else |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {},
            }
        }
        if (store.delete(a, service, "")) |_| {
            removed = true;
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {},
        }
    }

    return removed;
}

/// Return a stored Git credential for `raw_host` or, if none is stored and
/// `allow_interactive` is true (and the environment is not non-interactive),
/// run the native GitHub OAuth flow and persist the new token.
pub fn getOrLoginGitCredential(
    gpa: Allocator,
    raw_host: []const u8,
    requested_username: ?[]const u8,
    allow_interactive: bool,
    stderr: *Io.Writer,
) AuthError!?GitCredential {
    if (try lookupStoredCredential(gpa, raw_host, requested_username)) |cred| {
        return cred;
    }
    if (!allow_interactive or ado.isNonInteractive()) {
        return null;
    }
    const cred = try loginOAuth(gpa, .{ .hostname = raw_host }, stderr);
    errdefer cred.deinit(gpa);

    if (requested_username) |wanted| {
        const trimmed = std.mem.trim(u8, wanted, " \t\r\n");
        if (trimmed.len > 0 and
            !std.ascii.eqlIgnoreCase(trimmed, token_username) and
            !std.ascii.eqlIgnoreCase(trimmed, cred.username))
        {
            return error.AuthenticationFailed;
        }
    }
    return cred;
}

/// Parse CLI arguments for `keyring gh login [-h|--hostname <host>] [--scopes <scopes>] [--web|--device]`.
pub fn parseLoginArgs(args: []const []const u8) ?LoginOptions {
    var opts: LoginOptions = .{};
    var saw_web = false;
    var saw_device = false;

    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--hostname") or std.mem.eql(u8, arg, "-h")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return null;
            opts.hostname = args[i + 1];
            i += 2;
        } else if (std.mem.eql(u8, arg, "--scopes") or std.mem.eql(u8, arg, "-s")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return null;
            opts.scopes = args[i + 1];
            i += 2;
        } else if (std.mem.eql(u8, arg, "--web") or std.mem.eql(u8, arg, "-w")) {
            saw_web = true;
            opts.mode = .web;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--device")) {
            saw_device = true;
            opts.mode = .device;
            i += 1;
        } else {
            return null;
        }
    }
    if (saw_web and saw_device) return null;
    return opts;
}

/// Run `keyring gh login`.
pub fn runLogin(
    gpa: Allocator,
    opts: LoginOptions,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    const cred = loginOAuth(gpa, opts, stderr) catch |err| {
        try stderr.print("keyring: gh login: {s}\n", .{@errorName(err)});
        try stderr.flush();
        return switch (err) {
            error.InvalidHostname => 2,
            error.NoStorageAccess, error.Locked => 4,
            else => 1,
        };
    };
    defer cred.deinit(gpa);

    const canonical = normalizeHostnameAlloc(gpa, opts.hostname) catch {
        return 2;
    };
    defer gpa.free(canonical);

    const storage_desc = if (cred.stored_in_keyring) "stored in keyring and hosts.yml" else "stored in hosts.yml";
    try stdout.print("Logged in to {s} as {s} ({s})\n", .{ canonical, cred.username, storage_desc });
    try stdout.flush();
    return 0;
}

/// Authenticate to a GitHub host (`github.com`, `<tenant>.ghe.com`, or GHES)
/// via loopback browser OAuth (or device-code flow), resolve the authenticated
/// user via `<api_base_url>/user`, and persist the token into `gh:<host>` and
/// `<gh_config_dir>/hosts.yml`.
pub fn loginOAuth(
    gpa: Allocator,
    opts: LoginOptions,
    stderr: *Io.Writer,
) AuthError!GitCredential {
    const endpoints = try resolveEndpoints(gpa, opts.hostname);
    defer endpoints.deinit(gpa);

    const client_id = getEnvVarOwned(gpa, "KEYRING_GH_CLIENT_ID") orelse
        try gpa.dupe(u8, default_oauth_client_id);
    defer gpa.free(client_id);

    const client_secret = getEnvVarOwned(gpa, "KEYRING_GH_CLIENT_SECRET") orelse
        try gpa.dupe(u8, default_oauth_client_secret);
    defer gpa.free(client_secret);

    const normalized_scopes = try normalizeScopesAlloc(gpa, opts.scopes);
    defer gpa.free(normalized_scopes);

    const can_open_browser = canOpenBrowserForOAuth(gpa);
    const token = switch (opts.mode) {
        .device => try deviceCodeOAuthFlow(gpa, endpoints, client_id, normalized_scopes, can_open_browser, stderr),
        .web => try webAppOAuthFlow(gpa, endpoints, client_id, client_secret, normalized_scopes, false, stderr),
        .auto => if (can_open_browser)
            try webAppOAuthFlow(gpa, endpoints, client_id, client_secret, normalized_scopes, true, stderr)
        else
            try deviceCodeOAuthFlow(gpa, endpoints, client_id, normalized_scopes, false, stderr),
    };
    errdefer gpa.free(token);

    const username = try fetchAuthenticatedUser(gpa, endpoints.api_base_url, token);
    errdefer gpa.free(username);

    const stored_in_keyring = try saveUserCredential(gpa, endpoints.canonical_host, username, token);

    return .{
        .username = username,
        .token = token,
        .stored_in_keyring = stored_in_keyring,
    };
}

fn normalizeScopesAlloc(gpa: Allocator, raw_scopes: []const u8) AuthError![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);

    var it = std.mem.tokenizeAny(u8, raw_scopes, " ,\t\r\n");
    var first = true;
    while (it.next()) |part| {
        if (!first) try out.append(gpa, ' ');
        first = false;
        try out.appendSlice(gpa, part);
    }
    if (out.items.len == 0) {
        try out.appendSlice(gpa, default_oauth_scopes);
    }
    return out.toOwnedSlice(gpa);
}

const OAuthTokenResponse = struct {
    access_token: ?[]const u8 = null,
    @"error": ?[]const u8 = null,
    error_description: ?[]const u8 = null,
    interval: ?u32 = null,
};

const DeviceCodeResponse = struct {
    device_code: ?[]const u8 = null,
    user_code: ?[]const u8 = null,
    verification_uri: ?[]const u8 = null,
    expires_in: u32 = 900,
    interval: u32 = 5,
};

const ViewerResponse = struct {
    login: ?[]const u8 = null,
};

const oauth_success_html =
    \\<!doctype html><html><head><meta charset="utf-8"><title>keyring - GitHub Authenticated</title></head>
    \\<body style="font-family:system-ui,sans-serif;padding:2rem">
    \\<h2>GitHub authentication complete</h2>
    \\<p>You can close this browser tab and return to your terminal.</p>
    \\</body></html>
;

fn webAppOAuthFlow(
    gpa: Allocator,
    endpoints: Endpoints,
    client_id: []const u8,
    client_secret: []const u8,
    scopes: []const u8,
    fallback_to_device: bool,
    stderr: *Io.Writer,
) AuthError![]u8 {
    const io = Io.Threaded.global_single_threaded.io();
    var address: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
    var server = Io.net.IpAddress.listen(&address, io, .{ .reuse_address = true }) catch {
        if (fallback_to_device) {
            return deviceCodeOAuthFlow(gpa, endpoints, client_id, scopes, true, stderr);
        }
        return error.NoStorageAccess;
    };
    defer server.deinit(io);

    const bound_port = server.socket.address.getPort();
    const redirect_uri = try std.fmt.allocPrint(
        gpa,
        "http://{s}:{d}{s}",
        .{ endpoints.callback_host, bound_port, endpoints.callback_path },
    );
    defer gpa.free(redirect_uri);

    const state = try randomHexToken(gpa, 16);
    defer gpa.free(state);

    const auth_url = try buildGitHubAuthorizeUrl(
        gpa,
        endpoints.oauth_base_url,
        client_id,
        redirect_uri,
        scopes,
        state,
    );
    defer gpa.free(auth_url);

    var sink = Io.Writer.Allocating.init(gpa);
    defer sink.deinit();
    const browser_stderr = if (fallback_to_device) &sink.writer else stderr;

    openBrowserForOAuth(gpa, browser_stderr, auth_url) catch |err| {
        if (fallback_to_device) {
            return deviceCodeOAuthFlow(gpa, endpoints, client_id, scopes, false, stderr);
        }
        return err;
    };

    stderr.print("[keyring gh] Opening browser for {s} authentication...\n", .{endpoints.canonical_host}) catch {};
    stderr.print("[keyring gh] If the browser does not open, visit:\n{s}\n", .{auth_url}) catch {};
    stderr.flush() catch {};

    var stream = server.accept(io) catch return error.AuthenticationFailed;
    defer stream.socket.close(io);

    var read_buffer: [8192]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    const request_line = reader.interface.takeDelimiterExclusive('\n') catch return error.AuthenticationFailed;
    const path = parseHttpGetPath(request_line) orelse return error.AuthenticationFailed;
    const code = try parseGitHubOAuthCallback(gpa, path, state);
    defer gpa.free(code);

    sendOAuthHtml(io, stream, oauth_success_html);

    const token_url = try std.fmt.allocPrint(gpa, "{s}/login/oauth/access_token", .{endpoints.oauth_base_url});
    defer gpa.free(token_url);

    var body = Io.Writer.Allocating.init(gpa);
    defer body.deinit();
    try writeFormField(&body.writer, "client_id", client_id, true);
    try writeFormField(&body.writer, "client_secret", client_secret, false);
    try writeFormField(&body.writer, "code", code, false);
    try writeFormField(&body.writer, "redirect_uri", redirect_uri, false);
    try writeFormField(&body.writer, "state", state, false);

    const raw_json = try activeHttpTransport().postFormJson(gpa, token_url, body.written());
    defer gpa.free(raw_json);

    var parsed = std.json.parseFromSlice(OAuthTokenResponse, gpa, raw_json, .{ .ignore_unknown_fields = true }) catch
        return error.AuthenticationFailed;
    defer parsed.deinit();

    const access_token = parsed.value.access_token orelse return error.AuthenticationFailed;
    if (access_token.len == 0) return error.AuthenticationFailed;
    return gpa.dupe(u8, access_token);
}

fn deviceCodeOAuthFlow(
    gpa: Allocator,
    endpoints: Endpoints,
    client_id: []const u8,
    scopes: []const u8,
    try_open_browser: bool,
    stderr: *Io.Writer,
) AuthError![]u8 {
    const device_url = try std.fmt.allocPrint(gpa, "{s}/login/device/code", .{endpoints.oauth_base_url});
    defer gpa.free(device_url);

    var req_body = Io.Writer.Allocating.init(gpa);
    defer req_body.deinit();
    try writeFormField(&req_body.writer, "client_id", client_id, true);
    try writeFormField(&req_body.writer, "scope", scopes, false);

    const device_json = try activeHttpTransport().postFormJson(gpa, device_url, req_body.written());
    defer gpa.free(device_json);

    var device_parsed = std.json.parseFromSlice(DeviceCodeResponse, gpa, device_json, .{ .ignore_unknown_fields = true }) catch
        return error.AuthenticationFailed;
    defer device_parsed.deinit();

    const device_code = device_parsed.value.device_code orelse return error.AuthenticationFailed;
    const user_code = device_parsed.value.user_code orelse return error.AuthenticationFailed;
    const verification_uri = device_parsed.value.verification_uri orelse return error.AuthenticationFailed;
    if (device_code.len == 0 or user_code.len == 0 or verification_uri.len == 0) {
        return error.AuthenticationFailed;
    }

    stderr.print(
        "! First copy your one-time code: {s}\nOpen this URL to continue in your web browser: {s}\n",
        .{ user_code, verification_uri },
    ) catch {};
    stderr.flush() catch {};

    if (try_open_browser) {
        var sink = Io.Writer.Allocating.init(gpa);
        defer sink.deinit();
        _ = openBrowserForOAuth(gpa, &sink.writer, verification_uri) catch {};
    }

    const token_url = try std.fmt.allocPrint(gpa, "{s}/login/oauth/access_token", .{endpoints.oauth_base_url});
    defer gpa.free(token_url);

    var poll_body = Io.Writer.Allocating.init(gpa);
    defer poll_body.deinit();
    try writeFormField(&poll_body.writer, "client_id", client_id, true);
    try writeFormField(&poll_body.writer, "device_code", device_code, false);
    try writeFormField(&poll_body.writer, "grant_type", "urn:ietf:params:oauth:grant-type:device_code", false);

    var interval_sec: u32 = if (device_parsed.value.interval == 0) 5 else device_parsed.value.interval;
    var elapsed_sec: u32 = 0;
    const max_wait_sec: u32 = if (device_parsed.value.expires_in == 0) 900 else device_parsed.value.expires_in;

    while (elapsed_sec < max_wait_sec) {
        sleepSeconds(interval_sec);
        elapsed_sec +|= interval_sec;

        const poll_json = try activeHttpTransport().postFormJson(gpa, token_url, poll_body.written());
        defer gpa.free(poll_json);

        var poll_parsed = std.json.parseFromSlice(OAuthTokenResponse, gpa, poll_json, .{ .ignore_unknown_fields = true }) catch
            return error.AuthenticationFailed;
        defer poll_parsed.deinit();

        if (poll_parsed.value.access_token) |tok| {
            if (tok.len > 0) return gpa.dupe(u8, tok);
        }

        const err_code = poll_parsed.value.@"error" orelse return error.AuthenticationFailed;
        if (std.mem.eql(u8, err_code, "authorization_pending")) {
            continue;
        }
        if (std.mem.eql(u8, err_code, "slow_down")) {
            if (poll_parsed.value.interval) |srv_interval| {
                if (srv_interval > interval_sec) {
                    interval_sec = srv_interval;
                } else {
                    interval_sec += 5;
                }
            } else {
                interval_sec += 5;
            }
            continue;
        }
        return error.AuthenticationFailed;
    }

    return error.AuthenticationFailed;
}

pub fn fetchAuthenticatedUser(gpa: Allocator, api_base_url: []const u8, token: []const u8) AuthError![]u8 {
    const trimmed_base = std.mem.trimEnd(u8, api_base_url, "/");
    const user_url = try std.fmt.allocPrint(gpa, "{s}/user", .{trimmed_base});
    defer gpa.free(user_url);

    const raw_json = try activeHttpTransport().getJsonWithToken(gpa, user_url, token);
    defer gpa.free(raw_json);

    var parsed = std.json.parseFromSlice(ViewerResponse, gpa, raw_json, .{ .ignore_unknown_fields = true }) catch
        return error.AuthenticationFailed;
    defer parsed.deinit();

    const login = parsed.value.login orelse return error.AuthenticationFailed;
    if (login.len == 0) return error.AuthenticationFailed;
    return gpa.dupe(u8, login);
}

pub fn buildGitHubAuthorizeUrl(
    gpa: Allocator,
    oauth_base_url: []const u8,
    client_id: []const u8,
    redirect_uri: []const u8,
    scopes: []const u8,
    state: []const u8,
) AuthError![]u8 {
    var query = Io.Writer.Allocating.init(gpa);
    defer query.deinit();
    try writeFormField(&query.writer, "client_id", client_id, true);
    try writeFormField(&query.writer, "redirect_uri", redirect_uri, false);
    try writeFormField(&query.writer, "scope", scopes, false);
    try writeFormField(&query.writer, "state", state, false);
    const trimmed_base = std.mem.trimEnd(u8, oauth_base_url, "/");
    return std.fmt.allocPrint(gpa, "{s}/login/oauth/authorize?{s}", .{ trimmed_base, query.written() });
}

fn canOpenBrowserForOAuth(gpa: Allocator) bool {
    return ado.canLaunchBrowserWithEnv(
        gpa,
        getEnvVarOwned,
        true,
        builtin.os.tag,
        ado.isWsl(),
    );
}

fn openBrowserForOAuth(gpa: Allocator, stderr: *Io.Writer, url: []const u8) AuthError!void {
    if (browser_open_override) |override_fn| {
        return override_fn(gpa, stderr, url);
    }
    ado.openBrowserWithEnv(gpa, stderr, url, getEnvVarOwned, true) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.NoStorageAccess,
    };
}

fn sleepSeconds(seconds: u32) void {
    if (poll_sleep_override) |override_fn| {
        override_fn(seconds);
        return;
    }
    const io = Io.Threaded.global_single_threaded.io();
    Io.Clock.Duration.sleep(.{ .clock = .awake, .raw = .fromSeconds(@intCast(seconds)) }, io) catch {};
}

fn livePostFormJson(gpa: Allocator, url: []const u8, form_body: []const u8) AuthError![]u8 {
    var response = Io.Writer.Allocating.init(gpa);
    errdefer response.deinit();

    var client: std.http.Client = .{
        .allocator = gpa,
        .io = Io.Threaded.global_single_threaded.io(),
    };
    defer client.deinit();

    const extra_headers = [_]std.http.Header{
        .{ .name = "accept", .value = "application/json" },
        .{ .name = "user-agent", .value = "keyring" },
    };

    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .payload = form_body,
        .headers = .{ .content_type = .{ .override = "application/x-www-form-urlencoded" } },
        .extra_headers = &extra_headers,
        .response_writer = &response.writer,
    }) catch {
        response.deinit();
        return error.NetworkFailure;
    };

    if (result.status.class() != .success) {
        response.deinit();
        return error.AuthenticationFailed;
    }
    return response.toOwnedSlice() catch {
        response.deinit();
        return error.OutOfMemory;
    };
}

fn liveGetJsonWithToken(gpa: Allocator, url: []const u8, token: []const u8) AuthError![]u8 {
    var response = Io.Writer.Allocating.init(gpa);
    errdefer response.deinit();

    var client: std.http.Client = .{
        .allocator = gpa,
        .io = Io.Threaded.global_single_threaded.io(),
    };
    defer client.deinit();

    const auth_header = try std.fmt.allocPrint(gpa, "Bearer {s}", .{token});
    defer gpa.free(auth_header);

    const extra_headers = [_]std.http.Header{
        .{ .name = "authorization", .value = auth_header },
        .{ .name = "accept", .value = "application/vnd.github+json" },
        .{ .name = "user-agent", .value = "keyring" },
    };

    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = .GET,
        .extra_headers = &extra_headers,
        .response_writer = &response.writer,
    }) catch {
        response.deinit();
        return error.NetworkFailure;
    };

    if (result.status.class() != .success) {
        response.deinit();
        return error.AuthenticationFailed;
    }
    return response.toOwnedSlice() catch {
        response.deinit();
        return error.OutOfMemory;
    };
}

fn writeFormField(writer: *Io.Writer, key: []const u8, value: []const u8, first: bool) AuthError!void {
    if (!first) writer.writeByte('&') catch return error.NetworkFailure;
    try writePercentEncodedForm(writer, key);
    writer.writeByte('=') catch return error.NetworkFailure;
    try writePercentEncodedForm(writer, value);
}

fn writePercentEncodedForm(writer: *Io.Writer, value: []const u8) AuthError!void {
    const hex = "0123456789ABCDEF";
    for (value) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            writer.writeByte(c) catch return error.NetworkFailure;
        } else if (c == ' ') {
            writer.writeByte('+') catch return error.NetworkFailure;
        } else {
            writer.writeByte('%') catch return error.NetworkFailure;
            writer.writeByte(hex[c >> 4]) catch return error.NetworkFailure;
            writer.writeByte(hex[c & 0x0f]) catch return error.NetworkFailure;
        }
    }
}

fn parseHttpGetPath(request_line: []const u8) ?[]const u8 {
    const trimmed = std.mem.trimEnd(u8, request_line, "\r");
    if (!std.mem.startsWith(u8, trimmed, "GET ")) return null;
    const rest = trimmed[4..];
    const end = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
    return rest[0..end];
}

pub fn parseGitHubOAuthCallback(gpa: Allocator, path: []const u8, expected_state: []const u8) AuthError![]u8 {
    const query_start = std.mem.indexOfScalar(u8, path, '?') orelse return error.AuthenticationFailed;
    var code: ?[]u8 = null;
    var state_ok = false;

    var it = std.mem.splitScalar(u8, path[query_start + 1 ..], '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const value = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "error")) {
            if (code) |owned| gpa.free(owned);
            return error.AuthenticationFailed;
        }
        if (std.mem.eql(u8, key, "code")) {
            if (code) |owned| gpa.free(owned);
            code = try percentDecodeQuery(gpa, value);
        } else if (std.mem.eql(u8, key, "state")) {
            const decoded = try percentDecodeQuery(gpa, value);
            defer gpa.free(decoded);
            state_ok = std.mem.eql(u8, decoded, expected_state);
        }
    }

    if (!state_ok) {
        if (code) |owned| gpa.free(owned);
        return error.AuthenticationFailed;
    }
    return code orelse error.AuthenticationFailed;
}

fn percentDecodeQuery(gpa: Allocator, value: []const u8) AuthError![]u8 {
    var out = try std.ArrayList(u8).initCapacity(gpa, value.len);
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        if (value[i] == '+') {
            try out.append(gpa, ' ');
        } else if (value[i] == '%' and i + 2 < value.len) {
            const hi = std.fmt.charToDigit(value[i + 1], 16) catch return error.AuthenticationFailed;
            const lo = std.fmt.charToDigit(value[i + 2], 16) catch return error.AuthenticationFailed;
            try out.append(gpa, @intCast((hi << 4) | lo));
            i += 2;
        } else {
            try out.append(gpa, value[i]);
        }
    }
    return out.toOwnedSlice(gpa);
}

fn sendOAuthHtml(io: Io, stream: Io.net.Stream, html: []const u8) void {
    var write_buffer: [1024]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    writer.interface.print(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ html.len, html },
    ) catch return;
    writer.interface.flush() catch {};
}

fn randomHexToken(gpa: Allocator, byte_len: usize) AuthError![]u8 {
    const bytes = try gpa.alloc(u8, byte_len);
    defer gpa.free(bytes);
    Io.Threaded.global_single_threaded.io().random(bytes);
    const out = try gpa.alloc(u8, byte_len * 2);
    const hex_chars = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0x0f];
    }
    return out;
}

/// Print GitHub CLI / `gh:<host>` diagnostics for `keyring diagnose`.
pub fn diagnoseHosts(gpa: Allocator, stdout: *Io.Writer) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const config_dir = resolveGhConfigDir(a) orelse {
        try stdout.writeAll("gh hosts.yml: <unavailable>\n");
        return;
    };
    const hosts_path = try std.fs.path.join(a, &.{ config_dir, hosts_filename });
    const content = readFileIfExists(a, hosts_path) orelse {
        try stdout.print("gh hosts.yml: absent ({s})\n", .{hosts_path});
        return;
    };

    const hosts = parseHostsYaml(a, content) catch {
        try stdout.print("gh hosts.yml: unparseable ({s})\n", .{hosts_path});
        return;
    };
    if (hosts.items.len == 0) {
        try stdout.print("gh hosts.yml: empty ({s})\n", .{hosts_path});
        return;
    }

    try stdout.print("gh hosts.yml: {s} ({d} host(s))\n", .{ hosts_path, hosts.items.len });
    const store = activeSecretStore();
    for (hosts.items) |h| {
        const service = try keyringServiceName(a, h.hostname);
        const active = h.active_user orelse "<none>";
        const has_token = if (h.active_user) |au| blk: {
            var user_tok: ?[]const u8 = null;
            if (h.findUserIndex(au)) |idx| user_tok = h.users.items[idx].oauth_token;
            if (resolveUserToken(a, store, service, au, true, user_tok, h.oauth_token)) |tok| {
                a.free(tok);
                break :blk true;
            } else |_| {
                break :blk false;
            }
        } else false;
        try stdout.print(
            "gh host {s}: active user {s} (token: {s})\n",
            .{ h.hostname, active, if (has_token) "present" else "missing" },
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

pub const FakeStore = struct {
    var entries: std.StringHashMapUnmanaged([]const u8) = .empty;
    var backing_gpa: Allocator = undefined;

    pub fn reset(gpa: Allocator) void {
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

    pub fn get(gpa: Allocator, service: []const u8, account: []const u8) SecretError![]u8 {
        const key = makeKey(gpa, service, account) catch return error.OutOfMemory;
        defer gpa.free(key);
        const val = entries.get(key) orelse return error.EntryNotFound;
        return decodeKeyringSecret(gpa, val) catch return error.OutOfMemory;
    }

    pub fn set(gpa: Allocator, service: []const u8, account: []const u8, value: []const u8) SecretError!void {
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

    pub fn delete(gpa: Allocator, service: []const u8, account: []const u8) SecretError!void {
        const key = makeKey(gpa, service, account) catch return error.OutOfMemory;
        defer gpa.free(key);
        if (entries.fetchRemove(key)) |old| {
            backing_gpa.free(old.key);
            backing_gpa.free(old.value);
            return;
        }
        return error.EntryNotFound;
    }

    pub const store: SecretStore = .{
        .get = get,
        .set = set,
        .delete = delete,
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

test "resolveEndpoints classifies github.com, *.ghe.com data residency, and GHES hosts" {
    const gpa = std.testing.allocator;

    const dotcom = try resolveEndpoints(gpa, "https://gist.GitHub.com/owner/repo");
    defer dotcom.deinit(gpa);
    try std.testing.expectEqualStrings("github.com", dotcom.canonical_host);
    try std.testing.expectEqual(HostClass.dotcom, dotcom.host_class);
    try std.testing.expectEqualStrings("https://github.com", dotcom.oauth_base_url);
    try std.testing.expectEqualStrings("https://api.github.com", dotcom.api_base_url);
    try std.testing.expectEqualStrings("/callback", dotcom.callback_path);
    try std.testing.expectEqualStrings("127.0.0.1", dotcom.callback_host);

    const tenancy = try resolveEndpoints(gpa, "gist.Example.GHE.com");
    defer tenancy.deinit(gpa);
    try std.testing.expectEqualStrings("example.ghe.com", tenancy.canonical_host);
    try std.testing.expectEqual(HostClass.tenancy, tenancy.host_class);
    try std.testing.expectEqualStrings("https://example.ghe.com", tenancy.oauth_base_url);
    try std.testing.expectEqualStrings("https://api.example.ghe.com", tenancy.api_base_url);
    try std.testing.expectEqualStrings("/callback", tenancy.callback_path);
    try std.testing.expectEqualStrings("127.0.0.1", tenancy.callback_host);

    const ghes = try resolveEndpoints(gpa, "github.corp.example.com:8443");
    defer ghes.deinit(gpa);
    try std.testing.expectEqualStrings("github.corp.example.com", ghes.canonical_host);
    try std.testing.expectEqual(HostClass.enterprise, ghes.host_class);
    try std.testing.expectEqualStrings("https://github.corp.example.com", ghes.oauth_base_url);
    try std.testing.expectEqualStrings("https://github.corp.example.com/api/v3", ghes.api_base_url);
    try std.testing.expectEqualStrings("/", ghes.callback_path);
    try std.testing.expectEqualStrings("localhost", ghes.callback_host);
}

test "lookupStoredCredential selects active user, specific requested username, and eraseStoredCredential removes only target" {
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

    const hosts_yaml =
        \\github.com:
        \\    git_protocol: https
        \\    users:
        \\        alice:
        \\        bob:
        \\    user: alice
        \\example.ghe.com:
        \\    git_protocol: https
        \\    users:
        \\        alice_corp:
        \\    user: alice_corp
        \\
    ;
    try writePrivateFile(config_dir, hosts_filename, hosts_yaml);
    try FakeStore.set(gpa, "gh:github.com", "alice", "gho_alice_tok");
    try FakeStore.set(gpa, "gh:github.com", "", "gho_alice_tok");
    try FakeStore.set(gpa, "gh:github.com", "bob", "gho_bob_tok");
    try FakeStore.set(gpa, "gh:example.ghe.com", "alice_corp", "gho_ghe_tok");

    secret_store_override = FakeStore.store;
    defer secret_store_override = null;
    gh_config_dir_override = config_dir;
    defer gh_config_dir_override = null;
    env_override_fn = struct {
        fn get(_: []const u8) ?[]const u8 {
            return null;
        }
    }.get;
    defer env_override_fn = null;

    // 1. Default active user on github.com -> alice.
    const active_cred = (try lookupStoredCredential(gpa, "github.com", null)).?;
    defer active_cred.deinit(gpa);
    try std.testing.expectEqualStrings("alice", active_cred.username);
    try std.testing.expectEqualStrings("gho_alice_tok", active_cred.token);

    // 2. Specific username bob on github.com -> bob.
    const bob_cred = (try lookupStoredCredential(gpa, "github.com", "bob")).?;
    defer bob_cred.deinit(gpa);
    try std.testing.expectEqualStrings("bob", bob_cred.username);
    try std.testing.expectEqualStrings("gho_bob_tok", bob_cred.token);

    // 3. Unknown username on github.com must NOT silently return alice's token.
    const unknown_cred = try lookupStoredCredential(gpa, "github.com", "charlie");
    try std.testing.expect(unknown_cred == null);

    // 4. Tenancy host gist.example.ghe.com resolves to example.ghe.com.
    const ghe_cred = (try lookupStoredCredential(gpa, "gist.example.ghe.com", null)).?;
    defer ghe_cred.deinit(gpa);
    try std.testing.expectEqualStrings("alice_corp", ghe_cred.username);
    try std.testing.expectEqualStrings("gho_ghe_tok", ghe_cred.token);

    // 5. Erase bob on github.com; alice must remain intact.
    const erased = try eraseStoredCredential(gpa, "github.com", "bob");
    try std.testing.expect(erased);
    try std.testing.expect((try lookupStoredCredential(gpa, "github.com", "bob")) == null);
    const alice_still_there = (try lookupStoredCredential(gpa, "github.com", null)).?;
    defer alice_still_there.deinit(gpa);
    try std.testing.expectEqualStrings("alice", alice_still_there.username);
}

test "loginOAuth device flow polls authorization_pending then resolves user on api.example.ghe.com and saves to keyring" {
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

    const MockHttp = struct {
        var poll_calls: usize = 0;
        var last_user_url: [128]u8 = undefined;
        var last_user_url_len: usize = 0;

        fn postFormJson(alloc: Allocator, url: []const u8, body: []const u8) AuthError![]u8 {
            if (std.mem.endsWith(u8, url, "/login/device/code")) {
                if (!std.mem.eql(u8, "https://example.ghe.com/login/device/code", url)) return error.AuthenticationFailed;
                if (std.mem.indexOf(u8, body, "client_id=178c6fc778ccc68e1d6a") == null) return error.AuthenticationFailed;
                return alloc.dupe(
                    u8,
                    "{\"device_code\":\"dev_123\",\"user_code\":\"ABCD-1234\",\"verification_uri\":\"https://example.ghe.com/login/device\",\"expires_in\":900,\"interval\":1}",
                );
            }
            if (std.mem.endsWith(u8, url, "/login/oauth/access_token")) {
                if (!std.mem.eql(u8, "https://example.ghe.com/login/oauth/access_token", url)) return error.AuthenticationFailed;
                poll_calls += 1;
                if (poll_calls == 1) {
                    return alloc.dupe(u8, "{\"error\":\"authorization_pending\"}");
                }
                return alloc.dupe(u8, "{\"access_token\":\"gho_device_ghe_token\"}");
            }
            return error.AuthenticationFailed;
        }

        fn getJsonWithToken(alloc: Allocator, url: []const u8, token: []const u8) AuthError![]u8 {
            @memcpy(last_user_url[0..url.len], url);
            last_user_url_len = url.len;
            if (!std.mem.eql(u8, "gho_device_ghe_token", token)) return error.AuthenticationFailed;
            return alloc.dupe(u8, "{\"login\":\"alice_ghe\"}");
        }

        fn openBrowser(_: Allocator, _: *Io.Writer, _: []const u8) AuthError!void {}
        fn noSleep(_: u32) void {}
    };

    MockHttp.poll_calls = 0;
    MockHttp.last_user_url_len = 0;

    secret_store_override = FakeStore.store;
    defer secret_store_override = null;
    gh_config_dir_override = config_dir;
    defer gh_config_dir_override = null;
    http_transport_override = .{
        .postFormJson = MockHttp.postFormJson,
        .getJsonWithToken = MockHttp.getJsonWithToken,
    };
    defer http_transport_override = null;
    browser_open_override = MockHttp.openBrowser;
    defer browser_open_override = null;
    poll_sleep_override = MockHttp.noSleep;
    defer poll_sleep_override = null;
    env_override_fn = struct {
        fn get(_: []const u8) ?[]const u8 {
            return null;
        }
    }.get;
    defer env_override_fn = null;

    var stderr = Io.Writer.Allocating.init(gpa);
    defer stderr.deinit();

    const cred = try loginOAuth(gpa, .{
        .hostname = "example.ghe.com",
        .mode = .device,
    }, &stderr.writer);
    defer cred.deinit(gpa);

    try std.testing.expectEqual(@as(usize, 2), MockHttp.poll_calls);
    try std.testing.expectEqualStrings("https://api.example.ghe.com/user", MockHttp.last_user_url[0..MockHttp.last_user_url_len]);
    try std.testing.expectEqualStrings("alice_ghe", cred.username);
    try std.testing.expectEqualStrings("gho_device_ghe_token", cred.token);
    try std.testing.expect(std.mem.indexOf(u8, stderr.written(), "ABCD-1234") != null);

    const stored = try FakeStore.get(gpa, "gh:example.ghe.com", "alice_ghe");
    defer gpa.free(stored);
    try std.testing.expectEqualStrings("gho_device_ghe_token", stored);
}

test "loginOAuth web loopback flow exchanges callback code and stores token for example.ghe.com" {
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

    const MockWeb = struct {
        fn postFormJson(alloc: Allocator, url: []const u8, body: []const u8) AuthError![]u8 {
            if (!std.mem.eql(u8, "https://example.ghe.com/login/oauth/access_token", url)) return error.AuthenticationFailed;
            if (std.mem.indexOf(u8, body, "code=test_oauth_code_42") == null) return error.AuthenticationFailed;
            return alloc.dupe(u8, "{\"access_token\":\"gho_web_ghe_token\"}");
        }

        fn getJsonWithToken(alloc: Allocator, url: []const u8, token: []const u8) AuthError![]u8 {
            if (!std.mem.eql(u8, "https://api.example.ghe.com/user", url)) return error.AuthenticationFailed;
            if (!std.mem.eql(u8, "gho_web_ghe_token", token)) return error.AuthenticationFailed;
            return alloc.dupe(u8, "{\"login\":\"cameron_ghe\"}");
        }

        fn openBrowser(alloc: Allocator, _: *Io.Writer, auth_url: []const u8) AuthError!void {
            // Extract redirect_uri and state from auth_url and connect to loopback server.
            const state_marker = "state=";
            const state_idx = std.mem.indexOf(u8, auth_url, state_marker) orelse return error.AuthenticationFailed;
            const state = auth_url[state_idx + state_marker.len ..];

            const port_marker = "redirect_uri=http%3A%2F%2F127.0.0.1%3A";
            const port_start = (std.mem.indexOf(u8, auth_url, port_marker) orelse return error.AuthenticationFailed) + port_marker.len;
            const port_end = std.mem.indexOfPos(u8, auth_url, port_start, "%2F") orelse return error.AuthenticationFailed;
            const port = std.fmt.parseInt(u16, auth_url[port_start..port_end], 10) catch return error.AuthenticationFailed;

            const addr: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(port) };
            const stream = Io.net.IpAddress.connect(&addr, Io.Threaded.global_single_threaded.io(), .{ .mode = .stream }) catch
                return error.NetworkFailure;
            defer stream.close(Io.Threaded.global_single_threaded.io());

            const req = std.fmt.allocPrint(
                alloc,
                "GET /callback?code=test_oauth_code_42&state={s} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                .{state},
            ) catch return error.OutOfMemory;
            defer alloc.free(req);

            var write_buf: [512]u8 = undefined;
            var writer = stream.writer(Io.Threaded.global_single_threaded.io(), &write_buf);
            writer.interface.writeAll(req) catch return error.NetworkFailure;
            writer.interface.flush() catch return error.NetworkFailure;
        }
    };

    secret_store_override = FakeStore.store;
    defer secret_store_override = null;
    gh_config_dir_override = config_dir;
    defer gh_config_dir_override = null;
    http_transport_override = .{
        .postFormJson = MockWeb.postFormJson,
        .getJsonWithToken = MockWeb.getJsonWithToken,
    };
    defer http_transport_override = null;
    browser_open_override = MockWeb.openBrowser;
    defer browser_open_override = null;
    env_override_fn = struct {
        fn get(_: []const u8) ?[]const u8 {
            return null;
        }
    }.get;
    defer env_override_fn = null;

    var stderr = Io.Writer.Allocating.init(gpa);
    defer stderr.deinit();

    const cred = try loginOAuth(gpa, .{
        .hostname = "example.ghe.com",
        .mode = .web,
    }, &stderr.writer);
    defer cred.deinit(gpa);

    try std.testing.expectEqualStrings("cameron_ghe", cred.username);
    try std.testing.expectEqualStrings("gho_web_ghe_token", cred.token);
}

test "loginOAuth falls back to device flow and stores token in hosts.yml when OS keyring returns NoStorageAccess" {
    const gpa = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = Io.Threaded.global_single_threaded.io();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const root = root_buf[0..root_len];

    const config_dir = try std.fs.path.join(gpa, &.{ root, "gh-config" });
    defer gpa.free(config_dir);

    // Existing hosts.yml already has a plaintext token for github.com.
    const initial_hosts =
        \\github.com:
        \\    git_protocol: https
        \\    users:
        \\        cataggar:
        \\            oauth_token: gho_dotcom_existing
        \\    user: cataggar
        \\    oauth_token: gho_dotcom_existing
        \\
    ;
    try writePrivateFile(config_dir, hosts_filename, initial_hosts);

    const NoKeyringStore = struct {
        fn get(_: Allocator, _: []const u8, _: []const u8) SecretError![]u8 {
            return error.NoStorageAccess;
        }
        fn set(_: Allocator, _: []const u8, _: []const u8, _: []const u8) SecretError!void {
            return error.NoStorageAccess;
        }
        fn delete(_: Allocator, _: []const u8, _: []const u8) SecretError!void {
            return error.NoStorageAccess;
        }
        const store: SecretStore = .{
            .get = get,
            .set = set,
            .delete = delete,
        };
    };

    const HeadlessMocks = struct {
        var browser_calls: usize = 0;

        fn postFormJson(alloc: Allocator, url: []const u8, _: []const u8) AuthError![]u8 {
            if (std.mem.eql(u8, "https://microsoft.ghe.com/login/device/code", url)) {
                return alloc.dupe(
                    u8,
                    "{\"device_code\":\"dev_headless\",\"user_code\":\"335D-98F3\",\"verification_uri\":\"https://microsoft.ghe.com/login/device\",\"expires_in\":900,\"interval\":1}",
                );
            }
            if (std.mem.eql(u8, "https://microsoft.ghe.com/login/oauth/access_token", url)) {
                return alloc.dupe(u8, "{\"access_token\":\"gho_headless_ghe_token\"}");
            }
            return error.AuthenticationFailed;
        }

        fn getJsonWithToken(alloc: Allocator, url: []const u8, token: []const u8) AuthError![]u8 {
            if (!std.mem.eql(u8, "https://api.microsoft.ghe.com/user", url)) return error.AuthenticationFailed;
            if (!std.mem.eql(u8, "gho_headless_ghe_token", token)) return error.AuthenticationFailed;
            return alloc.dupe(u8, "{\"login\":\"cameron-taggart\"}");
        }

        fn openBrowser(_: Allocator, stderr_w: *Io.Writer, _: []const u8) AuthError!void {
            browser_calls += 1;
            stderr_w.writeAll("[keyring ado] browser spawn 'xdg-open' failed: FileNotFound\n") catch {};
            return error.NoStorageAccess;
        }

        fn noSleep(_: u32) void {}
    };

    HeadlessMocks.browser_calls = 0;

    secret_store_override = NoKeyringStore.store;
    defer secret_store_override = null;
    gh_config_dir_override = config_dir;
    defer gh_config_dir_override = null;
    http_transport_override = .{
        .postFormJson = HeadlessMocks.postFormJson,
        .getJsonWithToken = HeadlessMocks.getJsonWithToken,
    };
    defer http_transport_override = null;
    browser_open_override = HeadlessMocks.openBrowser;
    defer browser_open_override = null;
    poll_sleep_override = HeadlessMocks.noSleep;
    defer poll_sleep_override = null;
    env_override_fn = struct {
        fn get(name: []const u8) ?[]const u8 {
            if (std.mem.eql(u8, name, "DISPLAY")) return ":0";
            return null;
        }
    }.get;
    defer env_override_fn = null;

    var stdout = Io.Writer.Allocating.init(gpa);
    defer stdout.deinit();
    var stderr = Io.Writer.Allocating.init(gpa);
    defer stderr.deinit();

    const code = try runLogin(gpa, .{
        .hostname = "microsoft.ghe.com",
        .mode = .auto,
    }, &stdout.writer, &stderr.writer);
    try std.testing.expectEqual(@as(u8, 0), code);
    try std.testing.expectEqualStrings(
        "Logged in to microsoft.ghe.com as cameron-taggart (stored in hosts.yml)\n",
        stdout.written(),
    );
    // Browser was only probed once during auto fallback; neither dead loopback URL nor browser error was printed.
    try std.testing.expectEqual(@as(usize, 1), HeadlessMocks.browser_calls);
    try std.testing.expect(std.mem.indexOf(u8, stderr.written(), "127.0.0.1") == null);
    try std.testing.expect(std.mem.indexOf(u8, stderr.written(), "xdg-open") == null);
    try std.testing.expect(std.mem.indexOf(u8, stderr.written(), "335D-98F3") != null);

    // Subsequent credential lookup resolves microsoft.ghe.com from hosts.yml.
    const resolved = (try lookupStoredCredential(gpa, "microsoft.ghe.com", null)).?;
    defer resolved.deinit(gpa);
    try std.testing.expectEqualStrings("cameron-taggart", resolved.username);
    try std.testing.expectEqualStrings("gho_headless_ghe_token", resolved.token);

    // Existing github.com token in hosts.yml must also still be preserved.
    const dotcom_resolved = (try lookupStoredCredential(gpa, "github.com", null)).?;
    defer dotcom_resolved.deinit(gpa);
    try std.testing.expectEqualStrings("cataggar", dotcom_resolved.username);
    try std.testing.expectEqualStrings("gho_dotcom_existing", dotcom_resolved.token);

    // `git credential approve` (`storeGitCredential`) recognizes the token already in hosts.yml.
    try storeGitCredential(gpa, "microsoft.ghe.com", "cameron-taggart", "gho_headless_ghe_token");
}

test "loginOAuth skips web loopback and browser launch in headless SSH session" {
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

    const SshMocks = struct {
        var browser_calls: usize = 0;

        fn postFormJson(alloc: Allocator, url: []const u8, _: []const u8) AuthError![]u8 {
            if (std.mem.eql(u8, "https://microsoft.ghe.com/login/device/code", url)) {
                return alloc.dupe(
                    u8,
                    "{\"device_code\":\"dev_ssh\",\"user_code\":\"48FC-EFA6\",\"verification_uri\":\"https://microsoft.ghe.com/login/device\",\"expires_in\":900,\"interval\":1}",
                );
            }
            if (std.mem.eql(u8, "https://microsoft.ghe.com/login/oauth/access_token", url)) {
                return alloc.dupe(u8, "{\"access_token\":\"gho_ssh_ghe_token\"}");
            }
            return error.AuthenticationFailed;
        }

        fn getJsonWithToken(alloc: Allocator, url: []const u8, token: []const u8) AuthError![]u8 {
            if (!std.mem.eql(u8, "https://api.microsoft.ghe.com/user", url)) return error.AuthenticationFailed;
            if (!std.mem.eql(u8, "gho_ssh_ghe_token", token)) return error.AuthenticationFailed;
            return alloc.dupe(u8, "{\"login\":\"cameron-taggart\"}");
        }

        fn openBrowser(_: Allocator, _: *Io.Writer, _: []const u8) AuthError!void {
            browser_calls += 1;
            return error.NoStorageAccess;
        }

        fn noSleep(_: u32) void {}
    };

    SshMocks.browser_calls = 0;

    secret_store_override = FakeStore.store;
    defer secret_store_override = null;
    gh_config_dir_override = config_dir;
    defer gh_config_dir_override = null;
    http_transport_override = .{
        .postFormJson = SshMocks.postFormJson,
        .getJsonWithToken = SshMocks.getJsonWithToken,
    };
    defer http_transport_override = null;
    browser_open_override = SshMocks.openBrowser;
    defer browser_open_override = null;
    poll_sleep_override = SshMocks.noSleep;
    defer poll_sleep_override = null;
    env_override_fn = struct {
        fn get(name: []const u8) ?[]const u8 {
            if (std.mem.eql(u8, name, "SSH_TTY")) return "/dev/pts/0";
            if (std.mem.eql(u8, name, "SSH_CONNECTION")) return "10.0.0.1 54321 10.0.0.2 22";
            return null;
        }
    }.get;
    defer env_override_fn = null;

    var stdout = Io.Writer.Allocating.init(gpa);
    defer stdout.deinit();
    var stderr = Io.Writer.Allocating.init(gpa);
    defer stderr.deinit();

    const code = try runLogin(gpa, .{
        .hostname = "microsoft.ghe.com",
        .mode = .auto,
    }, &stdout.writer, &stderr.writer);
    try std.testing.expectEqual(@as(u8, 0), code);
    // Neither webAppOAuthFlow nor deviceCodeOAuthFlow attempted to launch a browser.
    try std.testing.expectEqual(@as(usize, 0), SshMocks.browser_calls);
    try std.testing.expect(std.mem.indexOf(u8, stderr.written(), "127.0.0.1") == null);
    try std.testing.expect(std.mem.indexOf(u8, stderr.written(), "48FC-EFA6") != null);
}

test "saveUserCredential returns Locked and does not write plaintext hosts.yml when keyring is locked" {
    const gpa = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = Io.Threaded.global_single_threaded.io();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const root = root_buf[0..root_len];

    const config_dir = try std.fs.path.join(gpa, &.{ root, "gh-config" });
    defer gpa.free(config_dir);

    const LockedStore = struct {
        fn get(_: Allocator, _: []const u8, _: []const u8) SecretError![]u8 {
            return error.Locked;
        }
        fn set(_: Allocator, _: []const u8, _: []const u8, _: []const u8) SecretError!void {
            return error.Locked;
        }
        fn delete(_: Allocator, _: []const u8, _: []const u8) SecretError!void {
            return error.Locked;
        }
        const store: SecretStore = .{
            .get = get,
            .set = set,
            .delete = delete,
        };
    };

    secret_store_override = LockedStore.store;
    defer secret_store_override = null;
    gh_config_dir_override = config_dir;
    defer gh_config_dir_override = null;

    try std.testing.expectError(
        error.Locked,
        saveUserCredential(gpa, "microsoft.ghe.com", "cameron-taggart", "gho_secret_token"),
    );

    const hosts_path = try std.fs.path.join(gpa, &.{ config_dir, hosts_filename });
    defer gpa.free(hosts_path);
    try std.testing.expect(readFileIfExists(gpa, hosts_path) == null);
}

