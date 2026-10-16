//! `keyring devops-npm [-c <path>] [-f|--force] [--validate-only]`
//!
//! Authenticates Azure Artifacts npm registries declared in a workspace `.npmrc`
//! and writes `//<registry>:_authToken=<token>` entries into the user's
//! `~/.npmrc` (or `$NPM_CONFIG_USERCONFIG`), matching the workflow of
//! `@microsoft/artifacts-npm-credprovider` without requiring Node.js, .NET, or
//! `@npmcli/config`.
const std = @import("std");
const builtin = @import("builtin");
const ado = @import("ado.zig");
const msal_cache = @import("msal_cache.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Options = struct {
    config_file: ?[]const u8 = null,
    force: bool = false,
    validate_only: bool = false,
};

pub const Hooks = struct {
    validateToken: *const fn (gpa: Allocator, io: Io, org: []const u8, token: []const u8) bool,
    acquireOrgToken: *const fn (gpa: Allocator, io: Io, stderr: *Io.Writer, registry_url: []const u8, bypass_session_cache: bool) ado.Error![]u8,
};

const live_hooks: Hooks = .{
    .validateToken = liveValidateToken,
    .acquireOrgToken = liveAcquireOrgToken,
};

var active_hooks: Hooks = live_hooks;
var user_config_override: ?[]const u8 = null;

const RegistrySpec = struct {
    /// Normalized registry path without scheme, always ending with `/`
    /// (e.g. `pkgs.dev.azure.com/myorg/myproj/_packaging/myfeed/npm/registry/`).
    normalized: []const u8,
    /// Full `https://` URL for `ado.extractOrg` and `ado.getCredentialWithOptions`.
    full_url: []const u8,
    /// Extracted Azure DevOps organization name.
    org: []const u8,
};

const TokenUpdate = struct {
    normalized: []const u8,
    token: []const u8,
};

/// Parse CLI arguments following `keyring devops-npm`. Returns `null` on
/// unrecognized flags or unexpected positional arguments.
pub fn parseArgs(rest: []const []const u8) ?Options {
    var opts: Options = .{};
    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        const arg = rest[i];
        if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--force")) {
            opts.force = true;
        } else if (std.mem.eql(u8, arg, "--validate-only")) {
            opts.validate_only = true;
        } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config-file")) {
            if (i + 1 >= rest.len) return null;
            i += 1;
            if (rest[i].len == 0) return null;
            opts.config_file = rest[i];
        } else if (std.mem.startsWith(u8, arg, "--config-file=")) {
            const val = arg["--config-file=".len..];
            if (val.len == 0) return null;
            opts.config_file = val;
        } else {
            return null;
        }
    }
    return opts;
}

pub fn run(gpa: Allocator, io: Io, opts: Options, stdout: *Io.Writer, stderr: *Io.Writer) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const user_npmrc = resolveUserNpmrcPath(a) catch {
        try stderr.writeAll("keyring: devops-npm: could not resolve user .npmrc path (HOME not set)\n");
        try stderr.flush();
        return 1;
    };

    const workspace_npmrc = resolveWorkspaceNpmrcPath(a, opts.config_file) orelse {
        if (opts.config_file) |cfg| {
            try stderr.print("keyring: devops-npm: workspace config file not found: {s}\n", .{cfg});
        } else {
            try stderr.writeAll("keyring: devops-npm: no workspace .npmrc found; try -c <path>\n");
        }
        try stderr.flush();
        return 1;
    };

    if (pathsReferToSameFile(a, workspace_npmrc, user_npmrc)) {
        try stderr.writeAll("keyring: devops-npm: workspace .npmrc path must not be the user .npmrc file\n");
        try stderr.flush();
        return 1;
    }

    const workspace_content = readFileIfExists(a, workspace_npmrc) orelse {
        try stderr.print("keyring: devops-npm: failed to read {s}\n", .{workspace_npmrc});
        try stderr.flush();
        return 1;
    };

    const workspace_registries = try parseWorkspaceRegistries(a, workspace_content);
    if (workspace_registries.len == 0) {
        try stderr.print("keyring: devops-npm: no Azure DevOps npm registries found in {s}\n", .{workspace_npmrc});
        try stderr.flush();
        return 1;
    }

    const user_content = readFileIfExists(a, user_npmrc) orelse "";
    var user_tokens = try parseUserAuthTokens(a, user_content);
    defer user_tokens.deinit(a);

    // Check which workspace registries need authentication.
    var invalid_specs: std.ArrayList(RegistrySpec) = .empty;
    defer invalid_specs.deinit(a);

    var validated_org_tokens: std.StringHashMapUnmanaged(bool) = .empty;
    defer validated_org_tokens.deinit(a);

    for (workspace_registries) |spec| {
        if (opts.force) {
            try invalid_specs.append(a, spec);
            continue;
        }
        const existing_token = user_tokens.get(spec.normalized) orelse {
            try invalid_specs.append(a, spec);
            continue;
        };
        if (!isUsableTokenLiteral(existing_token)) {
            try invalid_specs.append(a, spec);
            continue;
        }
        const cache_key = try std.fmt.allocPrint(a, "{s}\x00{s}", .{ spec.org, existing_token });
        const valid = if (validated_org_tokens.get(cache_key)) |cached|
            cached
        else blk: {
            const ok = active_hooks.validateToken(a, io, spec.org, existing_token);
            try validated_org_tokens.put(a, cache_key, ok);
            break :blk ok;
        };
        if (!valid) {
            try invalid_specs.append(a, spec);
        }
    }

    if (invalid_specs.items.len == 0) {
        try stdout.print("Credentials are already valid for {d} registry(ies).\n", .{workspace_registries.len});
        try stdout.flush();
        return 0;
    }

    if (opts.validate_only) {
        try stderr.print("keyring: devops-npm: {d} of {d} registry(ies) have missing or invalid credentials\n", .{
            invalid_specs.items.len,
            workspace_registries.len,
        });
        try stderr.flush();
        return 1;
    }

    // Group invalid registries by organization so each organization is
    // authenticated only once.
    var org_tokens: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer org_tokens.deinit(a);

    for (invalid_specs.items) |spec| {
        if (org_tokens.contains(spec.org)) continue;
        // Bypass the cached session.dat token when --force was passed or when the
        // user .npmrc already held a token for this registry that failed live
        // validation.
        const had_rejected_token = user_tokens.get(spec.normalized) != null;
        const bypass_cache = opts.force or had_rejected_token;
        const token = active_hooks.acquireOrgToken(a, io, stderr, spec.full_url, bypass_cache) catch |err| {
            try stderr.print("keyring: devops-npm: failed to authenticate organization '{s}': {s}\n", .{
                spec.org,
                @errorName(err),
            });
            try stderr.flush();
            return switch (err) {
                error.NoStorageAccess => 4,
                else => 1,
            };
        };
        try org_tokens.put(a, spec.org, token);
    }

    // Build the list of //registry:_authToken= updates: all invalidated workspace
    // registries plus any other Azure DevOps registries already present in the
    // user's .npmrc that belong to one of the newly authenticated organizations.
    var updates: std.ArrayList(TokenUpdate) = .empty;
    defer updates.deinit(a);

    for (invalid_specs.items) |spec| {
        if (org_tokens.get(spec.org)) |token| {
            try putOrUpdateToken(a, &updates, spec.normalized, token);
        }
    }

    var user_it = user_tokens.iterator();
    while (user_it.next()) |entry| {
        const reg = entry.key_ptr.*;
        const full_url = try std.fmt.allocPrint(a, "https://{s}", .{reg});
        if (!ado.isDevOpsUrl(full_url)) continue;
        const org = ado.extractOrg(full_url) orelse continue;
        if (org_tokens.get(org)) |token| {
            try putOrUpdateToken(a, &updates, reg, token);
        }
    }

    const updated_content = try patchUserNpmrc(a, user_content, updates.items);
    writeFileAtomic(a, user_npmrc, updated_content) catch |err| {
        try stderr.print("keyring: devops-npm: failed to write {s}: {s}\n", .{ user_npmrc, @errorName(err) });
        try stderr.flush();
        return 1;
    };

    try stdout.print("Updated credentials for {d} registry(ies) in {s}.\n", .{ updates.items.len, user_npmrc });
    try stdout.flush();
    return 0;
}

fn putOrUpdateToken(a: Allocator, updates: *std.ArrayList(TokenUpdate), normalized: []const u8, token: []const u8) !void {
    for (updates.items) |*item| {
        if (std.mem.eql(u8, item.normalized, normalized)) {
            item.token = token;
            return;
        }
    }
    try updates.append(a, .{ .normalized = normalized, .token = token });
}

fn isUsableTokenLiteral(token: []const u8) bool {
    const trimmed = std.mem.trim(u8, token, " \t\r\n");
    if (trimmed.len == 0) return false;
    // Reject unexpanded ${VAR} placeholders.
    if (std.mem.indexOf(u8, trimmed, "${") != null) return false;
    return true;
}

/// Extract and normalize all Azure DevOps npm registry URLs from a `.npmrc`
/// file's contents. Ignores comments, blank lines, unrelated settings, and
/// `//...:_authToken=...` lines.
pub fn parseWorkspaceRegistries(a: Allocator, content: []const u8) ![]RegistrySpec {
    var specs: std.ArrayList(RegistrySpec) = .empty;
    errdefer specs.deinit(a);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;
        if (std.mem.startsWith(u8, line, "//")) continue;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        if (!isRegistryConfigKey(key)) continue;

        const raw_value = cleanIniValue(line[eq + 1 ..]);
        if (raw_value.len == 0) continue;

        const normalized = normalizeRegistryUrl(a, raw_value) catch continue;
        const full_url = try std.fmt.allocPrint(a, "https://{s}", .{normalized});
        if (!ado.isDevOpsUrl(full_url)) continue;
        const org = ado.extractOrg(full_url) orelse continue;

        var duplicate = false;
        for (specs.items) |existing| {
            if (std.mem.eql(u8, existing.normalized, normalized)) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            try specs.append(a, .{
                .normalized = normalized,
                .full_url = full_url,
                .org = org,
            });
        }
    }

    return specs.toOwnedSlice(a);
}

fn isRegistryConfigKey(key: []const u8) bool {
    return std.mem.eql(u8, key, "registry") or std.mem.endsWith(u8, key, ":registry");
}

fn cleanIniValue(raw: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r");
    if (trimmed.len >= 2 and
        ((trimmed[0] == '"' and trimmed[trimmed.len - 1] == '"') or
            (trimmed[0] == '\'' and trimmed[trimmed.len - 1] == '\'')))
    {
        return trimmed[1 .. trimmed.len - 1];
    }
    // Strip unquoted inline comments (` #...` or ` ;...`).
    for (trimmed, 0..) |c, idx| {
        if ((c == '#' or c == ';') and idx > 0 and (trimmed[idx - 1] == ' ' or trimmed[idx - 1] == '\t')) {
            return std.mem.trimEnd(u8, trimmed[0..idx], " \t");
        }
    }
    return trimmed;
}

/// Normalize a registry URL to `<host>/<path>/` (no scheme or leading `//`,
/// always ending with `/`).
pub fn normalizeRegistryUrl(a: Allocator, raw_url: []const u8) ![]const u8 {
    var rest = std.mem.trim(u8, raw_url, " \t\r\n");
    if (std.mem.startsWith(u8, rest, "https://")) {
        rest = rest["https://".len..];
    } else if (std.mem.startsWith(u8, rest, "http://")) {
        rest = rest["http://".len..];
    } else if (std.mem.startsWith(u8, rest, "//")) {
        rest = rest["//".len..];
    }
    if (rest.len == 0) return error.InvalidRegistryUrl;
    if (std.mem.indexOfScalar(u8, rest, '/') == null) return error.InvalidRegistryUrl;

    if (std.mem.endsWith(u8, rest, "/")) {
        return a.dupe(u8, rest);
    }
    return std.fmt.allocPrint(a, "{s}/", .{rest});
}

/// Parse existing `//<registry>:_authToken=<token>` entries from a user `.npmrc`.
pub fn parseUserAuthTokens(a: Allocator, content: []const u8) !std.StringHashMapUnmanaged([]const u8) {
    var map: std.StringHashMapUnmanaged([]const u8) = .empty;
    errdefer map.deinit(a);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (parseAuthTokenLine(line)) |parsed| {
            const norm = normalizeRegistryUrl(a, parsed.registry) catch continue;
            try map.put(a, norm, try a.dupe(u8, parsed.token));
        }
    }
    return map;
}

const ParsedAuthLine = struct {
    registry: []const u8,
    token: []const u8,
};

fn parseAuthTokenLine(line: []const u8) ?ParsedAuthLine {
    if (!std.mem.startsWith(u8, line, "//")) return null;
    const marker = ":_authToken=";
    const idx = std.mem.indexOf(u8, line, marker) orelse return null;
    if (idx <= 2) return null;
    const reg = line[2..idx];
    const tok = cleanIniValue(line[idx + marker.len ..]);
    return .{ .registry = reg, .token = tok };
}

/// Update or append `//<registry>:_authToken=<token>` lines in `user_content`,
/// preserving all unrelated settings, comments, and line ordering.
pub fn patchUserNpmrc(a: Allocator, user_content: []const u8, updates: []const TokenUpdate) ![]u8 {
    var out = std.Io.Writer.Allocating.init(a);
    errdefer out.deinit();

    const applied = try a.alloc(bool, updates.len);
    @memset(applied, false);

    if (user_content.len > 0) {
        var lines = std.mem.splitScalar(u8, user_content, '\n');
        var first = true;
        var rest_iter = lines;
        _ = rest_iter.next();
        while (lines.next()) |raw_line| {
            const has_more = rest_iter.next() != null;
            const trimmed_cr = std.mem.trimEnd(u8, raw_line, "\r");
            // Avoid duplicating a trailing empty split segment when the file ends
            // with '\n'.
            if (!has_more and trimmed_cr.len == 0) break;

            if (!first) try out.writer.writeByte('\n');
            first = false;

            const trimmed = std.mem.trim(u8, trimmed_cr, " \t");
            if (parseAuthTokenLine(trimmed)) |parsed| {
                if (normalizeRegistryUrl(a, parsed.registry)) |norm| {
                    var replaced = false;
                    for (updates, 0..) |u, idx| {
                        if (std.mem.eql(u8, u.normalized, norm)) {
                            try out.writer.print("//{s}:_authToken={s}", .{ u.normalized, u.token });
                            applied[idx] = true;
                            replaced = true;
                            break;
                        }
                    }
                    if (replaced) continue;
                } else |_| {}
            }
            try out.writer.writeAll(trimmed_cr);
        }
    }

    for (updates, 0..) |u, idx| {
        if (applied[idx]) continue;
        if (out.written().len > 0) try out.writer.writeByte('\n');
        try out.writer.print("//{s}:_authToken={s}", .{ u.normalized, u.token });
    }

    if (out.written().len > 0) {
        try out.writer.writeByte('\n');
    }
    return out.toOwnedSlice();
}

/// Build the HTTP Authorization header value for the Azure DevOps Feeds REST
/// API (`feeds.dev.azure.com`), matching `azure_devops_rust_api/src/auth.rs`:
/// - OAuth bearer JWTs (`eyJ...` with `.` segments) use `Bearer <token>`
/// - PATs / `VssSessionToken`s use `Basic base64(":<pat>")`
pub fn authorizationHeaderForToken(gpa: Allocator, token: []const u8) ![]u8 {
    if (std.mem.startsWith(u8, token, "eyJ") and std.mem.indexOfScalar(u8, token, '.') != null) {
        return std.fmt.allocPrint(gpa, "Bearer {s}", .{token});
    }
    const raw = try std.fmt.allocPrint(gpa, ":{s}", .{token});
    defer gpa.free(raw);
    const enc_len = std.base64.standard.Encoder.calcSize(raw.len);
    const prefix = "Basic ";
    const out = try gpa.alloc(u8, prefix.len + enc_len);
    @memcpy(out[0..prefix.len], prefix);
    _ = std.base64.standard.Encoder.encode(out[prefix.len..], raw);
    return out;
}

fn liveValidateToken(gpa: Allocator, io: Io, org: []const u8, token: []const u8) bool {
    const url = std.fmt.allocPrint(
        gpa,
        "https://feeds.dev.azure.com/{s}/_apis/packaging/feeds/1?api-version=7.1",
        .{org},
    ) catch return false;
    defer gpa.free(url);

    const auth = authorizationHeaderForToken(gpa, token) catch return false;
    defer gpa.free(auth);

    var response = std.Io.Writer.Allocating.init(gpa);
    defer response.deinit();

    var client: std.http.Client = .{
        .allocator = gpa,
        .io = io,
    };
    defer client.deinit();

    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = .GET,
        .extra_headers = &.{
            .{ .name = "accept", .value = "application/json" },
            .{ .name = "authorization", .value = auth },
        },
        .response_writer = &response.writer,
    }) catch return false;

    // Matching @microsoft/artifacts-npm-credprovider's makeADORequest: feed ID
    // "1" does not exist, so an authenticated request returns 404 Not Found (or
    // 200 OK), whereas an invalid/expired token returns 401/403 or 203
    // Non-Authoritative Information (sign-in redirect).
    return result.status == .ok or result.status == .not_found;
}

const ado_entra_scope = "499b84ac-1321-427f-aa17-267ca6975798/.default";

fn liveAcquireOrgToken(gpa: Allocator, io: Io, stderr: *Io.Writer, registry_url: []const u8, bypass_session_cache: bool) ado.Error![]u8 {
    const org = ado.extractOrg(registry_url) orelse return error.Unsupported;

    // 1. Check explicit CI/CD environment variables (`SYSTEM_ACCESSTOKEN`,
    //    `AZURE_DEVOPS_EXT_PAT`). Both PATs and Entra bearer tokens work as
    //    npm `_authToken` values against Azure Artifacts feeds.
    for ([_][]const u8{ "SYSTEM_ACCESSTOKEN", "AZURE_DEVOPS_EXT_PAT" }) |env_name| {
        if (getEnvVarOwned(gpa, env_name)) |val| {
            const trimmed = std.mem.trim(u8, val, " \t\r\n");
            if (trimmed.len > 0) {
                defer gpa.free(val);
                return gpa.dupe(u8, trimmed);
            }
            gpa.free(val);
        }
    }

    // 2. Try AzureCliCredential (`az account get-access-token --output json
    //    --scope 499b84ac-1321-427f-aa17-267ca6975798/.default`, adapted from
    //    `azure-sdk-for-zig/sdk/core/identity/azure_cli.zig`). Exchange the
    //    Entra access token for a `vso.packaging` VssSessionToken when
    //    possible, or fall back to the Entra bearer token directly (e.g. for
    //    service principals).
    if (tryAzureCliAccessToken(gpa, io)) |access_token| {
        defer gpa.free(access_token);
        if (ado.exchangeForSessionToken(gpa, access_token, org, bypass_session_cache)) |session_token| {
            return session_token;
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return gpa.dupe(u8, access_token),
        }
    }

    // 3. Fall back to the built-in ADO backend (session.dat cache, MSAL FOCI
    //    cache, OS secret store refresh token, and browser OAuth2 + PKCE).
    const cred = try ado.getCredentialWithOptions(gpa, stderr, registry_url, .{
        .bypass_session_cache = bypass_session_cache,
    });
    return cred.password;
}

/// Acquire an Entra access token for Azure DevOps via Azure CLI
/// (`az account get-access-token`), following `AzureCliCredential` in
/// `cataggar/azure-sdk-for-zig` (`sdk/core/identity/azure_cli.zig`).
fn tryAzureCliAccessToken(gpa: Allocator, io: Io) ?[]u8 {
    const argv = [_][]const u8{
        if (builtin.os.tag == .windows) "az.cmd" else "az",
        "account",
        "get-access-token",
        "--output",
        "json",
        "--scope",
        ado_entra_scope,
    };
    const result = std.process.run(gpa, io, .{
        .argv = &argv,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(256 * 1024),
    }) catch return null;
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code != 0) return null,
        else => return null,
    }
    return parseAzureCliAccessToken(gpa, result.stdout) catch null;
}

/// Parse the `accessToken` field from `az account get-access-token --output json`.
pub fn parseAzureCliAccessToken(gpa: Allocator, body: []const u8) ![]u8 {
    const Schema = struct {
        accessToken: []const u8,
    };
    var parsed = try std.json.parseFromSlice(Schema, gpa, body, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    if (parsed.value.accessToken.len == 0) return error.InvalidTokenResponse;
    return gpa.dupe(u8, parsed.value.accessToken);
}

fn resolveUserNpmrcPath(gpa: Allocator) ![]u8 {
    if (user_config_override) |override| return gpa.dupe(u8, override);
    if (getEnvVarOwned(gpa, "NPM_CONFIG_USERCONFIG")) |val| {
        if (val.len > 0) return val;
        gpa.free(val);
    }
    const home = msal_cache.getHome(gpa) orelse return error.HomeNotFound;
    defer gpa.free(home);
    return std.fs.path.join(gpa, &.{ home, ".npmrc" });
}

fn resolveWorkspaceNpmrcPath(gpa: Allocator, explicit: ?[]const u8) ?[]u8 {
    if (explicit) |cfg| {
        if (fileExists(cfg)) return gpa.dupe(u8, cfg) catch null;
        return null;
    }
    if (fileExists(".npmrc")) {
        return gpa.dupe(u8, ".npmrc") catch null;
    }

    // Walk up from the current working directory looking for a git root.
    const io = std.Io.Threaded.global_single_threaded.io();
    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    const len = std.Io.Dir.cwd().realPath(io, &cwd_buf) catch return null;
    var current: []const u8 = cwd_buf[0..len];

    while (true) {
        const git_entry = std.fs.path.join(gpa, &.{ current, ".git" }) catch return null;
        defer gpa.free(git_entry);
        if (pathExists(git_entry)) {
            const root_npmrc = std.fs.path.join(gpa, &.{ current, ".npmrc" }) catch return null;
            if (fileExists(root_npmrc)) return root_npmrc;
            gpa.free(root_npmrc);

            const rush_npmrc = std.fs.path.join(gpa, &.{ current, "common", "config", "rush", ".npmrc" }) catch return null;
            if (fileExists(rush_npmrc)) return rush_npmrc;
            gpa.free(rush_npmrc);
            return null;
        }
        const parent = std.fs.path.dirname(current) orelse break;
        if (std.mem.eql(u8, parent, current)) break;
        current = parent;
    }
    return null;
}

fn pathsReferToSameFile(gpa: Allocator, a_path: []const u8, b_path: []const u8) bool {
    _ = gpa;
    if (std.mem.eql(u8, a_path, b_path)) return true;
    const io = std.Io.Threaded.global_single_threaded.io();
    var a_buf: [std.fs.max_path_bytes]u8 = undefined;
    var b_buf: [std.fs.max_path_bytes]u8 = undefined;
    const a_len = std.Io.Dir.cwd().realPathFile(io, a_path, &a_buf) catch return false;
    const b_len = std.Io.Dir.cwd().realPathFile(io, b_path, &b_buf) catch return false;
    return std.mem.eql(u8, a_buf[0..a_len], b_buf[0..b_len]);
}

fn readFileIfExists(gpa: Allocator, path: []const u8) ?[]u8 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(4 * 1024 * 1024)) catch null;
}

fn fileExists(path: []const u8) bool {
    const io = std.Io.Threaded.global_single_threaded.io();
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn pathExists(path: []const u8) bool {
    return fileExists(path);
}

fn writeFileAtomic(gpa: Allocator, path: []const u8, contents: []const u8) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    if (std.fs.path.dirname(path)) |parent| {
        if (parent.len > 0) {
            _ = std.Io.Dir.cwd().createDirPathStatus(io, parent, dirPermissions()) catch return error.WriteFailure;
        }
    }
    var suffix_bytes: [8]u8 = undefined;
    io.random(&suffix_bytes);
    const suffix_hex = std.fmt.bytesToHex(suffix_bytes, .lower);
    const tmp = try std.fmt.allocPrint(gpa, "{s}.{s}.tmp", .{ path, suffix_hex });
    defer gpa.free(tmp);
    {
        var file = std.Io.Dir.cwd().createFile(io, tmp, .{ .truncate = true, .permissions = filePermissions() }) catch return error.WriteFailure;
        defer file.close(io);
        file.writeStreamingAll(io, contents) catch return error.WriteFailure;
    }
    std.Io.Dir.cwd().rename(tmp, std.Io.Dir.cwd(), path, io) catch {
        std.Io.Dir.cwd().deleteFile(io, tmp) catch {};
        return error.WriteFailure;
    };
}

fn dirPermissions() std.Io.File.Permissions {
    return if (builtin.os.tag == .windows) .default_dir else .fromMode(0o700);
}

fn filePermissions() std.Io.File.Permissions {
    return if (builtin.os.tag == .windows) .default_file else .fromMode(0o600);
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

test "parseArgs parses devops-npm flags" {
    const def = parseArgs(&.{}).?;
    try std.testing.expect(!def.force);
    try std.testing.expect(!def.validate_only);
    try std.testing.expect(def.config_file == null);

    const full = parseArgs(&.{ "-c", "sub/.npmrc", "-f", "--validate-only" }).?;
    try std.testing.expect(full.force);
    try std.testing.expect(full.validate_only);
    try std.testing.expectEqualStrings("sub/.npmrc", full.config_file.?);

    const eq = parseArgs(&.{ "--config-file=custom/.npmrc", "--force" }).?;
    try std.testing.expect(eq.force);
    try std.testing.expectEqualStrings("custom/.npmrc", eq.config_file.?);

    try std.testing.expect(parseArgs(&.{"-c"}) == null);
    try std.testing.expect(parseArgs(&.{"--config-file="}) == null);
    try std.testing.expect(parseArgs(&.{"--unknown"}) == null);
    try std.testing.expect(parseArgs(&.{"positional"}) == null);
}

test "parseAzureCliAccessToken extracts accessToken from az json output" {
    const gpa = std.testing.allocator;
    const body =
        \\{"accessToken":"cli-tok-2","expiresOn":"2026-04-01 15:00:00.000000","expires_on":1743523200,"subscription":"sub","tenant":"tenant","tokenType":"Bearer"}
    ;
    const tok = try parseAzureCliAccessToken(gpa, body);
    defer gpa.free(tok);
    try std.testing.expectEqualStrings("cli-tok-2", tok);

    try std.testing.expectError(error.InvalidTokenResponse, parseAzureCliAccessToken(gpa, "{\"accessToken\":\"\"}"));
}

test "authorizationHeaderForToken formats PATs as Basic and JWTs as Bearer" {
    const gpa = std.testing.allocator;

    const pat_hdr = try authorizationHeaderForToken(gpa, "my-pat-token");
    defer gpa.free(pat_hdr);
    try std.testing.expectEqualStrings("Basic Om15LXBhdC10b2tlbg==", pat_hdr);

    const jwt_hdr = try authorizationHeaderForToken(gpa, "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig");
    defer gpa.free(jwt_hdr);
    try std.testing.expectEqualStrings("Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig", jwt_hdr);
}

test "parseWorkspaceRegistries handles legacy visualstudio.com, scoped registries, and _authToken=${NPM_TOKEN}" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const sample =
        \\# project npm config
        \\registry=https://myorg.pkgs.visualstudio.com/_packaging/myfeed/npm/registry/
        \\//myorg.pkgs.visualstudio.com/_packaging/myfeed/npm/registry/:_authToken=${NPM_TOKEN}
        \\@myscope:registry=https://pkgs.dev.azure.com/otherorg/proj/_packaging/scoped/npm/registry
        \\@pub:registry=https://registry.npmjs.org/
        \\always-auth=true
    ;

    const specs = try parseWorkspaceRegistries(a, sample);
    try std.testing.expectEqual(@as(usize, 2), specs.len);
    try std.testing.expectEqualStrings("myorg.pkgs.visualstudio.com/_packaging/myfeed/npm/registry/", specs[0].normalized);
    try std.testing.expectEqualStrings("myorg", specs[0].org);
    try std.testing.expectEqualStrings("pkgs.dev.azure.com/otherorg/proj/_packaging/scoped/npm/registry/", specs[1].normalized);
    try std.testing.expectEqualStrings("otherorg", specs[1].org);
}

test "patchUserNpmrc updates existing tokens in place and appends new ones" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const initial =
        \\script-shell=/bin/bash
        \\//pkgs.dev.azure.com/org1/proj/_packaging/feed1/npm/registry/:_authToken=old-token
        \\//registry.npmjs.org/:_authToken=npm-public-token
        \\
    ;
    const updates = [_]TokenUpdate{
        .{
            .normalized = "pkgs.dev.azure.com/org1/proj/_packaging/feed1/npm/registry/",
            .token = "new-token-1",
        },
        .{
            .normalized = "org2.pkgs.visualstudio.com/_packaging/feed2/npm/registry/",
            .token = "new-token-2",
        },
    };

    const patched = try patchUserNpmrc(a, initial, &updates);
    const expected =
        \\script-shell=/bin/bash
        \\//pkgs.dev.azure.com/org1/proj/_packaging/feed1/npm/registry/:_authToken=new-token-1
        \\//registry.npmjs.org/:_authToken=npm-public-token
        \\//org2.pkgs.visualstudio.com/_packaging/feed2/npm/registry/:_authToken=new-token-2
        \\
    ;
    try std.testing.expectEqualStrings(expected, patched);
}

const FakeState = struct {
    var valid_token: []const u8 = "valid-session-token";
    var issued_token: []const u8 = "fresh-session-token";
    var acquire_calls: usize = 0;
    var last_bypass_cache: bool = false;

    fn reset() void {
        valid_token = "valid-session-token";
        issued_token = "fresh-session-token";
        acquire_calls = 0;
        last_bypass_cache = false;
    }

    fn validate(_: Allocator, _: Io, _: []const u8, token: []const u8) bool {
        return std.mem.eql(u8, token, valid_token);
    }

    fn acquire(gpa: Allocator, _: Io, _: *Io.Writer, _: []const u8, bypass: bool) ado.Error![]u8 {
        acquire_calls += 1;
        last_bypass_cache = bypass;
        return gpa.dupe(u8, issued_token);
    }
};

test "run authenticates workspace feeds, deduplicates orgs, and honors validate-only and force" {
    const gpa = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &buf);
    const dir_path = try gpa.dupe(u8, buf[0..len]);
    defer gpa.free(dir_path);

    const ws_npmrc = try std.fs.path.join(gpa, &.{ dir_path, "project.npmrc" });
    defer gpa.free(ws_npmrc);
    const user_npmrc = try std.fs.path.join(gpa, &.{ dir_path, "user.npmrc" });
    defer gpa.free(user_npmrc);

    try tmp.dir.writeFile(io, .{
        .sub_path = "project.npmrc",
        .data =
        \\registry=https://myorg.pkgs.visualstudio.com/_packaging/feedA/npm/registry/
        \\//myorg.pkgs.visualstudio.com/_packaging/feedA/npm/registry/:_authToken=${NPM_TOKEN}
        \\@scope:registry=https://pkgs.dev.azure.com/myorg/proj/_packaging/feedB/npm/registry/
        \\
        ,
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "user.npmrc",
        .data = "script-shell=/bin/sh\n",
    });

    FakeState.reset();
    active_hooks = .{
        .validateToken = FakeState.validate,
        .acquireOrgToken = FakeState.acquire,
    };
    defer active_hooks = live_hooks;

    user_config_override = user_npmrc;
    defer user_config_override = null;

    var stdout = std.Io.Writer.Allocating.init(gpa);
    defer stdout.deinit();
    var stderr = std.Io.Writer.Allocating.init(gpa);
    defer stderr.deinit();

    // 1. --validate-only fails when user.npmrc has no tokens yet.
    const code_val_fail = try run(gpa, io, .{
        .config_file = ws_npmrc,
        .validate_only = true,
    }, &stdout.writer, &stderr.writer);
    try std.testing.expectEqual(@as(u8, 1), code_val_fail);
    try std.testing.expectEqual(@as(usize, 0), FakeState.acquire_calls);

    // 2. Normal run acquires once for 'myorg' and writes both registries.
    FakeState.issued_token = "valid-session-token";
    const code_auth = try run(gpa, io, .{
        .config_file = ws_npmrc,
    }, &stdout.writer, &stderr.writer);
    try std.testing.expectEqual(@as(u8, 0), code_auth);
    try std.testing.expectEqual(@as(usize, 1), FakeState.acquire_calls);
    try std.testing.expect(!FakeState.last_bypass_cache);

    const written = readFileIfExists(gpa, user_npmrc).?;
    defer gpa.free(written);
    try std.testing.expect(std.mem.indexOf(u8, written, "//myorg.pkgs.visualstudio.com/_packaging/feedA/npm/registry/:_authToken=valid-session-token\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "//pkgs.dev.azure.com/myorg/proj/_packaging/feedB/npm/registry/:_authToken=valid-session-token\n") != null);

    // 3. Subsequent run without --force sees valid credentials and makes 0 acquire calls.
    const code_cached = try run(gpa, io, .{
        .config_file = ws_npmrc,
    }, &stdout.writer, &stderr.writer);
    try std.testing.expectEqual(@as(u8, 0), code_cached);
    try std.testing.expectEqual(@as(usize, 1), FakeState.acquire_calls);

    // 4. --force bypasses cache and updates tokens.
    FakeState.issued_token = "rotated-session-token";
    const code_force = try run(gpa, io, .{
        .config_file = ws_npmrc,
        .force = true,
    }, &stdout.writer, &stderr.writer);
    try std.testing.expectEqual(@as(u8, 0), code_force);
    try std.testing.expectEqual(@as(usize, 2), FakeState.acquire_calls);
    try std.testing.expect(FakeState.last_bypass_cache);
}
