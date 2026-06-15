const std = @import("std");
const builtin = @import("builtin");
const wincred = @import("wincred.zig");
const keychain = @import("keychain.zig");
const msal_cache = @import("msal_cache.zig");
const dpapi = @import("dpapi.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Error = error{
    EntryNotFound,
    Unsupported,
    NoStorageAccess,
    AuthenticationFailed,
    NetworkFailure,
    CacheFailure,
    OutOfMemory,
    InvalidUtf8,
};

pub const Credential = struct {
    username: []const u8,
    password: []u8,
};

const client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
const scope = "499b84ac-1321-427f-aa17-267ca6975798/.default offline_access";
const auth_url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize";
const token_url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token";
const log_prefix = "[keyring ado]";
const session_username = "VssSessionToken";
// Legacy cleartext cache (issue #14). Read only for one-time migration into the
// user-protected `refresh.dat`/`session.dat` layout (issue #18) and then deleted.
const cache_dir_name = ".ado-keyring";
const cache_file_name = "token-cache.json";
const session_file_name = "session-cache.json";
// User-protected cache (issue #18), under `${cache_root}/keyring/`. See
// `cacheRoot` for how `cache_root` resolves per platform.
//   refresh.dat — OAuth refresh/access token + expiry (Linux only; on Windows /
//                 macOS the refresh token lives in the platform secret store).
//   session.dat — per-org session tokens; DPAPI-encrypted on Windows, 0600 on Unix.
//   .lock       — empty file held with an exclusive OS lock around each
//                 read-modify-write so concurrent writers do not lose updates.
const keyring_subdir = "keyring";
const refresh_dat_name = "refresh.dat";
const session_dat_name = "session.dat";
const lock_file_name = ".lock";
// Windows Credential Manager target. Using the bare service name as the target
// makes the entry inspectable via `cmdkey /list:ado-keyring` and removable via
// `cmdkey /delete:ado-keyring`.
const wcm_service = "ado-keyring";
const wcm_key = "refresh-token";
const noninteractive_env = "ADO_KEYRING_NONINTERACTIVE";
// Opt-out (mirrors artifacts-credprovider's
// ARTIFACTS_CREDENTIALPROVIDER_SESSIONTOKENCACHE_ENABLED): when set to a falsey
// value the backend keeps no persistent cache at all — neither the platform
// secret store nor the `.dat` files — so every process re-authenticates.
const disk_cache_env = "KEYRING_ADO_DISK_CACHE";

const TokenResponse = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    expires_in: i64 = 3600,
};

const SessionTokenResponse = struct {
    token: []const u8,
};

const CacheSessionToken = struct {
    token: []const u8,
    expires_at: i64,
};

const Cache = struct {
    access_token: ?[]const u8 = null,
    refresh_token: ?[]const u8 = null,
    expires_at: i64 = 0,
    session_tokens: std.json.ArrayHashMap(CacheSessionToken) = .{},
};

/// The long-lived portion of the cache persisted in the Windows Credential
/// Manager (issue #15) / macOS Keychain (issue #16). Only the OAuth refresh
/// token is stored: the matching access token is short-lived (~1 hour) and
/// trivially re-derived from the refresh token, and including it pushes the
/// credential blob past `CRED_MAX_CREDENTIAL_BLOB_SIZE` (5*512 bytes), making
/// `CredWriteW` fail. Per-org session tokens are kept separately in `session.dat`.
const LongLived = struct {
    refresh_token: ?[]const u8 = null,
};

/// The long-lived cache persisted in `refresh.dat` on Linux (issue #18). Unlike
/// the secret-store blob, the access token is included so a fresh process can
/// reuse a still-valid one without a refresh round-trip. The file is mode 0600.
const RefreshCache = struct {
    access_token: ?[]const u8 = null,
    refresh_token: ?[]const u8 = null,
    expires_at: i64 = 0,
};

/// The per-org session tokens persisted in `session.dat` on all platforms
/// (issue #18). DPAPI-encrypted on Windows, mode 0600 on Unix.
const SessionCache = struct {
    session_tokens: std.json.ArrayHashMap(CacheSessionToken) = .{},
};

/// An owned, mutable cache backed by a private arena so callers do not need to
/// juggle multiple JSON parse handles across the Windows/non-Windows split.
const LoadedCache = struct {
    arena: *std.heap.ArenaAllocator,
    cache: Cache,

    fn deinit(self: *LoadedCache, gpa: Allocator) void {
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

pub fn getCredential(gpa: Allocator, stderr: *Io.Writer, service_url: []const u8) Error!Credential {
    if (!isDevOpsUrl(service_url)) return error.EntryNotFound;

    const org = extractOrg(service_url) orelse return error.Unsupported;
    const now = unixNow();

    var loaded = loadCache(gpa);
    defer loaded.deinit(gpa);
    var cache: Cache = loaded.cache;

    if (cache.session_tokens.map.get(org)) |session| {
        if (session.expires_at > now + 300) {
            log(stderr, "{s} Using cached session token for '{s}'\n", .{ log_prefix, org });
            return .{ .username = session_username, .password = try gpa.dupe(u8, session.token) };
        }
    }

    var token_parsed: ?std.json.Parsed(TokenResponse) = null;
    defer if (token_parsed) |*parsed| parsed.deinit();

    // Tracks whether the access token we are about to use was just obtained via a
    // fresh refresh/browser auth in this invocation (as opposed to loaded from the
    // on-disk cache). A cached token may have been revoked or invalidated by clock
    // skew even though its recorded expiry has not yet passed.
    var fresh_auth = false;

    if (cache.access_token == null or cache.expires_at <= now + 60) {
        token_parsed = try acquireAccessToken(gpa, stderr, cache.refresh_token);
        fresh_auth = true;
        if (token_parsed) |parsed| {
            cache.access_token = parsed.value.access_token;
            cache.refresh_token = parsed.value.refresh_token;
            cache.expires_at = now + parsed.value.expires_in;
        }
    }

    var access_token = cache.access_token orelse return error.AuthenticationFailed;
    log(stderr, "{s} Exchanging for VssSessionToken ({s})...\n", .{ log_prefix, org });

    var retry_parsed: ?std.json.Parsed(TokenResponse) = null;
    defer if (retry_parsed) |*parsed| parsed.deinit();

    var session_parsed = getSessionToken(gpa, access_token, org) catch |err| reauth: {
        // The cached access token was rejected by Azure DevOps. Re-authenticate
        // (refresh first, then browser) and retry the exchange once. If the access
        // token was already freshly acquired in this call, the failure is real.
        if (fresh_auth) return err;
        log(stderr, "{s} Cached credentials rejected, re-authenticating...\n", .{log_prefix});
        retry_parsed = try acquireAccessToken(gpa, stderr, cache.refresh_token);
        if (retry_parsed) |parsed| {
            cache.access_token = parsed.value.access_token;
            cache.refresh_token = parsed.value.refresh_token;
            cache.expires_at = now + parsed.value.expires_in;
        }
        access_token = cache.access_token orelse return error.AuthenticationFailed;
        break :reauth try getSessionToken(gpa, access_token, org);
    };
    defer session_parsed.deinit();

    const token = session_parsed.value.token;
    const owned_token = try gpa.dupe(u8, token);
    errdefer gpa.free(owned_token);

    try saveCache(gpa, &cache, org, owned_token, now + 3000);

    log(stderr, "{s} Authenticated to '{s}'\n", .{ log_prefix, org });
    return .{ .username = session_username, .password = owned_token };
}

/// Obtain a fresh Entra access token, preferring a silent refresh-token grant,
/// then a refresh token inherited from the shared MSAL cache (az login SSO),
/// and finally falling back to interactive browser auth. Used both for the
/// initial acquisition and to recover when a cached access token is rejected
/// by Azure DevOps.
fn acquireAccessToken(gpa: Allocator, stderr: *Io.Writer, refresh_token: ?[]const u8) Error!std.json.Parsed(TokenResponse) {
    if (refresh_token) |rt| {
        log(stderr, "{s} Refreshing access token...\n", .{log_prefix});
        if (refreshAccessToken(gpa, rt)) |parsed| {
            return parsed;
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => log(stderr, "{s} Refresh failed ({s}), trying MSAL cache / browser\n", .{ log_prefix, @errorName(err) }),
        }
    }

    // Read-only SSO with az login and friends: redeem a Family Refresh Token
    // from the shared MSAL cache using our own client id (issue #19).
    if (tryMsalAuth(gpa, stderr)) |parsed| return parsed;

    if (isNonInteractive()) return error.NoStorageAccess;
    log(stderr, "{s} No cached token, starting browser auth...\n", .{log_prefix});
    return browserAuth(gpa, stderr);
}

/// Attempt to redeem a FOCI refresh token from the shared MSAL cache. Returns
/// null on any failure so the caller can fall through to browser auth. The
/// MSAL cache is never written back to.
fn tryMsalAuth(gpa: Allocator, stderr: *Io.Writer) ?std.json.Parsed(TokenResponse) {
    const candidate = msal_cache.findFociRefreshToken(gpa) orelse return null;
    log(stderr, "{s} Trying refresh token from MSAL cache (az login SSO)...\n", .{log_prefix});
    return refreshAccessToken(gpa, candidate.secret) catch |err| {
        log(stderr, "{s} MSAL cache refresh failed ({s})\n", .{ log_prefix, @errorName(err) });
        return null;
    };
}

pub fn getPassword(gpa: Allocator, stderr: *Io.Writer, service_url: []const u8, username: []const u8) Error![]u8 {
    const credential = try getCredential(gpa, stderr, service_url);
    if (username.len != 0 and !std.mem.eql(u8, username, credential.username)) {
        gpa.free(credential.password);
        return error.EntryNotFound;
    }
    return credential.password;
}

pub fn setPassword(_: Allocator, _: []const u8, _: []const u8, _: []const u8) Error!void {
    return error.Unsupported;
}

pub fn deletePassword(gpa: Allocator) Error!void {
    var removed = false;
    if (builtin.os.tag == .windows) {
        if (wincred.delete(gpa, wcm_service)) {
            removed = true;
        } else |err| switch (err) {
            error.EntryNotFound => {},
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.CacheFailure,
        }
    } else if (builtin.os.tag == .macos) {
        if (keychain.delete(wcm_service, wcm_key)) {
            removed = true;
        } else |err| switch (err) {
            error.EntryNotFound => {},
            error.NoStorageAccess => return error.NoStorageAccess,
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.CacheFailure,
        }
    }
    if (deleteAllCacheFiles(gpa)) removed = true;
    return if (removed) {} else error.EntryNotFound;
}

/// Remove every cache file we may have written: the user-protected `.dat` files
/// plus any legacy cleartext files left from before issue #18. Returns true if
/// at least one file was removed.
fn deleteAllCacheFiles(gpa: Allocator) bool {
    var removed = false;
    if (deleteDatFile(gpa, session_dat_name)) removed = true;
    if (deleteDatFile(gpa, refresh_dat_name)) removed = true;
    if (deleteLegacyFile(gpa, session_file_name)) removed = true;
    if (deleteLegacyFile(gpa, cache_file_name)) removed = true;
    return removed;
}

/// Delete a `.dat` file under the keyring cache directory. Returns true if a
/// file was removed, false if it was already absent.
fn deleteDatFile(gpa: Allocator, name: []const u8) bool {
    const io = ioGlobal();
    const path = datFilePath(gpa, name) catch return false;
    defer gpa.free(path);
    std.Io.Dir.cwd().deleteFile(io, path) catch return false;
    return true;
}

/// Delete a legacy cleartext file under `~/.ado-keyring/`. Returns true if a
/// file was removed, false if it was already absent.
fn deleteLegacyFile(gpa: Allocator, name: []const u8) bool {
    const io = ioGlobal();
    const path = legacyFilePath(gpa, name) catch return false;
    defer gpa.free(path);
    std.Io.Dir.cwd().deleteFile(io, path) catch return false;
    return true;
}

pub fn isDevOpsUrl(url: []const u8) bool {
    return std.mem.indexOf(u8, url, "visualstudio.com") != null or
        std.mem.indexOf(u8, url, "dev.azure.com") != null or
        std.mem.indexOf(u8, url, "pkgs.codedev.ms") != null or
        std.mem.indexOf(u8, url, "pkgs.vsts.me") != null;
}

pub fn extractOrg(service_url: []const u8) ?[]const u8 {
    // Slice the host and path directly out of `service_url` rather than going
    // through std.Uri.getHost, which copies the host into a caller-provided
    // stack buffer. Returning a slice into such a buffer yields a dangling
    // pointer once this function returns and the stack frame is reused (e.g. by
    // a subsequent loadCache JSON parse), corrupting the org name. All slices
    // returned here point into `service_url`, which outlives the call.
    const scheme_sep = std.mem.indexOf(u8, service_url, "://") orelse return null;
    const after_scheme = service_url[scheme_sep + 3 ..];

    var host_end: usize = after_scheme.len;
    for (after_scheme, 0..) |c, i| {
        if (c == '/' or c == '?' or c == '#') {
            host_end = i;
            break;
        }
    }

    var host = after_scheme[0..host_end];
    if (std.mem.lastIndexOfScalar(u8, host, '@')) |at| host = host[at + 1 ..];
    if (std.mem.indexOfScalar(u8, host, ':')) |colon| host = host[0..colon];

    if (std.mem.endsWith(u8, host, "visualstudio.com") or
        std.mem.endsWith(u8, host, "vsts.me") or
        std.mem.endsWith(u8, host, "codedev.ms"))
    {
        const dot = std.mem.indexOfScalar(u8, host, '.') orelse return null;
        return if (dot == 0) null else host[0..dot];
    }

    if (std.mem.indexOf(u8, host, "dev.azure.com") != null) {
        const path = after_scheme[host_end..];
        var start: usize = 0;
        while (start < path.len and path[start] == '/') start += 1;
        if (start >= path.len) return null;
        var end = start;
        while (end < path.len and (path[end] != '/' and path[end] != '?' and path[end] != '#')) end += 1;
        return if (end == start) null else path[start..end];
    }

    return null;
}

pub fn generatePkce(verifier_out: *[43]u8, challenge_out: *[43]u8) void {
    var random_bytes: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&random_bytes);
    _ = std.base64.url_safe_no_pad.Encoder.encode(verifier_out, &random_bytes);

    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier_out, &digest, .{});
    _ = std.base64.url_safe_no_pad.Encoder.encode(challenge_out, &digest);
}

fn browserAuth(gpa: Allocator, stderr: *Io.Writer) Error!std.json.Parsed(TokenResponse) {
    if (isNonInteractive()) return error.NoStorageAccess;

    var verifier: [43]u8 = undefined;
    var challenge: [43]u8 = undefined;
    generatePkce(&verifier, &challenge);
    const state = try randomUrlToken(gpa, 16);
    defer gpa.free(state);

    const io = std.Io.Threaded.global_single_threaded.io();
    var address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(0) };
    var server = std.Io.net.IpAddress.listen(&address, io, .{ .reuse_address = true }) catch return error.NoStorageAccess;
    defer server.deinit(io);

    const bound_port = server.socket.address.getPort();
    // Use "localhost" rather than "127.0.0.1": Entra ID treats http://localhost
    // as a special loopback redirect (any port allowed) for public clients,
    // matching what the Azure CLI app registration accepts. http://127.0.0.1
    // requires an exact-match registered redirect URI and fails with
    // AADSTS50011 for the Azure CLI client id we use.
    const redirect_uri = try std.fmt.allocPrint(gpa, "http://localhost:{d}", .{bound_port});
    defer gpa.free(redirect_uri);

    const url = try buildAuthorizeUrl(gpa, redirect_uri, &challenge, state);
    defer gpa.free(url);

    log(stderr, "{s} Opening browser for Azure DevOps authentication...\n", .{log_prefix});
    log(stderr, "{s} If the browser does not open, visit:\n{s}\n", .{ log_prefix, url });
    try openBrowser(gpa, stderr, url);

    var stream = server.accept(io) catch return error.AuthenticationFailed;
    defer stream.socket.close(io);

    var read_buffer: [8192]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    const request = reader.interface.takeDelimiterExclusive('\n') catch return error.AuthenticationFailed;
    const path = parseRequestPath(request) orelse return error.AuthenticationFailed;
    const code = try parseOAuthCallback(gpa, path, state);
    defer gpa.free(code);
    try sendHtml(io, stream, success_html);

    return exchangeCode(gpa, code, redirect_uri, &verifier);
}

fn refreshAccessToken(gpa: Allocator, refresh_token: []const u8) Error!std.json.Parsed(TokenResponse) {
    var body = std.Io.Writer.Allocating.init(gpa);
    defer body.deinit();
    try formField(&body.writer, "client_id", client_id, true);
    try formField(&body.writer, "grant_type", "refresh_token", false);
    try formField(&body.writer, "refresh_token", refresh_token, false);
    try formField(&body.writer, "scope", scope, false);
    return postJson(TokenResponse, gpa, token_url, body.written(), "application/x-www-form-urlencoded", &.{});
}

fn exchangeCode(gpa: Allocator, code: []const u8, redirect_uri: []const u8, verifier: []const u8) Error!std.json.Parsed(TokenResponse) {
    var body = std.Io.Writer.Allocating.init(gpa);
    defer body.deinit();
    try formField(&body.writer, "client_id", client_id, true);
    try formField(&body.writer, "grant_type", "authorization_code", false);
    try formField(&body.writer, "code", code, false);
    try formField(&body.writer, "redirect_uri", redirect_uri, false);
    try formField(&body.writer, "code_verifier", verifier, false);
    return postJson(TokenResponse, gpa, token_url, body.written(), "application/x-www-form-urlencoded", &.{});
}

fn getSessionToken(gpa: Allocator, access_token: []const u8, org: []const u8) Error!std.json.Parsed(SessionTokenResponse) {
    const url = try std.fmt.allocPrint(gpa, "https://vssps.dev.azure.com/{s}/_apis/token/sessiontokens?api-version=5.0-preview.1", .{org});
    defer gpa.free(url);
    const auth = try std.fmt.allocPrint(gpa, "Bearer {s}", .{access_token});
    defer gpa.free(auth);
    const body = "{\"scope\":\"vso.packaging\",\"targetAccounts\":[]}";
    return postJson(SessionTokenResponse, gpa, url, body, "application/json", &.{
        .{ .name = "authorization", .value = auth },
    });
}

fn postJson(comptime T: type, gpa: Allocator, url: []const u8, body: []const u8, content_type: []const u8, extra_headers: []const std.http.Header) Error!std.json.Parsed(T) {
    var response = std.Io.Writer.Allocating.init(gpa);
    defer response.deinit();

    var client: std.http.Client = .{
        .allocator = gpa,
        .io = std.Io.Threaded.global_single_threaded.io(),
    };
    defer client.deinit();

    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .payload = body,
        .headers = .{ .content_type = .{ .override = content_type } },
        .extra_headers = extra_headers,
        .response_writer = &response.writer,
    }) catch return error.NetworkFailure;

    if (result.status.class() != .success) return error.AuthenticationFailed;
    return std.json.parseFromSlice(T, gpa, response.written(), .{ .ignore_unknown_fields = true }) catch return error.AuthenticationFailed;
}

fn formField(writer: *Io.Writer, key: []const u8, value: []const u8, first: bool) Error!void {
    if (!first) writer.writeByte('&') catch return error.NetworkFailure;
    try percentEncodeForm(writer, key);
    writer.writeByte('=') catch return error.NetworkFailure;
    try percentEncodeForm(writer, value);
}

fn percentEncodeForm(writer: *Io.Writer, value: []const u8) Error!void {
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

fn buildAuthorizeUrl(gpa: Allocator, redirect_uri: []const u8, challenge: []const u8, state: []const u8) Error![]u8 {
    var query = std.Io.Writer.Allocating.init(gpa);
    defer query.deinit();
    try formField(&query.writer, "client_id", client_id, true);
    try formField(&query.writer, "response_type", "code", false);
    try formField(&query.writer, "redirect_uri", redirect_uri, false);
    try formField(&query.writer, "scope", scope, false);
    try formField(&query.writer, "code_challenge", challenge, false);
    try formField(&query.writer, "code_challenge_method", "S256", false);
    try formField(&query.writer, "state", state, false);
    try formField(&query.writer, "prompt", "select_account", false);
    return std.fmt.allocPrint(gpa, "{s}?{s}", .{ auth_url, query.written() });
}

fn parseRequestPath(request_line: []const u8) ?[]const u8 {
    const trimmed = std.mem.trimEnd(u8, request_line, "\r");
    if (!std.mem.startsWith(u8, trimmed, "GET ")) return null;
    const rest = trimmed[4..];
    const end = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
    return rest[0..end];
}

fn parseOAuthCallback(gpa: Allocator, path: []const u8, expected_state: []const u8) Error![]u8 {
    const query_start = std.mem.indexOfScalar(u8, path, '?') orelse return error.AuthenticationFailed;
    var code: ?[]u8 = null;
    var state_ok = false;

    var it = std.mem.splitScalar(u8, path[query_start + 1 ..], '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const value = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "error")) return error.AuthenticationFailed;
        if (std.mem.eql(u8, key, "code")) {
            code = try percentDecode(gpa, value);
        } else if (std.mem.eql(u8, key, "state")) {
            const decoded = try percentDecode(gpa, value);
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

fn percentDecode(gpa: Allocator, value: []const u8) Error![]u8 {
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

fn sendHtml(io: Io, stream: std.Io.net.Stream, html: []const u8) Error!void {
    var write_buffer: [1024]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    writer.interface.print(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ html.len, html },
    ) catch return error.NetworkFailure;
    writer.interface.flush() catch return error.NetworkFailure;
}

fn openBrowser(gpa: Allocator, stderr: *Io.Writer, url: []const u8) Error!void {
    if (builtin.os.tag == .windows) {
        // Call ShellExecuteW("open", url, ...) directly. Going through a shell
        // (cmd /c start, powershell Start-Process) truncates the URL at the
        // first `&` (cmd command separator / PowerShell call operator).
        // Spawning rundll32 with url.dll's FileProtocolHandler from a hidden
        // console exits 0 but never actually launches the browser. ShellExecuteW
        // is the Win32 primitive every other launcher ultimately calls.
        if (shellExecuteOpen(gpa, url)) return;
        log(stderr, "{s} ShellExecuteW failed to open browser\n", .{log_prefix});
        return error.NoStorageAccess;
    }
    // global_single_threaded uses a failing allocator, which makes
    // std.process.spawn return OutOfMemory. Initialize our own Threaded
    // instance backed by `gpa` for process spawning.
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const attempts = browserAttempts();
    for (attempts) |argv_prefix| {
        const argv = try appendUrlArg(gpa, argv_prefix, url);
        defer gpa.free(argv);
        var child = std.process.spawn(io, .{
            .argv = argv,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch |err| {
            log(stderr, "{s} browser spawn '{s}' failed: {s}\n", .{ log_prefix, argv[0], @errorName(err) });
            continue;
        };
        const term = child.wait(io) catch |err| {
            log(stderr, "{s} browser wait '{s}' failed: {s}\n", .{ log_prefix, argv[0], @errorName(err) });
            continue;
        };
        if (term == .exited and term.exited == 0) return;
        log(stderr, "{s} browser command '{s}' exited non-zero: {any}\n", .{ log_prefix, argv[0], term });
    }
    return error.NoStorageAccess;
}

const SW_SHOWNORMAL: i32 = 1;

extern "shell32" fn ShellExecuteW(
    hwnd: ?*anyopaque,
    lpOperation: ?[*:0]const u16,
    lpFile: ?[*:0]const u16,
    lpParameters: ?[*:0]const u16,
    lpDirectory: ?[*:0]const u16,
    nShowCmd: i32,
) callconv(.winapi) ?*anyopaque;

fn shellExecuteOpen(gpa: Allocator, url: []const u8) bool {
    const op = std.unicode.utf8ToUtf16LeAllocZ(gpa, "open") catch return false;
    defer gpa.free(op);
    const file = std.unicode.utf8ToUtf16LeAllocZ(gpa, url) catch return false;
    defer gpa.free(file);
    const result = ShellExecuteW(null, op.ptr, file.ptr, null, null, SW_SHOWNORMAL);
    // ShellExecuteW returns an HINSTANCE cast to a pointer. Per MSDN, values
    // <= 32 are error codes; success returns a value > 32.
    const code: usize = @intFromPtr(result);
    return code > 32;
}

fn browserAttempts() []const []const []const u8 {
    if (builtin.os.tag == .macos) {
        return &.{&.{"open"}};
    }
    if (isWsl()) {
        return &.{
            &.{ "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "-NoProfile", "-Command", "Start-Process" },
            &.{ "/mnt/c/Windows/system32/cmd.exe", "/c", "start", "" },
            &.{"xdg-open"},
        };
    }
    return &.{&.{"xdg-open"}};
}

fn appendUrlArg(gpa: Allocator, prefix: []const []const u8, url: []const u8) Error![]const []const u8 {
    var argv = try gpa.alloc([]const u8, prefix.len + 1);
    @memcpy(argv[0..prefix.len], prefix);
    argv[prefix.len] = url;
    return argv;
}

fn isWsl() bool {
    if (builtin.os.tag != .linux) return false;
    const io = std.Io.Threaded.global_single_threaded.io();
    const contents = std.Io.Dir.cwd().readFileAlloc(io, "/proc/version", std.heap.page_allocator, .limited(4096)) catch return false;
    defer std.heap.page_allocator.free(contents);
    _ = std.ascii.lowerString(contents, contents);
    return std.mem.indexOf(u8, contents, "microsoft") != null;
}

fn randomUrlToken(gpa: Allocator, byte_len: usize) Error![]u8 {
    const bytes = try gpa.alloc(u8, byte_len);
    defer gpa.free(bytes);
    std.Io.Threaded.global_single_threaded.io().random(bytes);
    const out = try gpa.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(byte_len));
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, bytes);
    return out;
}

fn ioGlobal() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

/// Whether the persistent cache is disabled via `KEYRING_ADO_DISK_CACHE`. When
/// disabled the backend keeps nothing on disk or in the secret store, so each
/// process re-authenticates from scratch.
fn diskCacheDisabled() bool {
    const value = getEnvVarOwned(std.heap.page_allocator, disk_cache_env) orelse return false;
    defer std.heap.page_allocator.free(value);
    return std.ascii.eqlIgnoreCase(value, "false") or
        std.mem.eql(u8, value, "0") or
        std.ascii.eqlIgnoreCase(value, "no");
}

/// Load the long-lived tokens and per-org session tokens into an owned cache.
/// The refresh token lives in the platform secret store on Windows (issue #15)
/// and macOS (issue #16) and in `refresh.dat` on Linux; per-org session tokens
/// always live in `session.dat`. Never errors — a missing, corrupt, or disabled
/// cache yields an empty one.
fn loadCache(gpa: Allocator) LoadedCache {
    const arena = gpa.create(std.heap.ArenaAllocator) catch
        return .{ .arena = emptyArena(gpa), .cache = .{} };
    arena.* = .init(gpa);
    const a = arena.allocator();
    var cache: Cache = .{};
    if (diskCacheDisabled()) return .{ .arena = arena, .cache = cache };

    migrateLegacyIfNeeded(a, &cache);

    switch (builtin.os.tag) {
        .windows => loadRefreshSecretStore(a, &cache, .windows),
        .macos => loadRefreshSecretStore(a, &cache, .macos),
        else => loadRefreshDat(a, &cache),
    }
    loadSessionDat(a, &cache);
    return .{ .arena = arena, .cache = cache };
}

fn emptyArena(gpa: Allocator) *std.heap.ArenaAllocator {
    const arena = gpa.create(std.heap.ArenaAllocator) catch unreachable;
    arena.* = .init(gpa);
    return arena;
}

/// Read the refresh token from the platform secret store (Windows Credential
/// Manager / macOS Keychain). The access token is intentionally not persisted
/// there (see `LongLived`); it stays in memory for the lifetime of this process.
fn loadRefreshSecretStore(a: Allocator, cache: *Cache, comptime os: std.Target.Os.Tag) void {
    const blob = switch (os) {
        .windows => wincred.get(a, wcm_service) catch return,
        .macos => keychain.get(a, wcm_service, wcm_key) catch return,
        else => return,
    };
    if (std.json.parseFromSliceLeaky(LongLived, a, blob, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    })) |ll| {
        cache.refresh_token = ll.refresh_token;
    } else |_| {}
}

/// Read `refresh.dat` (Linux) into `cache`. A missing or corrupt file leaves the
/// cache empty so the caller re-authenticates instead of crashing.
fn loadRefreshDat(a: Allocator, cache: *Cache) void {
    const json = readDatFile(a, refresh_dat_name) orelse return;
    defer a.free(json);
    const parsed = std.json.parseFromSliceLeaky(RefreshCache, a, json, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return;
    cache.access_token = parsed.access_token;
    cache.refresh_token = parsed.refresh_token;
    cache.expires_at = parsed.expires_at;
}

/// Read `session.dat` (all platforms) into `cache.session_tokens`. A missing or
/// corrupt file leaves the session map empty.
fn loadSessionDat(a: Allocator, cache: *Cache) void {
    const json = readDatFile(a, session_dat_name) orelse return;
    defer a.free(json);
    const parsed = std.json.parseFromSliceLeaky(SessionCache, a, json, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return;
    cache.session_tokens = parsed.session_tokens;
}

/// Read and unprotect a `.dat` file, returning its plaintext JSON bytes owned by
/// `a`, or null if the file is absent or fails to decrypt (a corrupt cache,
/// which the caller treats as empty and rewrites from scratch).
fn readDatFile(a: Allocator, name: []const u8) ?[]u8 {
    const io = ioGlobal();
    const path = datFilePath(a, name) catch return null;
    defer a.free(path);
    const raw = std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(1024 * 1024)) catch return null;
    defer a.free(raw);
    return unprotectBytes(a, raw);
}

/// One-time migration from the legacy cleartext layout (issue #14) to the
/// user-protected `.dat` files (issue #18). Runs only when `session.dat` does
/// not yet exist; once a successful migration creates it, this is a no-op
/// forever. The legacy refresh token is moved to the secret store
/// (Windows/macOS) or `refresh.dat` (Linux) and the legacy session tokens to
/// `session.dat`.
///
/// The legacy tokens are also seeded into `cache` so the current process keeps
/// working even if a destination write fails (matching the pre-#18 in-memory
/// fallback); `loadCache` only overwrites them when the destination actually
/// holds data. Legacy files are deleted **only after** every destination write
/// succeeds, so a transient failure (e.g. a locked Keychain) leaves the cleartext
/// cache in place to be retried on the next run rather than losing the token.
fn migrateLegacyIfNeeded(a: Allocator, cache: *Cache) void {
    if (datExists(a, session_dat_name)) return;

    var legacy: Cache = .{};
    const had_json = loadLegacyInto(a, cache_file_name, &legacy);
    const had_session = loadLegacyInto(a, session_file_name, &legacy);
    if (!had_json and !had_session) return;

    // In-memory fallback for this process. Overwritten by loadCache's reads when
    // the destination write below succeeded; preserved when it failed.
    cache.access_token = legacy.access_token;
    cache.refresh_token = legacy.refresh_token;
    cache.expires_at = legacy.expires_at;
    cache.session_tokens = legacy.session_tokens;

    // Persist the refresh token first; if it cannot be saved, abort without
    // creating session.dat or deleting anything so a later run retries.
    if (legacy.refresh_token != null or legacy.access_token != null) {
        const saved = switch (builtin.os.tag) {
            .windows => saveLongLivedWindows(a, &legacy),
            .macos => saveLongLivedMacos(a, &legacy),
            else => saveRefreshDat(a, &legacy),
        };
        saved catch return;
    }

    // Persist the session tokens; abort before deleting if this fails.
    migrateSessions(a, &legacy) catch return;

    _ = deleteLegacyFile(a, cache_file_name);
    _ = deleteLegacyFile(a, session_file_name);
}

/// Parse a legacy cleartext JSON file under `~/.ado-keyring/` and merge it into
/// `cache`. Session tokens always replace those in `cache`; the long-lived
/// tokens are only copied when present, so reading the session-only legacy file
/// does not clobber a refresh token read from `token-cache.json`. Returns true
/// if the file existed and parsed. Strings are owned by `a`.
fn loadLegacyInto(a: Allocator, name: []const u8, cache: *Cache) bool {
    const io = ioGlobal();
    const path = legacyFilePath(a, name) catch return false;
    defer a.free(path);
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(1024 * 1024)) catch return false;
    defer a.free(bytes);
    // .alloc_always so parsed strings are copied into `a` and survive `bytes`
    // being freed. The default slices unescaped strings out of `bytes`, which
    // would dangle once this function returns.
    const parsed = std.json.parseFromSliceLeaky(Cache, a, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return false;

    cache.session_tokens = parsed.session_tokens;
    if (parsed.access_token != null or parsed.refresh_token != null) {
        cache.access_token = parsed.access_token;
        cache.refresh_token = parsed.refresh_token;
        cache.expires_at = parsed.expires_at;
    }
    return true;
}

fn datExists(a: Allocator, name: []const u8) bool {
    const path = datFilePath(a, name) catch return false;
    defer a.free(path);
    std.Io.Dir.cwd().access(ioGlobal(), path, .{}) catch return false;
    return true;
}

fn saveCache(gpa: Allocator, cache: *const Cache, org: []const u8, token: []const u8, expires_at: i64) Error!void {
    if (diskCacheDisabled()) return;
    switch (builtin.os.tag) {
        .windows => try saveLongLivedWindows(gpa, cache),
        .macos => try saveLongLivedMacos(gpa, cache),
        else => try saveRefreshDat(gpa, cache),
    }
    return saveSessionDat(gpa, org, token, expires_at);
}

/// Persist the long-lived tokens into the Windows Credential Manager.
fn saveLongLivedWindows(gpa: Allocator, cache: *const Cache) Error!void {
    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    try writeLongLivedJson(&out.writer, cache);
    wincred.set(gpa, wcm_service, wcm_key, out.written()) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.CacheFailure,
    };
}

/// Persist the long-lived tokens into the macOS Keychain.
fn saveLongLivedMacos(gpa: Allocator, cache: *const Cache) Error!void {
    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    try writeLongLivedJson(&out.writer, cache);
    keychain.set(wcm_service, wcm_key, out.written()) catch |err| switch (err) {
        error.NoStorageAccess => return error.NoStorageAccess,
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.CacheFailure,
    };
}

fn writeLongLivedJson(writer: *Io.Writer, cache: *const Cache) Error!void {
    writer.writeAll("{\"refresh_token\":") catch return error.CacheFailure;
    try writeJsonOptionalString(writer, cache.refresh_token);
    writer.writeAll("}") catch return error.CacheFailure;
}

/// Persist the long-lived tokens into `refresh.dat` (Linux), under an exclusive
/// cross-process lock. Includes the access token so a fresh process can reuse a
/// still-valid one without a refresh round-trip.
fn saveRefreshDat(gpa: Allocator, cache: *const Cache) Error!void {
    var lock = acquireCacheLock(gpa);
    defer lock.release();

    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    out.writer.writeAll("{\n  \"access_token\": ") catch return error.CacheFailure;
    try writeJsonOptionalString(&out.writer, cache.access_token);
    out.writer.writeAll(",\n  \"refresh_token\": ") catch return error.CacheFailure;
    try writeJsonOptionalString(&out.writer, cache.refresh_token);
    out.writer.print(",\n  \"expires_at\": {d}\n}}\n", .{cache.expires_at}) catch return error.CacheFailure;

    try writeProtectedDat(gpa, refresh_dat_name, out.written());
}

/// Persist the per-org session tokens into `session.dat` (all platforms). Holds
/// an exclusive cross-process lock for the whole read-modify-write so concurrent
/// writers minting tokens for different orgs do not lose each other's entries:
/// the current on-disk map is re-read under the lock and the new `org`/`token`
/// entry merged into it before the atomic rewrite.
fn saveSessionDat(gpa: Allocator, org: ?[]const u8, token: ?[]const u8, expires_at: i64) Error!void {
    var lock = acquireCacheLock(gpa);
    defer lock.release();

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var disk: Cache = .{};
    loadSessionDat(arena.allocator(), &disk);

    return writeSessionDatUnlocked(gpa, &disk, org, token, expires_at);
}

/// One-time migration of the legacy session tokens into `session.dat`, under the
/// cross-process lock. To stay safe inside the first-run window where two
/// processes can both observe `session.dat` absent, this re-reads the current
/// on-disk map under the lock and only adds legacy entries for orgs not already
/// present, so it never clobbers a token another process just wrote.
fn migrateSessions(gpa: Allocator, legacy: *const Cache) Error!void {
    var lock = acquireCacheLock(gpa);
    defer lock.release();

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var disk: Cache = .{};
    loadSessionDat(a, &disk);

    var it = legacy.session_tokens.map.iterator();
    while (it.next()) |entry| {
        if (disk.session_tokens.map.contains(entry.key_ptr.*)) continue;
        disk.session_tokens.map.put(a, entry.key_ptr.*, entry.value_ptr.*) catch return error.CacheFailure;
    }
    return writeSessionDatUnlocked(gpa, &disk, null, null, 0);
}

/// Serialize `base`'s session map plus an optional new `org`/`token` entry and
/// write it to `session.dat`. The caller must already hold the cache lock.
fn writeSessionDatUnlocked(gpa: Allocator, base: *const Cache, org: ?[]const u8, token: ?[]const u8, expires_at: i64) Error!void {
    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    out.writer.writeAll("{\n  \"session_tokens\": {") catch return error.CacheFailure;
    try writeSessionMap(&out.writer, base, org, token, expires_at);
    out.writer.writeAll("\n  }\n}\n") catch return error.CacheFailure;
    try writeProtectedDat(gpa, session_dat_name, out.written());
}

/// Protect `contents` (DPAPI on Windows, identity on Unix) and atomically write
/// it to the named `.dat` file in the keyring cache directory.
fn writeProtectedDat(gpa: Allocator, name: []const u8, contents: []const u8) Error!void {
    const protected = try protectBytes(gpa, contents);
    defer gpa.free(protected);
    const path = try datFilePath(gpa, name);
    defer gpa.free(path);
    try writeFileAtomic(gpa, path, protected);
}

/// Protect a plaintext byte slice for at-rest storage. DPAPI (current-user) on
/// Windows; an owned copy of the input on Unix, where mode 0600 is the only
/// protection (the design floor per issue #18). Caller owns the result.
fn protectBytes(gpa: Allocator, data: []const u8) Error![]u8 {
    if (builtin.os.tag == .windows) {
        return dpapi.protect(gpa, data) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.CacheFailure,
        };
    }
    return gpa.dupe(u8, data) catch error.OutOfMemory;
}

/// Reverse `protectBytes`. Returns null when the bytes cannot be decrypted
/// (a corrupt or foreign DPAPI blob), which the caller treats as an empty cache.
fn unprotectBytes(a: Allocator, data: []const u8) ?[]u8 {
    if (builtin.os.tag == .windows) {
        return dpapi.unprotect(a, data) catch return null;
    }
    return a.dupe(u8, data) catch null;
}

/// Atomically write `contents` to the absolute `path`, creating the parent
/// directory if needed. Uses a per-process random temp suffix + rename so
/// concurrent writers never observe a partial file.
fn writeFileAtomic(gpa: Allocator, path: []const u8, contents: []const u8) Error!void {
    const io = ioGlobal();
    const parent = std.fs.path.dirname(path) orelse return error.CacheFailure;
    _ = std.Io.Dir.cwd().createDirPathStatus(io, parent, cacheDirPermissions()) catch return error.CacheFailure;

    // Use a unique temp filename per write. uv (and other consumers) spawn many
    // keyring processes concurrently; a shared "{path}.tmp" name causes them to
    // race on the same file, producing a corrupt cache that fails to parse and
    // forces a re-authentication on every subsequent call. A per-process random
    // suffix keeps each writer's temp file private before the atomic rename.
    var suffix_bytes: [8]u8 = undefined;
    io.random(&suffix_bytes);
    const suffix_hex = std.fmt.bytesToHex(suffix_bytes, .lower);
    const tmp = try std.fmt.allocPrint(gpa, "{s}.{s}.tmp", .{ path, suffix_hex });
    defer gpa.free(tmp);
    {
        var file = std.Io.Dir.cwd().createFile(io, tmp, .{ .truncate = true, .permissions = cacheFilePermissions() }) catch return error.CacheFailure;
        defer file.close(io);
        file.writeStreamingAll(io, contents) catch return error.CacheFailure;
    }
    std.Io.Dir.renameAbsolute(tmp, path, io) catch return error.CacheFailure;
}

/// An exclusive cross-process lock over the cache directory, held for the
/// duration of a read-modify-write. `held` is false when locking was
/// unavailable, in which case callers proceed lock-free (the atomic rename still
/// prevents a torn file; only the lost-update guarantee is relaxed) rather than
/// failing authentication.
const CacheLock = struct {
    file: std.Io.File = undefined,
    held: bool = false,

    fn release(self: *CacheLock) void {
        if (!self.held) return;
        const io = ioGlobal();
        self.file.unlock(io);
        self.file.close(io);
        self.held = false;
    }
};

fn acquireCacheLock(gpa: Allocator) CacheLock {
    const io = ioGlobal();
    ensureKeyringDir(gpa) catch return .{};
    const path = datFilePath(gpa, lock_file_name) catch return .{};
    defer gpa.free(path);
    const file = std.Io.Dir.cwd().createFile(io, path, .{
        .truncate = false,
        .read = true,
        .permissions = cacheFilePermissions(),
    }) catch return .{};
    file.lock(io, .exclusive) catch {
        file.close(io);
        return .{};
    };
    return .{ .file = file, .held = true };
}

fn ensureKeyringDir(gpa: Allocator) Error!void {
    const dir = keyringDir(gpa) catch return error.CacheFailure;
    defer gpa.free(dir);
    _ = std.Io.Dir.cwd().createDirPathStatus(ioGlobal(), dir, cacheDirPermissions()) catch return error.CacheFailure;
}

fn cacheDirPermissions() std.Io.File.Permissions {
    return if (builtin.os.tag == .windows) .default_dir else .fromMode(0o700);
}

fn cacheFilePermissions() std.Io.File.Permissions {
    return if (builtin.os.tag == .windows) .default_file else .fromMode(0o600);
}

/// Write the body of the session_tokens object (without the enclosing braces).
/// Existing entries are emitted, skipping `org`, then a fresh `org` entry is
/// appended when `org`/`token` are provided.
fn writeSessionMap(writer: *Io.Writer, cache: *const Cache, org: ?[]const u8, token: ?[]const u8, expires_at: i64) Error!void {
    var first = true;
    var it = cache.session_tokens.map.iterator();
    while (it.next()) |entry| {
        if (org) |o| if (std.mem.eql(u8, entry.key_ptr.*, o)) continue;
        if (!first) writer.writeAll(",") catch return error.CacheFailure;
        first = false;
        writer.writeAll("\n    ") catch return error.CacheFailure;
        try writeJsonString(writer, entry.key_ptr.*);
        writer.print(": {{ \"token\": ", .{}) catch return error.CacheFailure;
        try writeJsonString(writer, entry.value_ptr.token);
        writer.print(", \"expires_at\": {d} }}", .{entry.value_ptr.expires_at}) catch return error.CacheFailure;
    }

    if (org) |o| if (token) |t| {
        if (!first) writer.writeAll(",") catch return error.CacheFailure;
        writer.writeAll("\n    ") catch return error.CacheFailure;
        try writeJsonString(writer, o);
        writer.writeAll(": { \"token\": ") catch return error.CacheFailure;
        try writeJsonString(writer, t);
        writer.print(", \"expires_at\": {d} }}", .{expires_at}) catch return error.CacheFailure;
    };
}

fn writeJsonOptionalString(writer: *Io.Writer, value: ?[]const u8) Error!void {
    if (value) |s| {
        try writeJsonString(writer, s);
    } else {
        writer.writeAll("null") catch return error.CacheFailure;
    }
}

fn writeJsonString(writer: *Io.Writer, value: []const u8) Error!void {
    writer.writeByte('"') catch return error.CacheFailure;
    for (value) |c| switch (c) {
        '\\' => writer.writeAll("\\\\") catch return error.CacheFailure,
        '"' => writer.writeAll("\\\"") catch return error.CacheFailure,
        '\n' => writer.writeAll("\\n") catch return error.CacheFailure,
        '\r' => writer.writeAll("\\r") catch return error.CacheFailure,
        '\t' => writer.writeAll("\\t") catch return error.CacheFailure,
        else => writer.writeByte(c) catch return error.CacheFailure,
    };
    writer.writeByte('"') catch return error.CacheFailure;
}

/// Resolve the platform cache root that holds the `keyring/` subdirectory
/// (issue #18). Honors `$XDG_DATA_HOME` (when absolute) on Linux/macOS.
///   Linux:   `$XDG_DATA_HOME`, else `~/.local/share`
///   macOS:   `$XDG_DATA_HOME`, else `~/Library/Application Support`
///   Windows: `%LocalAppData%`, else `%USERPROFILE%\AppData\Local`
fn cacheRoot(gpa: Allocator) ![]u8 {
    if (cache_root_override) |root| return gpa.dupe(u8, root);

    if (builtin.os.tag == .windows) {
        if (getEnvVarOwned(gpa, "LOCALAPPDATA")) |value| return value;
        if (getEnvVarOwned(gpa, "USERPROFILE")) |profile| {
            defer gpa.free(profile);
            return std.fs.path.join(gpa, &.{ profile, "AppData", "Local" }) catch return error.OutOfMemory;
        }
        return error.EnvironmentVariableNotFound;
    }

    if (getEnvVarOwned(gpa, "XDG_DATA_HOME")) |value| {
        // Per the XDG spec a relative path is invalid and must be ignored.
        if (value.len > 0 and value[0] == '/') return value;
        gpa.free(value);
    }
    const home = getEnvVarOwned(gpa, "HOME") orelse return error.EnvironmentVariableNotFound;
    defer gpa.free(home);
    if (builtin.os.tag == .macos) {
        return std.fs.path.join(gpa, &.{ home, "Library", "Application Support" }) catch return error.OutOfMemory;
    }
    return std.fs.path.join(gpa, &.{ home, ".local", "share" }) catch return error.OutOfMemory;
}

/// Test-only override for `cacheRoot`, letting unit tests redirect the cache to
/// a temporary directory without mutating process environment variables.
var cache_root_override: ?[]const u8 = null;

fn keyringDir(gpa: Allocator) Error![]u8 {
    const root = cacheRoot(gpa) catch return error.CacheFailure;
    defer gpa.free(root);
    return std.fs.path.join(gpa, &.{ root, keyring_subdir }) catch return error.OutOfMemory;
}

/// Absolute path to a `.dat` (or lock) file under `${cache_root}/keyring/`.
fn datFilePath(gpa: Allocator, name: []const u8) Error![]u8 {
    const dir = keyringDir(gpa) catch return error.CacheFailure;
    defer gpa.free(dir);
    return std.fs.path.join(gpa, &.{ dir, name }) catch return error.OutOfMemory;
}

/// Absolute path to a legacy cleartext file under `~/.ado-keyring/` (read only
/// during migration; see issue #18).
fn legacyFilePath(gpa: Allocator, name: []const u8) Error![]u8 {
    if (legacy_dir_override) |dir| {
        return std.fs.path.join(gpa, &.{ dir, name }) catch return error.OutOfMemory;
    }
    const home = getHome(gpa) catch return error.CacheFailure;
    defer gpa.free(home);
    return std.fs.path.join(gpa, &.{ home, cache_dir_name, name }) catch return error.OutOfMemory;
}

/// Test-only override for the legacy cleartext directory; see `cache_root_override`.
var legacy_dir_override: ?[]const u8 = null;

/// Print the ADO file-cache diagnostics for `keyring diagnose`: the resolved
/// cache directory, whether the disk cache is enabled, where the refresh token
/// lives and which `.dat` files exist, and the at-rest protection in use.
pub fn diagnoseCache(gpa: Allocator, stdout: *Io.Writer) !void {
    const dir = keyringDir(gpa) catch {
        try stdout.writeAll("ado cache dir: <unavailable>\n");
        return;
    };
    defer gpa.free(dir);
    try stdout.print("ado cache dir: {s}\n", .{dir});
    try stdout.print("ado disk cache: {s} ({s})\n", .{
        if (diskCacheDisabled()) "disabled" else "enabled",
        disk_cache_env,
    });
    switch (builtin.os.tag) {
        .windows => try stdout.writeAll("ado refresh token: Windows Credential Manager (ado-keyring)\n"),
        .macos => try stdout.writeAll("ado refresh token: macOS Keychain (ado-keyring/refresh-token)\n"),
        else => try stdout.print("ado refresh.dat: {s}\n", .{if (datExists(gpa, refresh_dat_name)) "present" else "absent"}),
    }
    try stdout.print("ado session.dat: {s}\n", .{if (datExists(gpa, session_dat_name)) "present" else "absent"});
    try stdout.print("ado at-rest: {s}\n", .{
        if (builtin.os.tag == .windows) "DPAPI (CryptProtectData, current-user)" else "chmod 0600",
    });
}

fn getHome(gpa: Allocator) ![]u8 {
    if (builtin.os.tag == .windows) {
        if (getEnvVarOwned(gpa, "USERPROFILE")) |value| return value;
        if (getEnvVarOwned(gpa, "LOCALAPPDATA")) |value| return value;
    }
    return getEnvVarOwned(gpa, "HOME") orelse error.EnvironmentVariableNotFound;
}

fn isNonInteractive() bool {
    const value = getEnvVarOwned(std.heap.page_allocator, noninteractive_env) orelse return false;
    defer std.heap.page_allocator.free(value);
    return std.ascii.eqlIgnoreCase(value, "true") or std.mem.eql(u8, value, "1");
}

fn unixNow() i64 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Clock.real.now(io).toSeconds();
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

fn log(stderr: *Io.Writer, comptime fmt: []const u8, args: anytype) void {
    stderr.print(fmt, args) catch return;
    stderr.flush() catch return;
}

const success_html =
    "<html><head><title>Authentication Successful</title></head>" ++
    "<body style=\"font-family:sans-serif;text-align:center;margin-top:80px\">" ++
    "<h1>Authentication Successful</h1>" ++
    "<p>You can close this tab and return to the terminal.</p>" ++
    "</body></html>";

test "recognizes Azure DevOps URLs" {
    try std.testing.expect(isDevOpsUrl("https://myorg.pkgs.visualstudio.com/_packaging/foo/pypi/simple/"));
    try std.testing.expect(isDevOpsUrl("https://pkgs.dev.azure.com/myorg/_packaging/feed/pypi/simple/"));
    try std.testing.expect(isDevOpsUrl("https://pkgs.codedev.ms/myorg/_packaging/feed/pypi/simple/"));
    try std.testing.expect(isDevOpsUrl("https://pkgs.vsts.me/myorg/_packaging/feed/pypi/simple/"));
    try std.testing.expect(!isDevOpsUrl("https://pypi.org/simple/"));
}

test "extracts Azure DevOps org" {
    try std.testing.expectEqualStrings("myorg", extractOrg("https://myorg.pkgs.visualstudio.com/_packaging/feed/pypi/simple/").?);
    try std.testing.expectEqualStrings("myorg", extractOrg("https://pkgs.dev.azure.com/myorg/_packaging/feed/pypi/simple/").?);
    try std.testing.expectEqualStrings("contoso", extractOrg("https://dev.azure.com/contoso/_packaging/feed/pypi/simple/").?);
    try std.testing.expectEqualStrings("pkgs", extractOrg("https://pkgs.codedev.ms/myorg/_packaging/feed/pypi/simple/").?);
    try std.testing.expect(extractOrg("https://dev.azure.com/") == null);
}

test "PKCE challenge hashes verifier text" {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier, &digest, .{});
    var challenge: [43]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&challenge, &digest);
    try std.testing.expectEqualStrings("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", &challenge);
}

test "parses OAuth callback" {
    const code = try parseOAuthCallback(std.testing.allocator, "/?code=abc%20123&state=ok", "ok");
    defer std.testing.allocator.free(code);
    try std.testing.expectEqualStrings("abc 123", code);
    try std.testing.expectError(error.AuthenticationFailed, parseOAuthCallback(std.testing.allocator, "/?code=abc&state=no", "ok"));
}

test "extractOrg result survives a subsequent stack-clobbering call" {
    // Regression test: extractOrg previously returned a slice into a local stack
    // buffer (via std.Uri.getHost). After returning, the next function call could
    // reuse that stack region and corrupt the org name. Capture the org, then run
    // an unrelated call that allocates a large stack frame, and confirm the org
    // bytes are unchanged.
    const org = extractOrg("https://msazure.pkgs.visualstudio.com/One/_packaging/feed/pypi/simple/").?;
    var scratch: [4096]u8 = undefined;
    for (&scratch, 0..) |*b, i| b.* = @intCast(i & 0xff);
    std.mem.doNotOptimizeAway(&scratch);
    try std.testing.expectEqualStrings("msazure", org);
}

test "refresh cache JSON round-trips the tokens after the source buffer is freed" {
    // Regression test for a use-after-free: loadRefreshDat frees the file buffer
    // after parsing, so the parsed RefreshCache must own its strings. We emulate
    // that by parsing with the same options, freeing the source buffer, and only
    // then reading the tokens.
    const gpa = std.testing.allocator;
    const json =
        \\{ "access_token": "access-abc", "refresh_token": "refresh-xyz", "expires_at": 1000000 }
    ;
    const bytes = try gpa.dupe(u8, json);

    var parsed = try std.json.parseFromSlice(RefreshCache, gpa, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer parsed.deinit();
    gpa.free(bytes);

    try std.testing.expectEqualStrings("access-abc", parsed.value.access_token.?);
    try std.testing.expectEqualStrings("refresh-xyz", parsed.value.refresh_token.?);
    try std.testing.expectEqual(@as(i64, 1_000_000), parsed.value.expires_at);
}

test "long-lived JSON round-trips refresh token only and excludes session tokens" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var cache: Cache = .{
        .access_token = "access-abc",
        .refresh_token = "refresh-xyz",
        .expires_at = 1_700_000_000,
    };

    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    try writeLongLivedJson(&out.writer, &cache);

    const parsed = try std.json.parseFromSliceLeaky(LongLived, arena.allocator(), out.written(), .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    // Only the refresh token is persisted to WCM; the access token is omitted
    // so the blob stays under CRED_MAX_CREDENTIAL_BLOB_SIZE (issue #15 fix).
    try std.testing.expectEqualStrings("refresh-xyz", parsed.refresh_token.?);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "access-abc") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "session") == null);
}

test "session file holds session tokens and no secrets" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var cache: Cache = .{
        .access_token = "access-secret",
        .refresh_token = "refresh-secret",
        .expires_at = 1_000,
    };

    // Build a cache with one pre-existing org session token.
    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    out.writer.writeAll("{\n  \"session_tokens\": {") catch unreachable;
    try writeSessionMap(&out.writer, &cache, "contoso", "tok-contoso", 2_000);
    out.writer.writeAll("\n  }\n}\n") catch unreachable;

    // The long-lived secrets must never appear in the session file.
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "access-secret") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "refresh-secret") == null);

    const parsed = try std.json.parseFromSliceLeaky(Cache, arena.allocator(), out.written(), .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    const session = parsed.session_tokens.map.get("contoso") orelse return error.SessionTokenMissing;
    try std.testing.expectEqualStrings("tok-contoso", session.token);
    try std.testing.expectEqual(@as(i64, 2_000), session.expires_at);
    try std.testing.expect(parsed.access_token == null);
}

test "loadLegacyInto session file does not clobber long-lived tokens" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    // Simulate the Windows split: long-lived loaded first, then a session-only
    // file merged on top must keep the long-lived tokens intact.
    var cache: Cache = .{ .access_token = "ll-access", .refresh_token = "ll-refresh", .expires_at = 42 };
    const session_json =
        \\{ "session_tokens": { "contoso": { "token": "s", "expires_at": 9 } } }
    ;
    const parsed = try std.json.parseFromSliceLeaky(Cache, a, session_json, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    cache.session_tokens = parsed.session_tokens;
    if (parsed.access_token != null or parsed.refresh_token != null) {
        cache.access_token = parsed.access_token;
        cache.refresh_token = parsed.refresh_token;
        cache.expires_at = parsed.expires_at;
    }

    try std.testing.expectEqualStrings("ll-access", cache.access_token.?);
    try std.testing.expectEqualStrings("ll-refresh", cache.refresh_token.?);
    try std.testing.expectEqual(@as(i64, 42), cache.expires_at);
    try std.testing.expect(cache.session_tokens.map.get("contoso") != null);
}

/// Point the cache (and optionally the legacy dir) at a temporary directory for
/// the duration of a test. The resolved root is heap-allocated so the override
/// slice stays valid after `init` returns by value.
const TempCache = struct {
    tmp: std.testing.TmpDir,
    root: []u8,

    fn init(gpa: Allocator) !TempCache {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(ioGlobal(), &buf);
        const root = try gpa.dupe(u8, buf[0..len]);
        cache_root_override = root;
        return .{ .tmp = tmp, .root = root };
    }

    fn deinit(self: *TempCache, gpa: Allocator) void {
        cache_root_override = null;
        legacy_dir_override = null;
        gpa.free(self.root);
        self.tmp.cleanup();
    }
};

test "session.dat round-trips a session token" {
    const gpa = std.testing.allocator;
    var tc = try TempCache.init(gpa);
    defer tc.deinit(gpa);

    try saveSessionDat(gpa, "contoso", "tok-contoso", 2_000);

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var cache: Cache = .{};
    loadSessionDat(arena.allocator(), &cache);

    const session = cache.session_tokens.map.get("contoso") orelse return error.SessionTokenMissing;
    try std.testing.expectEqualStrings("tok-contoso", session.token);
    try std.testing.expectEqual(@as(i64, 2_000), session.expires_at);
}

test "refresh.dat round-trips the long-lived tokens" {
    const gpa = std.testing.allocator;
    var tc = try TempCache.init(gpa);
    defer tc.deinit(gpa);

    const written: Cache = .{ .access_token = "acc", .refresh_token = "ref", .expires_at = 1_234 };
    try saveRefreshDat(gpa, &written);

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var cache: Cache = .{};
    loadRefreshDat(arena.allocator(), &cache);

    try std.testing.expectEqualStrings("acc", cache.access_token.?);
    try std.testing.expectEqualStrings("ref", cache.refresh_token.?);
    try std.testing.expectEqual(@as(i64, 1_234), cache.expires_at);
}

test "corrupt session.dat is treated as empty, not a crash" {
    const gpa = std.testing.allocator;
    var tc = try TempCache.init(gpa);
    defer tc.deinit(gpa);

    // Bytes that are neither a valid DPAPI blob (Windows) nor valid JSON (Unix).
    const path = try datFilePath(gpa, session_dat_name);
    defer gpa.free(path);
    try writeFileAtomic(gpa, path, "this is not a valid cache \x00\xff");

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var cache: Cache = .{};
    loadSessionDat(arena.allocator(), &cache);

    try std.testing.expectEqual(@as(usize, 0), cache.session_tokens.map.count());
}

test "session.dat merges sequential writers without losing entries" {
    // Each save re-reads the on-disk map under the lock and merges in its own
    // org, so writers for different orgs (including separate processes) do not
    // clobber one another. This exercises that read-modify-write merge.
    const gpa = std.testing.allocator;
    var tc = try TempCache.init(gpa);
    defer tc.deinit(gpa);

    try saveSessionDat(gpa, "org-a", "tok-a", 100);
    try saveSessionDat(gpa, "org-b", "tok-b", 200);
    try saveSessionDat(gpa, "org-c", "tok-c", 300);

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var cache: Cache = .{};
    loadSessionDat(arena.allocator(), &cache);

    try std.testing.expectEqual(@as(usize, 3), cache.session_tokens.map.count());
    try std.testing.expectEqualStrings("tok-a", cache.session_tokens.map.get("org-a").?.token);
    try std.testing.expectEqualStrings("tok-b", cache.session_tokens.map.get("org-b").?.token);
    try std.testing.expectEqualStrings("tok-c", cache.session_tokens.map.get("org-c").?.token);
}

test "legacy token-cache.json migrates once into the dat files" {
    // Gated to Linux: there the refresh token migrates into refresh.dat (a file),
    // whereas on Windows/macOS it would write the real OS secret store. The
    // file-based pieces of the migration are otherwise platform-uniform.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    var tc = try TempCache.init(gpa);
    defer tc.deinit(gpa);

    const legacy_dir = try std.fs.path.join(gpa, &.{ tc.root, "legacy" });
    defer gpa.free(legacy_dir);
    legacy_dir_override = legacy_dir;

    const legacy_json =
        \\{ "access_token": "a", "refresh_token": "r", "expires_at": 5, "session_tokens": { "contoso": { "token": "s", "expires_at": 9 } } }
    ;
    const legacy_path = try legacyFilePath(gpa, cache_file_name);
    defer gpa.free(legacy_path);
    try writeFileAtomic(gpa, legacy_path, legacy_json);

    var loaded = loadCache(gpa);
    defer loaded.deinit(gpa);
    try std.testing.expectEqualStrings("r", loaded.cache.refresh_token.?);
    try std.testing.expect(loaded.cache.session_tokens.map.get("contoso") != null);

    // Legacy file removed; new protected files written.
    {
        const exists = blk: {
            std.Io.Dir.cwd().access(ioGlobal(), legacy_path, .{}) catch break :blk false;
            break :blk true;
        };
        try std.testing.expect(!exists);
    }
    try std.testing.expect(datExists(gpa, refresh_dat_name));
    try std.testing.expect(datExists(gpa, session_dat_name));

    // A second load reads only the dat files; migration does not run again.
    var loaded2 = loadCache(gpa);
    defer loaded2.deinit(gpa);
    try std.testing.expectEqualStrings("r", loaded2.cache.refresh_token.?);
    try std.testing.expect(loaded2.cache.session_tokens.map.get("contoso") != null);
}
