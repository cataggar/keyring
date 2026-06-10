const std = @import("std");
const builtin = @import("builtin");
const wincred = @import("wincred.zig");
const msal_cache = @import("msal_cache.zig");

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
const cache_dir_name = ".ado-keyring";
const cache_file_name = "token-cache.json";
const session_file_name = "session-cache.json";
// Windows Credential Manager target. Using the bare service name as the target
// makes the entry inspectable via `cmdkey /list:ado-keyring` and removable via
// `cmdkey /delete:ado-keyring`.
const wcm_service = "ado-keyring";
const wcm_key = "refresh-token";
const noninteractive_env = "ADO_KEYRING_NONINTERACTIVE";

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
/// Manager (issue #15). Only the OAuth refresh token is stored: the matching
/// access token is short-lived (~1 hour) and trivially re-derived from the
/// refresh token, and including it pushes the credential blob past
/// `CRED_MAX_CREDENTIAL_BLOB_SIZE` (5*512 bytes), making `CredWriteW` fail.
/// Per-org session tokens are kept separately in a non-secret file.
const LongLived = struct {
    refresh_token: ?[]const u8 = null,
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
    if (builtin.os.tag == .windows) {
        var removed = true;
        wincred.delete(gpa, wcm_service) catch |err| switch (err) {
            error.EntryNotFound => removed = false,
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.CacheFailure,
        };
        if (deleteCacheFile(gpa, session_file_name)) removed = true;
        if (deleteCacheFile(gpa, cache_file_name)) removed = true;
        return if (removed) {} else error.EntryNotFound;
    }
    if (deleteCacheFile(gpa, cache_file_name)) return;
    return error.EntryNotFound;
}

/// Delete a cache file under the cache directory. Returns true if a file was
/// removed, false if it was already absent.
fn deleteCacheFile(gpa: Allocator, name: []const u8) bool {
    const io = std.Io.Threaded.global_single_threaded.io();
    const path = cacheFilePath(gpa, name) catch return false;
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

/// Load the long-lived tokens and per-org session tokens into an owned cache.
/// On Windows the long-lived tokens live in the Credential Manager and the
/// session tokens in a non-secret JSON file; elsewhere a single JSON file holds
/// both. Never errors — a missing or corrupt cache yields an empty one.
fn loadCache(gpa: Allocator) LoadedCache {
    const arena = gpa.create(std.heap.ArenaAllocator) catch
        return .{ .arena = emptyArena(gpa), .cache = .{} };
    arena.* = .init(gpa);
    const a = arena.allocator();
    var cache: Cache = .{};
    if (builtin.os.tag == .windows) {
        loadWindows(a, &cache);
    } else {
        _ = loadFileInto(a, cache_file_name, &cache);
    }
    return .{ .arena = arena, .cache = cache };
}

fn emptyArena(gpa: Allocator) *std.heap.ArenaAllocator {
    const arena = gpa.create(std.heap.ArenaAllocator) catch unreachable;
    arena.* = .init(gpa);
    return arena;
}

/// Windows: read the long-lived refresh token from the Credential Manager,
/// migrating a legacy plaintext JSON cache on first run, then load the
/// session-token file. The access token is intentionally not persisted (see
/// `LongLived`); it stays in memory for the lifetime of this process.
fn loadWindows(a: Allocator, cache: *Cache) void {
    if (wincred.get(a, wcm_service)) |blob| {
        if (std.json.parseFromSliceLeaky(LongLived, a, blob, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        })) |ll| {
            cache.refresh_token = ll.refresh_token;
        } else |_| {}
    } else |_| {
        migrateLegacyWindows(a, cache);
    }
    _ = loadFileInto(a, session_file_name, cache);
}

/// One-time migration: if a legacy `token-cache.json` exists, move its
/// long-lived tokens into the Credential Manager, adopt its session tokens, and
/// delete the file.
fn migrateLegacyWindows(a: Allocator, cache: *Cache) void {
    var legacy: Cache = .{};
    if (!loadFileInto(a, cache_file_name, &legacy)) return;

    cache.access_token = legacy.access_token;
    cache.refresh_token = legacy.refresh_token;
    cache.expires_at = legacy.expires_at;
    cache.session_tokens = legacy.session_tokens;

    if (legacy.refresh_token != null or legacy.access_token != null) {
        saveLongLivedWindows(a, cache) catch {};
    }
    saveSessionFile(a, cache, null, null, 0) catch {};
    _ = deleteCacheFile(a, cache_file_name);
}

/// Parse a JSON cache file under the cache directory and merge it into `cache`.
/// Session tokens always replace those in `cache`; the long-lived tokens are
/// only copied when present, so reading the Windows session-only file does not
/// clobber tokens already loaded from the Credential Manager. Returns true if
/// the file existed and parsed. Strings are owned by `a`.
fn loadFileInto(a: Allocator, name: []const u8, cache: *Cache) bool {
    const io = std.Io.Threaded.global_single_threaded.io();
    const path = cacheFilePath(a, name) catch return false;
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

fn saveCache(gpa: Allocator, cache: *const Cache, org: []const u8, token: []const u8, expires_at: i64) Error!void {
    if (builtin.os.tag == .windows) {
        try saveLongLivedWindows(gpa, cache);
        return saveSessionFile(gpa, cache, org, token, expires_at);
    }
    return saveFile(gpa, cache, org, token, expires_at);
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

fn writeLongLivedJson(writer: *Io.Writer, cache: *const Cache) Error!void {
    writer.writeAll("{\"refresh_token\":") catch return error.CacheFailure;
    try writeJsonOptionalString(writer, cache.refresh_token);
    writer.writeAll("}") catch return error.CacheFailure;
}

/// Write the non-secret session-token file. When `org`/`token` are non-null the
/// new entry replaces any existing one for that org.
fn saveSessionFile(gpa: Allocator, cache: *const Cache, org: ?[]const u8, token: ?[]const u8, expires_at: i64) Error!void {
    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    out.writer.writeAll("{\n  \"session_tokens\": {") catch return error.CacheFailure;
    try writeSessionMap(&out.writer, cache, org, token, expires_at);
    out.writer.writeAll("\n  }\n}\n") catch return error.CacheFailure;
    return writeCacheFileAtomic(gpa, session_file_name, out.written());
}

fn saveFile(gpa: Allocator, cache: *const Cache, org: []const u8, token: []const u8, expires_at: i64) Error!void {
    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    try writeCacheJson(gpa, &out.writer, cache, org, token, expires_at);
    return writeCacheFileAtomic(gpa, cache_file_name, out.written());
}

/// Atomically write `contents` to the named file in the cache directory.
fn writeCacheFileAtomic(gpa: Allocator, name: []const u8, contents: []const u8) Error!void {
    const io = std.Io.Threaded.global_single_threaded.io();
    const path = try cacheFilePath(gpa, name);
    defer gpa.free(path);
    const parent = std.fs.path.dirname(path) orelse return error.CacheFailure;
    _ = std.Io.Dir.cwd().createDirPathStatus(io, parent, cacheDirPermissions()) catch return error.CacheFailure;

    // Use a unique temp filename per write. uv (and other consumers) spawn many
    // keyring processes concurrently; a shared "{path}.tmp" name causes them to
    // race on the same file, producing a corrupt cache that fails to parse and
    // forces a re-authentication on every subsequent call. A per-process random
    // suffix keeps each writer's temp file private before the atomic rename.
    var suffix_bytes: [8]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&suffix_bytes);
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

fn cacheDirPermissions() std.Io.File.Permissions {
    return if (builtin.os.tag == .windows) .default_dir else .fromMode(0o700);
}

fn cacheFilePermissions() std.Io.File.Permissions {
    return if (builtin.os.tag == .windows) .default_file else .fromMode(0o600);
}

fn writeCacheJson(gpa: Allocator, writer: *Io.Writer, cache: *const Cache, org: []const u8, token: []const u8, expires_at: i64) Error!void {
    _ = gpa;
    writer.writeAll("{\n  \"access_token\": ") catch return error.CacheFailure;
    try writeJsonOptionalString(writer, cache.access_token);
    writer.writeAll(",\n  \"refresh_token\": ") catch return error.CacheFailure;
    try writeJsonOptionalString(writer, cache.refresh_token);
    writer.print(",\n  \"expires_at\": {d},\n  \"session_tokens\": {{", .{cache.expires_at}) catch return error.CacheFailure;
    try writeSessionMap(writer, cache, org, token, expires_at);
    writer.writeAll("\n  }\n}\n") catch return error.CacheFailure;
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

fn cacheFilePath(gpa: Allocator, name: []const u8) Error![]u8 {
    const home = getHome(gpa) catch return error.CacheFailure;
    defer gpa.free(home);
    return std.fs.path.join(gpa, &.{ home, cache_dir_name, name }) catch return error.OutOfMemory;
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

test "cache JSON round-trips the session token after the source buffer is freed" {
    // Regression test for a use-after-free: loadCache frees the file buffer after
    // parsing, so the parsed Cache must own its strings. We emulate that by
    // serializing into a heap buffer, parsing with the same options loadCache
    // uses, freeing the source buffer, and only then reading the session token.
    const gpa = std.testing.allocator;
    var cache: Cache = .{
        .access_token = "access-abc",
        .refresh_token = "refresh-xyz",
        .expires_at = 1_000_000,
    };

    var out = std.Io.Writer.Allocating.init(gpa);
    try writeCacheJson(gpa, &out.writer, &cache, "msazure", "session-token-123", 2_000_000);

    // Copy the JSON onto its own heap buffer and free `out` so that any slice that
    // still references the original bytes would be reading freed memory.
    const bytes = try gpa.dupe(u8, out.written());
    out.deinit();

    var parsed = try std.json.parseFromSlice(Cache, gpa, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer parsed.deinit();
    gpa.free(bytes);

    const session = parsed.value.session_tokens.map.get("msazure") orelse return error.SessionTokenMissing;
    try std.testing.expectEqualStrings("session-token-123", session.token);
    try std.testing.expectEqual(@as(i64, 2_000_000), session.expires_at);
    try std.testing.expectEqualStrings("access-abc", parsed.value.access_token.?);
    try std.testing.expectEqualStrings("refresh-xyz", parsed.value.refresh_token.?);
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

test "loadFileInto session file does not clobber long-lived tokens" {
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
