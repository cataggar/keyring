const std = @import("std");
const builtin = @import("builtin");

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

pub fn getCredential(gpa: Allocator, stderr: *Io.Writer, service_url: []const u8) Error!Credential {
    if (!isDevOpsUrl(service_url)) return error.EntryNotFound;

    const org = extractOrg(service_url) orelse return error.Unsupported;
    const now = unixNow();

    var cache_parsed = loadCache(gpa) catch null;
    defer if (cache_parsed) |*parsed| parsed.deinit();
    var cache: Cache = if (cache_parsed) |parsed| parsed.value else .{};

    if (cache.session_tokens.map.get(org)) |session| {
        if (session.expires_at > now + 300) {
            log(stderr, "{s} Using cached session token for '{s}'\n", .{ log_prefix, org });
            return .{ .username = session_username, .password = try gpa.dupe(u8, session.token) };
        }
    }

    var token_parsed: ?std.json.Parsed(TokenResponse) = null;
    defer if (token_parsed) |*parsed| parsed.deinit();

    if (cache.access_token == null or cache.expires_at <= now + 60) {
        if (cache.refresh_token) |refresh_token| {
            log(stderr, "{s} Refreshing access token...\n", .{log_prefix});
            token_parsed = refreshAccessToken(gpa, refresh_token) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => blk: {
                    log(stderr, "{s} Refresh failed ({s}), falling back to browser\n", .{ log_prefix, @errorName(err) });
                    break :blk try browserAuth(gpa, stderr);
                },
            };
        } else {
            if (isNonInteractive()) return error.NoStorageAccess;
            log(stderr, "{s} No cached token, starting browser auth...\n", .{log_prefix});
            token_parsed = try browserAuth(gpa, stderr);
        }

        if (token_parsed) |parsed| {
            cache.access_token = parsed.value.access_token;
            cache.refresh_token = parsed.value.refresh_token;
            cache.expires_at = now + parsed.value.expires_in;
        }
    }

    const access_token = cache.access_token orelse return error.AuthenticationFailed;
    log(stderr, "{s} Exchanging for VssSessionToken ({s})...\n", .{ log_prefix, org });
    var session_parsed = try getSessionToken(gpa, access_token, org);
    defer session_parsed.deinit();

    const token = session_parsed.value.token;
    const owned_token = try gpa.dupe(u8, token);
    errdefer gpa.free(owned_token);

    try saveCache(gpa, &cache, org, token, now + 3000);

    log(stderr, "{s} Authenticated to '{s}'\n", .{ log_prefix, org });
    return .{ .username = session_username, .password = owned_token };
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
    const io = std.Io.Threaded.global_single_threaded.io();
    const path = try cachePath(gpa);
    defer gpa.free(path);
    std.Io.Dir.cwd().deleteFile(io, path) catch |err| switch (err) {
        error.FileNotFound => return error.EntryNotFound,
        else => return error.CacheFailure,
    };
}

pub fn isDevOpsUrl(url: []const u8) bool {
    return std.mem.indexOf(u8, url, "visualstudio.com") != null or
        std.mem.indexOf(u8, url, "dev.azure.com") != null or
        std.mem.indexOf(u8, url, "pkgs.codedev.ms") != null or
        std.mem.indexOf(u8, url, "pkgs.vsts.me") != null;
}

pub fn extractOrg(service_url: []const u8) ?[]const u8 {
    const parsed = std.Uri.parse(service_url) catch return null;
    var host_buffer: [std.Io.net.HostName.max_len]u8 = undefined;
    const host_name = parsed.getHost(&host_buffer) catch return null;
    const host = host_name.bytes;

    if (std.mem.endsWith(u8, host, "visualstudio.com") or
        std.mem.endsWith(u8, host, "vsts.me") or
        std.mem.endsWith(u8, host, "codedev.ms"))
    {
        const dot = std.mem.indexOfScalar(u8, host, '.') orelse return null;
        return if (dot == 0) null else host[0..dot];
    }

    if (std.mem.indexOf(u8, host, "dev.azure.com") != null) {
        const path = parsed.path.percent_encoded;
        var start: usize = 0;
        while (start < path.len and path[start] == '/') start += 1;
        if (start >= path.len) return null;
        var end = start;
        while (end < path.len and path[end] != '/') end += 1;
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
    const redirect_uri = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}", .{bound_port});
    defer gpa.free(redirect_uri);

    const url = try buildAuthorizeUrl(gpa, redirect_uri, &challenge, state);
    defer gpa.free(url);

    log(stderr, "{s} Opening browser for Azure DevOps authentication...\n", .{log_prefix});
    log(stderr, "{s} If the browser does not open, visit:\n{s}\n", .{ log_prefix, url });
    try openBrowser(gpa, url);

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

fn openBrowser(gpa: Allocator, url: []const u8) Error!void {
    const io = std.Io.Threaded.global_single_threaded.io();
    const attempts = browserAttempts();
    for (attempts) |argv_prefix| {
        const argv = try appendUrlArg(gpa, argv_prefix, url);
        defer gpa.free(argv);
        const result = std.process.run(gpa, io, .{
            .argv = argv,
            .stdout_limit = .limited(32 * 1024),
            .stderr_limit = .limited(32 * 1024),
        }) catch continue;
        defer gpa.free(result.stdout);
        defer gpa.free(result.stderr);
        if (result.term == .exited and result.term.exited == 0) return;
    }
    return error.NoStorageAccess;
}

fn browserAttempts() []const []const []const u8 {
    if (builtin.os.tag == .macos) {
        return &.{&.{"open"}};
    }
    if (builtin.os.tag == .windows) {
        return &.{ &.{ "cmd", "/c", "start", "" }, &.{ "powershell", "-NoProfile", "-Command", "Start-Process" } };
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

fn loadCache(gpa: Allocator) Error!?std.json.Parsed(Cache) {
    const io = std.Io.Threaded.global_single_threaded.io();
    const path = try cachePath(gpa);
    defer gpa.free(path);
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return null,
    };
    defer gpa.free(bytes);
    return std.json.parseFromSlice(Cache, gpa, bytes, .{ .ignore_unknown_fields = true }) catch null;
}

fn saveCache(gpa: Allocator, cache: *const Cache, org: []const u8, token: []const u8, expires_at: i64) Error!void {
    const io = std.Io.Threaded.global_single_threaded.io();
    const path = try cachePath(gpa);
    defer gpa.free(path);
    const parent = std.fs.path.dirname(path) orelse return error.CacheFailure;
    _ = std.Io.Dir.cwd().createDirPathStatus(io, parent, .fromMode(0o700)) catch return error.CacheFailure;

    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    try writeCacheJson(gpa, &out.writer, cache, org, token, expires_at);

    const tmp = try std.fmt.allocPrint(gpa, "{s}.tmp", .{path});
    defer gpa.free(tmp);
    {
        var file = std.Io.Dir.cwd().createFile(io, tmp, .{ .truncate = true, .permissions = .fromMode(0o600) }) catch return error.CacheFailure;
        defer file.close(io);
        file.writeStreamingAll(io, out.written()) catch return error.CacheFailure;
    }
    std.Io.Dir.renameAbsolute(tmp, path, io) catch return error.CacheFailure;
}

fn writeCacheJson(gpa: Allocator, writer: *Io.Writer, cache: *const Cache, org: []const u8, token: []const u8, expires_at: i64) Error!void {
    writer.writeAll("{\n  \"access_token\": ") catch return error.CacheFailure;
    try writeJsonOptionalString(writer, cache.access_token);
    writer.writeAll(",\n  \"refresh_token\": ") catch return error.CacheFailure;
    try writeJsonOptionalString(writer, cache.refresh_token);
    writer.print(",\n  \"expires_at\": {d},\n  \"session_tokens\": {{", .{cache.expires_at}) catch return error.CacheFailure;

    var first = true;
    var it = cache.session_tokens.map.iterator();
    while (it.next()) |entry| {
        if (std.mem.eql(u8, entry.key_ptr.*, org)) continue;
        if (!first) writer.writeAll(",") catch return error.CacheFailure;
        first = false;
        writer.writeAll("\n    ") catch return error.CacheFailure;
        try writeJsonString(writer, entry.key_ptr.*);
        writer.print(": {{ \"token\": ", .{}) catch return error.CacheFailure;
        try writeJsonString(writer, entry.value_ptr.token);
        writer.print(", \"expires_at\": {d} }}", .{entry.value_ptr.expires_at}) catch return error.CacheFailure;
    }

    if (!first) writer.writeAll(",") catch return error.CacheFailure;
    _ = gpa;
    writer.writeAll("\n    ") catch return error.CacheFailure;
    try writeJsonString(writer, org);
    writer.writeAll(": { \"token\": ") catch return error.CacheFailure;
    try writeJsonString(writer, token);
    writer.print(", \"expires_at\": {d} }}\n  }}\n}}\n", .{expires_at}) catch return error.CacheFailure;
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

fn cachePath(gpa: Allocator) Error![]u8 {
    const home = getHome(gpa) catch return error.CacheFailure;
    defer gpa.free(home);
    return std.fs.path.join(gpa, &.{ home, cache_dir_name, cache_file_name }) catch return error.OutOfMemory;
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
