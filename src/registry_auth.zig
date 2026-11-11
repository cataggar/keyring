//! Shared OCI/Docker container registry authentication primitives (`#40`, `#63`, `#65`).
//!
//! Centralizes:
//! - Typed registry credentials (`CredentialKind.basic` vs `.identity_token`) with
//!   automatic secret zeroing.
//! - Server normalization for both legacy Docker Hub URLs (`wslc` ->
//!   `https://index.docker.io/v1/`) and bare hostnames (`podman` / Podman Desktop ->
//!   `docker.io`).
//! - GitHub Container Registry (`ghcr.io`, `containers.<tenant>.ghe.com`,
//!   `docker.<ghes>`) host mapping.
//! - Azure Container Registry (`*.azurecr.{io,cn,de,us}`) `/v2/` tenant discovery,
//!   `/oauth2/exchange` request/client, and JWT `exp`/`tid` claim inspection.
//! - Deterministic OS-keyring storage (`service = "container-registry://<host>"`,
//!   `account = "default"`) paired with a non-secret `<state_dir>/registries.json`
//!   server-to-username index so `docker-credential-keyring get` and `list` work
//!   without username input or backend enumeration.
//! - Docker/Podman credential-helper wire protocol (`get`, `store`, `erase`, `list`,
//!   `version`) and user-restricted atomic file persistence (POSIX `0600` and
//!   Windows protected current-user DACL).
const std = @import("std");
const builtin = @import("builtin");
const keyring_zig = @import("keyring_zig");
const ado = @import("ado.zig");
const credential_provider = @import("credential_provider.zig");
const gh = @import("gh.zig");
const msal_cache = @import("msal_cache.zig");
const stored_provider = @import("stored_provider.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const docker_hub_legacy_url = "https://index.docker.io/v1/";
pub const docker_hub_bare_host = "docker.io";
pub const acr_token_username = "00000000-0000-0000-0000-000000000000";
pub const identity_token_username = "<token>";
pub const helper_not_found_message = "credentials not found in native keychain\n";
pub const max_helper_input_bytes: usize = 64 * 1024;
pub const generic_service_prefix = "container-registry://";
pub const generic_default_account = "default";
pub const registries_index_filename = "registries.json";
pub const registries_lock_filename = "registries.lock";

pub const CredentialKind = enum {
    basic,
    identity_token,
};

pub const InteractionPolicy = enum {
    interactive,
    noninteractive,
};

pub const DockerHubStyle = enum {
    legacy_v1_url,
    bare_docker_io,
};

pub const HelperOperation = enum {
    get,
    store,
    erase,
    list,
    version,

    pub fn fromString(s: []const u8) ?HelperOperation {
        if (std.mem.eql(u8, s, "get")) return .get;
        if (std.mem.eql(u8, s, "store")) return .store;
        if (std.mem.eql(u8, s, "erase")) return .erase;
        if (std.mem.eql(u8, s, "list")) return .list;
        if (std.mem.eql(u8, s, "version")) return .version;
        return null;
    }
};

pub const Error = error{
    InvalidServer,
    InvalidInput,
    EntryNotFound,
    NoStorageAccess,
    Locked,
    StorageFailure,
    AuthenticationFailed,
    NetworkFailure,
    OutOfMemory,
};

pub const RegistryCredential = struct {
    kind: CredentialKind = .basic,
    server: []u8,
    username: []u8,
    secret: []u8,
    expires_at: ?i64 = null,

    pub fn deinit(self: *const RegistryCredential, gpa: Allocator) void {
        gpa.free(self.server);
        gpa.free(self.username);
        std.crypto.secureZero(u8, self.secret);
        gpa.free(self.secret);
    }
};

pub const RegistryIndexEntry = struct {
    server: []u8,
    username: []u8,

    pub fn deinit(self: *const RegistryIndexEntry, gpa: Allocator) void {
        gpa.free(self.server);
        gpa.free(self.username);
    }
};

pub const HelperStorePayload = struct {
    server_url: []u8,
    username: []u8,
    secret: []u8,

    pub fn deinit(self: *const HelperStorePayload, gpa: Allocator) void {
        gpa.free(self.server_url);
        gpa.free(self.username);
        std.crypto.secureZero(u8, self.secret);
        gpa.free(self.secret);
    }
};

pub const GenericStoreOps = struct {
    get: *const fn (gpa: Allocator, service: []const u8, account: []const u8) keyring_zig.Error![]u8,
    set: *const fn (gpa: Allocator, service: []const u8, account: []const u8, password: []const u8) keyring_zig.Error!void,
    delete: *const fn (gpa: Allocator, service: []const u8, account: []const u8) keyring_zig.Error!void,
};

const live_generic_store_ops: GenericStoreOps = .{
    .get = keyring_zig.getAlloc,
    .set = keyring_zig.setAlloc,
    .delete = keyring_zig.deleteAlloc,
};

pub var generic_store_override: ?GenericStoreOps = null;
pub var state_dir_override: ?[]const u8 = null;
pub var env_override_fn: ?*const fn (name: []const u8) ?[]const u8 = null;
pub var now_seconds_override_fn: ?*const fn () i64 = null;

threadlocal var scoped_now_ms_override: ?i64 = null;

fn secondsToClampedMs(sec: i64) i64 {
    const max_sec = @divFloor(std.math.maxInt(i64), std.time.ms_per_s);
    const min_sec = @divFloor(std.math.minInt(i64), std.time.ms_per_s);
    if (sec >= max_sec) return std.math.maxInt(i64);
    if (sec <= min_sec) return std.math.minInt(i64);
    return sec * std.time.ms_per_s;
}

fn genericLookupNowMs() i64 {
    if (scoped_now_ms_override) |ms| return ms;
    if (now_seconds_override_fn) |f| return secondsToClampedMs(f());
    return credential_provider.defaultNowMs();
}

pub fn activeGenericStoreOps() GenericStoreOps {
    return generic_store_override orelse live_generic_store_ops;
}

// ---------------------------------------------------------------------------
// Server Normalization & Host Classification
// ---------------------------------------------------------------------------

/// Normalize a container registry server address:
/// - Trims whitespace, strips `http://` or `https://` (rejecting other schemes)
/// - Rejects `?`, `#`, `\`, `@`, whitespace, and ASCII control characters
/// - Strips `/<path>`
/// - Validates optional `:port` (`1..65535` for both host/IPv4 and `[ipv6]:port`)
/// - Lowercases authority and canonicalizes Docker Hub (`docker.io`,
///   `index.docker.io`, `registry-1.docker.io`) according to `style`.
pub fn normalizeServerAlloc(gpa: Allocator, raw_server: []const u8, style: DockerHubStyle) Error![]u8 {
    var s = std.mem.trim(u8, raw_server, " \t\r\n");
    if (s.len == 0) return error.InvalidServer;

    if (std.mem.indexOf(u8, s, "://")) |scheme_idx| {
        if (scheme_idx == 0) return error.InvalidServer;
        const scheme = s[0..scheme_idx];
        if (!std.ascii.eqlIgnoreCase(scheme, "https") and !std.ascii.eqlIgnoreCase(scheme, "http")) {
            return error.InvalidServer;
        }
        s = s[scheme_idx + 3 ..];
    }

    if (std.mem.indexOfAny(u8, s, "?#") != null) return error.InvalidServer;

    if (std.mem.indexOfScalar(u8, s, '/')) |slash_idx| {
        s = s[0..slash_idx];
    }

    if (s.len == 0) return error.InvalidServer;
    if (std.mem.indexOfAny(u8, s, " \t\r\n\\@") != null) return error.InvalidServer;
    for (s) |c| {
        if (std.ascii.isControl(c)) return error.InvalidServer;
    }

    const host_only = try extractHostWithoutPort(s);
    if (host_only.len == 0) return error.InvalidServer;

    if (host_only[0] == '[') {
        const inner = host_only[1 .. host_only.len - 1];
        const groups = credential_provider.parseIpv6(inner) orelse return error.InvalidServer;
        const canon_host = credential_provider.formatCanonicalIpv6Alloc(gpa, groups) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidServer,
        };
        if (s.len > host_only.len) {
            defer gpa.free(canon_host);
            return std.fmt.allocPrint(gpa, "{s}{s}", .{ canon_host, s[host_only.len..] });
        }
        return canon_host;
    }

    const lowered = try gpa.dupe(u8, s);
    errdefer gpa.free(lowered);
    _ = std.ascii.lowerString(lowered, lowered);

    if (std.mem.eql(u8, lowered, "docker.io") or
        std.mem.eql(u8, lowered, "index.docker.io") or
        std.mem.eql(u8, lowered, "registry-1.docker.io"))
    {
        gpa.free(lowered);
        return switch (style) {
            .legacy_v1_url => gpa.dupe(u8, docker_hub_legacy_url),
            .bare_docker_io => gpa.dupe(u8, docker_hub_bare_host),
        };
    }

    return lowered;
}

pub fn parseValidPort(port_str: []const u8) Error!u16 {
    if (port_str.len == 0) return error.InvalidServer;
    for (port_str) |c| {
        if (!std.ascii.isDigit(c)) return error.InvalidServer;
    }
    const port = std.fmt.parseUnsigned(u16, port_str, 10) catch return error.InvalidServer;
    if (port == 0) return error.InvalidServer;
    return port;
}

pub fn extractHostWithoutPort(authority_or_url: []const u8) Error![]const u8 {
    var authority = authority_or_url;
    if (std.mem.indexOf(u8, authority, "://")) |scheme_idx| {
        authority = authority[scheme_idx + 3 ..];
        if (std.mem.indexOfScalar(u8, authority, '/')) |slash_idx| {
            authority = authority[0..slash_idx];
        }
    }
    if (authority.len == 0) return error.InvalidServer;
    if (authority[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidServer;
        if (close <= 1) return error.InvalidServer;
        if (close + 1 < authority.len) {
            if (authority[close + 1] != ':') return error.InvalidServer;
            _ = try parseValidPort(authority[close + 2 ..]);
        }
        return authority[0 .. close + 1];
    }
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon_idx| {
        if (std.mem.indexOfScalar(u8, authority[0..colon_idx], ':') != null) {
            return error.InvalidServer;
        }
        _ = try parseValidPort(authority[colon_idx + 1 ..]);
        return authority[0..colon_idx];
    }
    return authority;
}

/// Map `ghcr.io`, `containers.<tenant>.ghe.com`, or `docker.<github-host>` to
/// its corresponding GitHub host (`github.com`, `<tenant>.ghe.com`, or GHES host).
pub fn resolveGhcrGitHubHostAlloc(gpa: Allocator, normalized_server: []const u8) Error!?[]u8 {
    if (std.mem.indexOf(u8, normalized_server, "://") != null) return null;
    const host = extractHostWithoutPort(normalized_server) catch return null;
    if (std.ascii.eqlIgnoreCase(host, "ghcr.io")) {
        return try gpa.dupe(u8, "github.com");
    }
    if (std.ascii.startsWithIgnoreCase(host, "containers.") and
        host.len > "containers..ghe.com".len and
        std.ascii.endsWithIgnoreCase(host, ".ghe.com"))
    {
        return try gpa.dupe(u8, host["containers.".len..]);
    }
    if (std.ascii.startsWithIgnoreCase(host, "docker.") and host.len > "docker.".len) {
        const candidate = host["docker.".len..];
        if (gh.isGitHubHost(gpa, candidate)) {
            return try gpa.dupe(u8, candidate);
        }
    }
    return null;
}

/// Return true if `normalized_server` is an Azure Container Registry host
/// (`<name>.azurecr.io`, `<name>.azurecr.cn`, `<name>.azurecr.de`, `<name>.azurecr.us`).
pub fn isAcrServer(normalized_server: []const u8) bool {
    if (std.mem.indexOf(u8, normalized_server, "://") != null) return false;
    const host = extractHostWithoutPort(normalized_server) catch return false;
    const suffixes = [_][]const u8{
        ".azurecr.io",
        ".azurecr.cn",
        ".azurecr.de",
        ".azurecr.us",
    };
    for (suffixes) |suffix| {
        if (host.len > suffix.len and std.ascii.endsWithIgnoreCase(host, suffix)) {
            const prefix = host[0 .. host.len - suffix.len];
            if (prefix.len > 0 and prefix[0] != '.' and prefix[prefix.len - 1] != '.') {
                return true;
            }
        }
    }
    return false;
}

pub fn isAcrSentinelUsername(username: []const u8) bool {
    return std.mem.eql(u8, username, acr_token_username) or
        std.mem.eql(u8, username, identity_token_username);
}

pub fn isRealGenericUsername(username: []const u8) bool {
    return username.len > 0 and !isAcrSentinelUsername(username);
}

// ---------------------------------------------------------------------------
// JWT Claims & ACR OAuth2 Exchange
// ---------------------------------------------------------------------------

const JwtClaims = struct {
    exp: ?i64 = null,
    tid: ?[]const u8 = null,
};

pub fn extractJwtExpiration(gpa: Allocator, token: []const u8) ?i64 {
    const payload = decodeJwtPayloadAlloc(gpa, token) orelse return null;
    defer gpa.free(payload);
    const parsed = std.json.parseFromSlice(JwtClaims, gpa, payload, .{
        .ignore_unknown_fields = true,
    }) catch return null;
    defer parsed.deinit();
    return parsed.value.exp;
}

pub fn extractJwtTenantIdAlloc(gpa: Allocator, token: []const u8) ?[]u8 {
    const payload = decodeJwtPayloadAlloc(gpa, token) orelse return null;
    defer gpa.free(payload);
    const parsed = std.json.parseFromSlice(JwtClaims, gpa, payload, .{
        .ignore_unknown_fields = true,
    }) catch return null;
    defer parsed.deinit();
    const tid = parsed.value.tid orelse return null;
    if (tid.len == 0) return null;
    return gpa.dupe(u8, tid) catch null;
}

fn decodeJwtPayloadAlloc(gpa: Allocator, token: []const u8) ?[]u8 {
    const trimmed = std.mem.trim(u8, token, " \t\r\n");
    const first_dot = std.mem.indexOfScalar(u8, trimmed, '.') orelse return null;
    const after_first = trimmed[first_dot + 1 ..];
    const second_dot = std.mem.indexOfScalar(u8, after_first, '.') orelse return null;
    const raw_b64 = std.mem.trimEnd(u8, after_first[0..second_dot], "=");
    if (raw_b64.len == 0 or raw_b64.len > 64 * 1024) return null;

    if (std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(raw_b64)) |dec_len| {
        const out = gpa.alloc(u8, dec_len) catch return null;
        if (std.base64.url_safe_no_pad.Decoder.decode(out, raw_b64)) |_| {
            return out;
        } else |_| {
            gpa.free(out);
        }
    } else |_| {}

    if (std.base64.standard_no_pad.Decoder.calcSizeForSlice(raw_b64)) |dec_len| {
        const out = gpa.alloc(u8, dec_len) catch return null;
        if (std.base64.standard_no_pad.Decoder.decode(out, raw_b64)) |_| {
            return out;
        } else |_| {
            gpa.free(out);
        }
    } else |_| {}

    return null;
}

pub fn parseWwwAuthenticateTenantIdAlloc(gpa: Allocator, header_value: []const u8) ?[]u8 {
    var in_bearer = false;
    var i: usize = 0;
    while (i < header_value.len) {
        while (i < header_value.len and (header_value[i] == ' ' or header_value[i] == '\t' or header_value[i] == ',')) {
            i += 1;
        }
        if (i >= header_value.len) break;

        const tok_start = i;
        while (i < header_value.len and isAuthTokenChar(header_value[i])) {
            i += 1;
        }
        if (i == tok_start) {
            i += 1;
            continue;
        }
        const token = header_value[tok_start..i];

        while (i < header_value.len and (header_value[i] == ' ' or header_value[i] == '\t')) {
            i += 1;
        }

        if (i >= header_value.len or header_value[i] != '=') {
            in_bearer = std.ascii.eqlIgnoreCase(token, "Bearer");
            continue;
        }

        i += 1;
        while (i < header_value.len and (header_value[i] == ' ' or header_value[i] == '\t')) {
            i += 1;
        }
        if (i >= header_value.len) break;

        var raw_val: []const u8 = "";
        if (header_value[i] == '"') {
            i += 1;
            const val_start = i;
            while (i < header_value.len and header_value[i] != '"') {
                if (header_value[i] == '\\' and i + 1 < header_value.len) {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            raw_val = header_value[val_start..i];
            if (i < header_value.len and header_value[i] == '"') i += 1;
        } else {
            const val_start = i;
            while (i < header_value.len and header_value[i] != ',' and header_value[i] != ' ' and header_value[i] != '\t') {
                i += 1;
            }
            raw_val = header_value[val_start..i];
        }

        if (!in_bearer) continue;

        if (std.ascii.eqlIgnoreCase(token, "tenant") or std.ascii.eqlIgnoreCase(token, "tenant_id")) {
            if (ado.normalizeEntraTenantIdAlloc(gpa, raw_val)) |tid| {
                return tid;
            } else |_| {}
        } else if (std.ascii.eqlIgnoreCase(token, "authorization_uri") or std.ascii.eqlIgnoreCase(token, "authorization")) {
            if (extractTenantFromAuthorityUrlAlloc(gpa, raw_val)) |tid| {
                return tid;
            }
        }
    }
    return null;
}

fn isAuthTokenChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or switch (c) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

fn extractTenantFromAuthorityUrlAlloc(gpa: Allocator, raw_url: []const u8) ?[]u8 {
    const trimmed = std.mem.trim(u8, raw_url, " \t\r\n");
    if (!std.ascii.startsWithIgnoreCase(trimmed, "https://")) return null;
    const after_scheme = trimmed["https://".len..];
    const slash_idx = std.mem.indexOfScalar(u8, after_scheme, '/') orelse return null;
    const host = after_scheme[0..slash_idx];
    const trusted_hosts = [_][]const u8{
        "login.microsoftonline.com",
        "login.microsoftonline.us",
        "login.chinacloudapi.cn",
        "login.microsoftonline.de",
        "sts.windows.net",
    };
    var trusted = false;
    for (trusted_hosts) |th| {
        if (std.ascii.eqlIgnoreCase(host, th)) {
            trusted = true;
            break;
        }
    }
    if (!trusted) return null;

    var path = after_scheme[slash_idx + 1 ..];
    while (path.len > 0 and path[0] == '/') path = path[1..];
    var seg_end: usize = 0;
    while (seg_end < path.len and path[seg_end] != '/' and path[seg_end] != '?' and path[seg_end] != '#') {
        seg_end += 1;
    }
    if (seg_end == 0) return null;
    return ado.normalizeEntraTenantIdAlloc(gpa, path[0..seg_end]) catch null;
}

pub fn liveDiscoverAcrTenant(gpa: Allocator, server: []const u8) ?[]u8 {
    const url = std.fmt.allocPrint(gpa, "https://{s}/v2/", .{server}) catch return null;
    defer gpa.free(url);
    const uri = std.Uri.parse(url) catch return null;

    var client: std.http.Client = .{
        .allocator = gpa,
        .io = Io.Threaded.global_single_threaded.io(),
    };
    defer client.deinit();

    var req = client.request(.GET, uri, .{
        .redirect_behavior = .unhandled,
    }) catch return null;
    defer req.deinit();

    req.sendBodiless() catch return null;
    const response = req.receiveHead(&.{}) catch return null;

    var it = response.head.iterateHeaders();
    while (it.next()) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, "www-authenticate")) {
            if (parseWwwAuthenticateTenantIdAlloc(gpa, hdr.value)) |tid| {
                return tid;
            }
        }
    }
    return null;
}

pub const AcrExchangeRequest = struct {
    url: []u8,
    form_body: []u8,

    pub fn deinit(self: *const AcrExchangeRequest, gpa: Allocator) void {
        gpa.free(self.url);
        std.crypto.secureZero(u8, self.form_body);
        gpa.free(self.form_body);
    }
};

pub fn buildAcrExchangeRequest(
    gpa: Allocator,
    server: []const u8,
    arm_access_token: []const u8,
    tenant_id: ?[]const u8,
) Error!AcrExchangeRequest {
    const service_host = try extractHostWithoutPort(server);
    const url = try std.fmt.allocPrint(gpa, "https://{s}/oauth2/exchange", .{server});
    errdefer gpa.free(url);

    var body = Io.Writer.Allocating.init(gpa);
    errdefer body.deinit();
    try writeFormField(&body.writer, "grant_type", "access_token", true);
    try writeFormField(&body.writer, "service", service_host, false);
    if (tenant_id) |tid| {
        if (tid.len > 0) {
            try writeFormField(&body.writer, "tenant", tid, false);
        }
    }
    try writeFormField(&body.writer, "access_token", arm_access_token, false);

    const form_body = body.toOwnedSlice() catch return error.OutOfMemory;
    return .{
        .url = url,
        .form_body = form_body,
    };
}

const AcrExchangeResponse = struct {
    refresh_token: ?[]const u8 = null,
};

pub fn liveExchangeAcrToken(
    gpa: Allocator,
    server: []const u8,
    arm_access_token: []const u8,
    tenant_id: ?[]const u8,
) Error![]u8 {
    const req = try buildAcrExchangeRequest(gpa, server, arm_access_token, tenant_id);
    defer req.deinit(gpa);

    var response = Io.Writer.Allocating.init(gpa);
    defer {
        std.crypto.secureZero(u8, response.written());
        response.deinit();
    }

    var client: std.http.Client = .{
        .allocator = gpa,
        .io = Io.Threaded.global_single_threaded.io(),
    };
    defer client.deinit();

    const result = client.fetch(.{
        .location = .{ .url = req.url },
        .method = .POST,
        .payload = req.form_body,
        .headers = .{ .content_type = .{ .override = "application/x-www-form-urlencoded" } },
        .redirect_behavior = .not_allowed,
        .response_writer = &response.writer,
    }) catch return error.NetworkFailure;

    if (result.status.class() != .success) return error.AuthenticationFailed;

    var parsed = std.json.parseFromSlice(AcrExchangeResponse, gpa, response.written(), .{
        .ignore_unknown_fields = true,
    }) catch return error.AuthenticationFailed;
    defer parsed.deinit();

    const rt = parsed.value.refresh_token orelse return error.AuthenticationFailed;
    if (rt.len == 0) return error.AuthenticationFailed;
    return gpa.dupe(u8, rt);
}

fn writeFormField(writer: *Io.Writer, key: []const u8, value: []const u8, first: bool) Error!void {
    if (!first) writer.writeByte('&') catch return error.OutOfMemory;
    try writePercentEncodedForm(writer, key);
    writer.writeByte('=') catch return error.OutOfMemory;
    try writePercentEncodedForm(writer, value);
}

fn writePercentEncodedForm(writer: *Io.Writer, value: []const u8) Error!void {
    const hex = "0123456789ABCDEF";
    for (value) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            writer.writeByte(c) catch return error.OutOfMemory;
        } else if (c == ' ') {
            writer.writeByte('+') catch return error.OutOfMemory;
        } else {
            writer.writeByte('%') catch return error.OutOfMemory;
            writer.writeByte(hex[c >> 4]) catch return error.OutOfMemory;
            writer.writeByte(hex[c & 0x0f]) catch return error.OutOfMemory;
        }
    }
}

// ---------------------------------------------------------------------------
// Deterministic Generic Keyring Store + Non-Secret Registry Index
// ---------------------------------------------------------------------------

const RegistryIndexDocument = struct {
    registries: std.json.ArrayHashMap([]const u8) = .{},
};

pub fn genericRegistryServiceAlloc(gpa: Allocator, bare_host: []const u8) Error![]u8 {
    return std.fmt.allocPrint(gpa, "{s}{s}", .{ generic_service_prefix, bare_host });
}

fn mapKeyringError(err: keyring_zig.Error) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.EntryNotFound => error.EntryNotFound,
        error.Locked => error.Locked,
        error.NoStorageAccess => error.NoStorageAccess,
        else => error.StorageFailure,
    };
}

fn mapProviderError(err: credential_provider.ProviderError) Error {
    return switch (err) {
        error.CredentialNotFound => error.EntryNotFound,
        error.ReauthenticationRequired => error.AuthenticationFailed,
        error.StorageUnavailable, error.AccessDenied => error.NoStorageAccess,
        error.StorageLocked => error.Locked,
        error.InvalidInput => error.InvalidInput,
        error.OutOfMemory => error.OutOfMemory,
        error.StorageFailure,
        error.UnsupportedTarget,
        error.UnsupportedOperation,
        error.Cancelled,
        error.DeadlineExceeded,
        => error.StorageFailure,
    };
}

fn activeGenericKeyringAdapter() stored_provider.KeyringOpsAdapter {
    if (generic_store_override) |override| {
        return .{
            .ops = .{
                .get = override.get,
                .set = override.set,
                .delete = override.delete,
            },
            .enforce_secure_backend = false,
        };
    }
    return .{
        .ops = stored_provider.live_keyring_ops,
        .enforce_secure_backend = true,
    };
}

fn parseRegistryTargetAlloc(gpa: Allocator, bare_host: []const u8) Error!credential_provider.Target {
    return credential_provider.Target.parseAlloc(gpa, bare_host, .{
        .default_scheme = "https",
    }) catch |err| switch (err) {
        error.InvalidInput => error.InvalidServer,
        else => mapProviderError(err),
    };
}

/// Store `(username, secret)` deterministically in `keyring_zig` under
/// `service = "container-registry://<bare_host>"`, `account = "default"` and
/// record `<bare_host> -> <username>` in `<state_dir>/registries.json` (zero secrets).
pub fn storeGenericCredential(
    gpa: Allocator,
    raw_or_norm_server: []const u8,
    username: []const u8,
    secret: []const u8,
) Error!void {
    if (username.len == 0 or secret.len == 0) return error.InvalidInput;
    for (username) |c| {
        if (c == 0 or std.ascii.isControl(c)) return error.InvalidInput;
    }
    if (std.mem.indexOfScalar(u8, secret, 0) != null) return error.InvalidInput;

    const bare_host = try normalizeServerAlloc(gpa, raw_or_norm_server, .bare_docker_io);
    defer gpa.free(bare_host);

    var target = try parseRegistryTargetAlloc(gpa, bare_host);
    defer target.deinit(gpa);

    const known_exp = extractJwtExpiration(gpa, secret);
    const is_identity_token = std.mem.eql(u8, username, identity_token_username);
    var cred_in: credential_provider.CredentialResult = blk_cred: {
        var cred_secret: credential_provider.CredentialSecret = if (is_identity_token) .{
            .identity_token = try gpa.dupe(u8, secret),
        } else .{
            .basic = blk_basic: {
                const user_copy = try gpa.dupe(u8, username);
                errdefer gpa.free(user_copy);
                const sec_copy = try gpa.dupe(u8, secret);
                break :blk_basic .{
                    .username = user_copy,
                    .secret = sec_copy,
                };
            },
        };
        errdefer cred_secret.deinit(gpa);

        const account_copy: ?[]u8 = if (is_identity_token) null else try gpa.dupe(u8, username);
        break :blk_cred .{
            .secret = cred_secret,
            .account = account_copy,
            .expires_at = known_exp,
            .cache_policy = if (known_exp != null) .until_expiration else .eternal,
            .audience = null,
            .scopes = null,
            .supports_noninteractive_renewal = false,
        };
    };
    defer cred_in.deinit(gpa);

    const adapter = activeGenericKeyringAdapter();
    const stored = stored_provider.StoredCredentialProvider.initContainerRegistry(adapter.backend());
    const deadline: credential_provider.Deadline = if (now_seconds_override_fn != null)
        .{ .now_ms_fn = genericLookupNowMs }
    else
        .{};

    var saved = stored.login(gpa, .{
        .request = .{
            .target = target,
            .operation = .login,
            .account = if (is_identity_token) null else username,
            .interaction = .never,
            .deadline = deadline,
        },
        .credential = &cred_in,
    }) catch |err| return mapProviderError(err);
    saved.deinit(gpa);

    try upsertRegistryIndex(gpa, bare_host, username);
}

pub const GenericLookupSource = enum {
    primary_container_registry,
    legacy_https_service,
};

pub const GenericLookupResult = struct {
    credential: RegistryCredential,
    source: GenericLookupSource,
};

fn hasAsciiControl(s: []const u8) bool {
    for (s) |c| {
        if (c == 0 or std.ascii.isControl(c)) return true;
    }
    return false;
}

/// Retrieve a stored generic registry credential evaluated against an optional
/// caller-supplied `now_seconds` clock, along with whether it came from
/// `container-registry://<bare_host>` (`primary_container_registry`) or a legacy
/// `https://<host>` fallback (`legacy_https_service`).
pub fn getGenericCredentialDetailedAt(
    gpa: Allocator,
    raw_or_norm_server: []const u8,
    requested_username: ?[]const u8,
    now_seconds: ?i64,
) Error!GenericLookupResult {
    const bare_host = try normalizeServerAlloc(gpa, raw_or_norm_server, .bare_docker_io);
    defer gpa.free(bare_host);

    var target = try parseRegistryTargetAlloc(gpa, bare_host);
    defer target.deinit(gpa);

    const effective_now: ?i64 = now_seconds orelse if (now_seconds_override_fn) |f| f() else null;
    const prev_scoped_ms = scoped_now_ms_override;
    scoped_now_ms_override = if (effective_now) |sec| secondsToClampedMs(sec) else null;
    defer scoped_now_ms_override = prev_scoped_ms;

    const deadline: credential_provider.Deadline = if (effective_now != null)
        .{ .now_ms_fn = genericLookupNowMs }
    else
        .{};

    const adapter = activeGenericKeyringAdapter();
    const stored = stored_provider.StoredCredentialProvider.initContainerRegistry(adapter.backend());

    var primary_miss_err: Error = error.EntryNotFound;

    const req_account: ?[]const u8 = if (requested_username) |u|
        (if (u.len > 0 and !hasAsciiControl(u)) u else null)
    else
        null;

    if (stored.get(gpa, .{
        .target = target,
        .operation = .get,
        .account = req_account,
        .interaction = .never,
        .deadline = deadline,
    })) |res_val| {
        var res = res_val;
        defer res.deinit(gpa);

        const MappedSecret = struct {
            kind: CredentialKind,
            username: []const u8,
            secret: []const u8,
        };
        const mapped: MappedSecret = switch (res.secret) {
            .basic => |b| blk: {
                if (std.mem.eql(u8, b.username, identity_token_username)) {
                    return error.StorageFailure;
                }
                break :blk .{
                    .kind = .basic,
                    .username = b.username,
                    .secret = b.secret,
                };
            },
            .identity_token => |tok| .{
                .kind = .identity_token,
                .username = identity_token_username,
                .secret = tok,
            },
            .bearer_token => return error.StorageFailure,
        };

        if (requested_username == null or std.mem.eql(u8, mapped.username, requested_username.?)) {
            const server_copy = try gpa.dupe(u8, bare_host);
            errdefer gpa.free(server_copy);
            const user_copy = try gpa.dupe(u8, mapped.username);
            errdefer gpa.free(user_copy);
            const secret_copy = try gpa.dupe(u8, mapped.secret);
            errdefer {
                std.crypto.secureZero(u8, secret_copy);
                gpa.free(secret_copy);
            }
            return .{
                .credential = .{
                    .kind = mapped.kind,
                    .server = server_copy,
                    .username = user_copy,
                    .secret = secret_copy,
                    .expires_at = res.expires_at orelse extractJwtExpiration(gpa, secret_copy),
                },
                .source = .primary_container_registry,
            };
        }
    } else |err| switch (err) {
        error.CredentialNotFound => primary_miss_err = error.EntryNotFound,
        error.ReauthenticationRequired => primary_miss_err = error.AuthenticationFailed,
        else => return mapProviderError(err),
    }

    const ops = activeGenericStoreOps();
    if (requested_username) |user| {
        if (user.len > 0) {
            const https_svc = try std.fmt.allocPrint(gpa, "https://{s}", .{bare_host});
            defer gpa.free(https_svc);
            if (ops.get(gpa, https_svc, user)) |secret| {
                errdefer {
                    std.crypto.secureZero(u8, secret);
                    gpa.free(secret);
                }
                const server_copy = try gpa.dupe(u8, bare_host);
                errdefer gpa.free(server_copy);
                const user_copy = try gpa.dupe(u8, user);
                return .{
                    .credential = .{
                        .kind = if (std.mem.eql(u8, user, identity_token_username)) .identity_token else .basic,
                        .server = server_copy,
                        .username = user_copy,
                        .secret = secret,
                        .expires_at = extractJwtExpiration(gpa, secret),
                    },
                    .source = .legacy_https_service,
                };
            } else |err| switch (err) {
                error.EntryNotFound => {},
                else => return mapKeyringError(err),
            }

            if (std.mem.eql(u8, bare_host, docker_hub_bare_host)) {
                if (ops.get(gpa, docker_hub_legacy_url, user)) |secret| {
                    errdefer {
                        std.crypto.secureZero(u8, secret);
                        gpa.free(secret);
                    }
                    const server_copy = try gpa.dupe(u8, bare_host);
                    errdefer gpa.free(server_copy);
                    const user_copy = try gpa.dupe(u8, user);
                    return .{
                        .credential = .{
                            .kind = if (std.mem.eql(u8, user, identity_token_username)) .identity_token else .basic,
                            .server = server_copy,
                            .username = user_copy,
                            .secret = secret,
                            .expires_at = extractJwtExpiration(gpa, secret),
                        },
                        .source = .legacy_https_service,
                    };
                } else |err| switch (err) {
                    error.EntryNotFound => {},
                    else => return mapKeyringError(err),
                }
            }
        }
    }

    return primary_miss_err;
}

/// Retrieve a stored generic registry credential along with whether it came from
/// `container-registry://<bare_host>` (`primary_container_registry`) or a legacy
/// `https://<host>` fallback (`legacy_https_service`).
pub fn getGenericCredentialDetailed(
    gpa: Allocator,
    raw_or_norm_server: []const u8,
    requested_username: ?[]const u8,
) Error!GenericLookupResult {
    return getGenericCredentialDetailedAt(
        gpa,
        raw_or_norm_server,
        requested_username,
        if (now_seconds_override_fn) |f| f() else null,
    );
}

/// Retrieve a stored generic registry credential for `raw_or_norm_server`,
/// checking `container-registry://<bare_host>` (`account = "default"`) first,
/// then falling back to `https://<bare_host>` (and `https://index.docker.io/v1/`
/// for Docker Hub) when `requested_username` is provided.
pub fn getGenericCredential(
    gpa: Allocator,
    raw_or_norm_server: []const u8,
    requested_username: ?[]const u8,
) Error!RegistryCredential {
    return (try getGenericCredentialDetailed(gpa, raw_or_norm_server, requested_username)).credential;
}

/// Delete any generic credential stored for `raw_or_norm_server` and remove it
/// from `registries.json`. Returns `error.EntryNotFound` only if absent in both.
pub fn deleteGenericCredential(gpa: Allocator, raw_or_norm_server: []const u8) Error!void {
    const bare_host = try normalizeServerAlloc(gpa, raw_or_norm_server, .bare_docker_io);
    defer gpa.free(bare_host);

    var target = try parseRegistryTargetAlloc(gpa, bare_host);
    defer target.deinit(gpa);

    const adapter = activeGenericKeyringAdapter();
    const stored = stored_provider.StoredCredentialProvider.initContainerRegistry(adapter.backend());

    var found_keyring = true;
    stored.logout(gpa, .{
        .target = target,
        .operation = .logout,
        .interaction = .never,
    }) catch |err| switch (err) {
        error.CredentialNotFound => found_keyring = false,
        else => return mapProviderError(err),
    };

    const removed_index = try removeRegistryIndex(gpa, bare_host);
    if (!found_keyring and !removed_index) {
        return error.EntryNotFound;
    }
}

pub fn listGenericIndexAlloc(gpa: Allocator) Error![]RegistryIndexEntry {
    const state_dir = resolveKeyringStateDir(gpa) orelse return gpa.alloc(RegistryIndexEntry, 0);
    defer gpa.free(state_dir);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const index_path = try std.fs.path.join(a, &.{ state_dir, registries_index_filename });
    const bytes = (try readFileIfExists(a, index_path)) orelse return gpa.alloc(RegistryIndexEntry, 0);
    if (bytes.len == 0) return gpa.alloc(RegistryIndexEntry, 0);

    const doc = std.json.parseFromSliceLeaky(RegistryIndexDocument, a, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.StorageFailure;

    var out = try std.ArrayList(RegistryIndexEntry).initCapacity(gpa, doc.registries.map.count());
    errdefer {
        for (out.items) |*item| item.deinit(gpa);
        out.deinit(gpa);
    }

    var it = doc.registries.map.iterator();
    while (it.next()) |kv| {
        if (kv.key_ptr.*.len == 0 or kv.value_ptr.*.len == 0) continue;
        const srv = try gpa.dupe(u8, kv.key_ptr.*);
        errdefer gpa.free(srv);
        const usr = try gpa.dupe(u8, kv.value_ptr.*);
        try out.append(gpa, .{ .server = srv, .username = usr });
    }
    return out.toOwnedSlice(gpa);
}

fn upsertRegistryIndex(gpa: Allocator, bare_host: []const u8, username: []const u8) Error!void {
    const state_dir = resolveKeyringStateDir(gpa) orelse return error.NoStorageAccess;
    defer gpa.free(state_dir);

    const lock_path = try std.fs.path.join(gpa, &.{ state_dir, registries_lock_filename });
    defer gpa.free(lock_path);
    var lock = try acquireLockFile(lock_path);
    defer lock.release();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const index_path = try std.fs.path.join(a, &.{ state_dir, registries_index_filename });
    var doc: RegistryIndexDocument = .{};
    if (try readFileIfExists(a, index_path)) |bytes| {
        if (bytes.len > 0) {
            doc = std.json.parseFromSliceLeaky(RegistryIndexDocument, a, bytes, .{
                .ignore_unknown_fields = true,
                .allocate = .alloc_always,
            }) catch return error.StorageFailure;
        }
    }

    try doc.registries.map.put(a, bare_host, username);
    const serialized = std.json.Stringify.valueAlloc(a, doc, .{
        .whitespace = .indent_2,
    }) catch return error.OutOfMemory;
    try writeProtectedFileAtomic(a, index_path, serialized);
}

fn removeRegistryIndex(gpa: Allocator, bare_host: []const u8) Error!bool {
    const state_dir = resolveKeyringStateDir(gpa) orelse return false;
    defer gpa.free(state_dir);

    const index_check = try std.fs.path.join(gpa, &.{ state_dir, registries_index_filename });
    defer gpa.free(index_check);

    const lock_path = try std.fs.path.join(gpa, &.{ state_dir, registries_lock_filename });
    defer gpa.free(lock_path);
    var lock = acquireLockFile(lock_path) catch |err| {
        const io = Io.Threaded.global_single_threaded.io();
        Io.Dir.cwd().access(io, index_check, .{}) catch return false;
        return err;
    };
    defer lock.release();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const bytes = (try readFileIfExists(a, index_check)) orelse return false;
    if (bytes.len == 0) return false;

    var doc = std.json.parseFromSliceLeaky(RegistryIndexDocument, a, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.StorageFailure;

    if (!doc.registries.map.orderedRemove(bare_host)) {
        return false;
    }

    const serialized = std.json.Stringify.valueAlloc(a, doc, .{
        .whitespace = .indent_2,
    }) catch return error.OutOfMemory;
    try writeProtectedFileAtomic(a, index_check, serialized);
    return true;
}

// ---------------------------------------------------------------------------
// Docker / Podman Credential Helper Wire Protocol
// ---------------------------------------------------------------------------

const RawHelperStoreInput = struct {
    ServerURL: ?[]const u8 = null,
    Username: ?[]const u8 = null,
    Secret: ?[]const u8 = null,
};

const RawHelperGetOutput = struct {
    ServerURL: []const u8,
    Username: []const u8,
    Secret: []const u8,
};

pub fn readBoundedStdinAll(gpa: Allocator, stdin: *Io.Reader, max_bytes: usize) Error![]u8 {
    var buffer: std.ArrayList(u8) = .empty;
    errdefer {
        std.crypto.secureZero(u8, buffer.items);
        buffer.deinit(gpa);
    }
    stdin.appendRemaining(gpa, &buffer, .limited(max_bytes)) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidInput,
    };
    if (buffer.items.len == 0) {
        return error.InvalidInput;
    }
    return buffer.toOwnedSlice(gpa) catch error.OutOfMemory;
}

pub fn readBoundedStdinLine(gpa: Allocator, stdin: *Io.Reader, max_bytes: usize) Error![]u8 {
    const raw = try readBoundedStdinAll(gpa, stdin, max_bytes);
    errdefer {
        std.crypto.secureZero(u8, raw);
        gpa.free(raw);
    }

    var slice: []const u8 = raw;
    if (std.mem.endsWith(u8, slice, "\n")) {
        slice = slice[0 .. slice.len - 1];
    }
    if (std.mem.endsWith(u8, slice, "\r")) {
        slice = slice[0 .. slice.len - 1];
    }
    if (slice.len == 0 or
        std.mem.indexOfScalar(u8, slice, 0) != null or
        std.mem.indexOfAny(u8, slice, "\r\n") != null)
    {
        return error.InvalidInput;
    }

    const out = try gpa.dupe(u8, slice);
    std.crypto.secureZero(u8, raw);
    gpa.free(raw);
    return out;
}

pub fn parseHelperStoreStdinAlloc(gpa: Allocator, stdin: *Io.Reader) Error!HelperStorePayload {
    const raw_json = try readBoundedStdinAll(gpa, stdin, max_helper_input_bytes);
    defer {
        std.crypto.secureZero(u8, raw_json);
        gpa.free(raw_json);
    }

    const parsed = std.json.parseFromSlice(RawHelperStoreInput, gpa, raw_json, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidInput;
    defer parsed.deinit();

    const srv = parsed.value.ServerURL orelse return error.InvalidInput;
    const user = parsed.value.Username orelse return error.InvalidInput;
    const sec = parsed.value.Secret orelse return error.InvalidInput;
    if (srv.len == 0 or user.len == 0 or sec.len == 0 or
        std.mem.indexOfScalar(u8, srv, 0) != null or
        std.mem.indexOfScalar(u8, user, 0) != null or
        std.mem.indexOfScalar(u8, sec, 0) != null)
    {
        return error.InvalidInput;
    }

    const srv_copy = try gpa.dupe(u8, srv);
    errdefer gpa.free(srv_copy);
    const user_copy = try gpa.dupe(u8, user);
    errdefer gpa.free(user_copy);
    const sec_copy = try gpa.dupe(u8, sec);

    return .{
        .server_url = srv_copy,
        .username = user_copy,
        .secret = sec_copy,
    };
}

pub fn writeHelperGetResponse(
    gpa: Allocator,
    stdout: *Io.Writer,
    server_url: []const u8,
    username: []const u8,
    secret: []const u8,
) !void {
    const json_out = try std.json.Stringify.valueAlloc(gpa, RawHelperGetOutput{
        .ServerURL = server_url,
        .Username = username,
        .Secret = secret,
    }, .{});
    defer {
        std.crypto.secureZero(u8, json_out);
        gpa.free(json_out);
    }

    try stdout.writeAll(json_out);
    try stdout.writeByte('\n');
    try stdout.flush();
}

pub fn writeHelperListResponse(
    gpa: Allocator,
    stdout: *Io.Writer,
    entries: []const RegistryIndexEntry,
) !void {
    var map: std.json.ArrayHashMap([]const u8) = .{};
    defer map.deinit(gpa);

    for (entries) |entry| {
        try map.map.put(gpa, entry.server, entry.username);
    }

    const json_out = try std.json.Stringify.valueAlloc(gpa, map, .{});
    defer gpa.free(json_out);

    try stdout.writeAll(json_out);
    try stdout.writeByte('\n');
    try stdout.flush();
}

// ---------------------------------------------------------------------------
// Keyring State Dir, File Locking, & User-Restricted Atomic File Writes
// ---------------------------------------------------------------------------

pub fn resolveKeyringStateDir(gpa: Allocator) ?[]u8 {
    if (state_dir_override) |override| {
        return gpa.dupe(u8, override) catch null;
    }
    if (builtin.os.tag == .windows) {
        if (getEnvVarOwned(gpa, "LOCALAPPDATA")) |lad| {
            defer gpa.free(lad);
            if (lad.len > 0) return std.fs.path.join(gpa, &.{ lad, "keyring" }) catch null;
        }
        if (getEnvVarOwned(gpa, "USERPROFILE")) |profile| {
            defer gpa.free(profile);
            if (profile.len > 0) return std.fs.path.join(gpa, &.{ profile, "AppData", "Local", "keyring" }) catch null;
        }
    } else {
        if (getEnvVarOwned(gpa, "XDG_DATA_HOME")) |xdg| {
            defer gpa.free(xdg);
            if (xdg.len > 0 and xdg[0] == '/') {
                return std.fs.path.join(gpa, &.{ xdg, "keyring" }) catch null;
            }
        }
        if (getHomeDir(gpa)) |home| {
            defer gpa.free(home);
            if (builtin.os.tag == .macos) {
                return std.fs.path.join(gpa, &.{ home, "Library", "Application Support", "keyring" }) catch null;
            }
            return std.fs.path.join(gpa, &.{ home, ".local", "share", "keyring" }) catch null;
        }
    }
    return null;
}

pub fn getHomeDir(gpa: Allocator) ?[]u8 {
    if (builtin.os.tag == .windows) {
        if (getEnvVarOwned(gpa, "USERPROFILE")) |p| {
            if (p.len > 0) return p;
            gpa.free(p);
        }
        if (getEnvVarOwned(gpa, "HOME")) |h| {
            if (h.len > 0) return h;
            gpa.free(h);
        }
        if (env_override_fn != null) return null;
        return msal_cache.getHome(gpa);
    }
    if (getEnvVarOwned(gpa, "HOME")) |h| {
        if (h.len > 0) return h;
        gpa.free(h);
    }
    if (env_override_fn != null) return null;
    return msal_cache.getHome(gpa);
}

pub fn getEnvVarOwned(gpa: Allocator, name: []const u8) ?[]u8 {
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
    var idx: usize = 0;
    while (std.c.environ[idx]) |entry_ptr| : (idx += 1) {
        const entry = std.mem.span(entry_ptr);
        if (entry.len > name.len and entry[name.len] == '=' and std.mem.eql(u8, entry[0..name.len], name)) {
            return gpa.dupe(u8, entry[name.len + 1 ..]) catch null;
        }
    }
    return null;
}

pub const FileLock = struct {
    file: Io.File,

    pub fn release(self: *FileLock) void {
        const io = Io.Threaded.global_single_threaded.io();
        self.file.unlock(io);
        self.file.close(io);
    }
};

const fs_max_attempts: usize = 5;

pub fn isTransientFsError(err: anyerror) bool {
    return switch (err) {
        error.AccessDenied,
        error.PermissionDenied,
        error.LockViolation,
        error.FileBusy,
        error.AntivirusInterference,
        error.WouldBlock,
        error.PipeBusy,
        error.DeviceBusy,
        => true,
        else => false,
    };
}

pub fn sleepRetryMs(ms: u32) void {
    const io = Io.Threaded.global_single_threaded.io();
    Io.Clock.Duration.sleep(.{ .clock = .awake, .raw = .fromMilliseconds(ms) }, io) catch {};
}

pub fn acquireLockFile(lock_path: []const u8) Error!FileLock {
    const io = Io.Threaded.global_single_threaded.io();
    if (std.fs.path.dirname(lock_path)) |parent| {
        if (parent.len > 0) {
            _ = Io.Dir.cwd().createDirPathStatus(io, parent, dirPermissions()) catch return error.StorageFailure;
        }
    }

    var delay_ms: u32 = 10;
    var attempt: usize = 0;
    const file = while (true) : (attempt += 1) {
        if (Io.Dir.cwd().createFile(io, lock_path, .{
            .truncate = false,
            .read = true,
            .permissions = filePermissions(),
        })) |f| {
            break f;
        } else |err| {
            if (attempt + 1 < fs_max_attempts and isTransientFsError(err)) {
                sleepRetryMs(delay_ms);
                delay_ms *= 2;
                continue;
            }
            return error.StorageFailure;
        }
    };

    file.lock(io, .exclusive) catch {
        file.close(io);
        return error.StorageFailure;
    };
    return .{ .file = file };
}

pub fn readFileIfExists(gpa: Allocator, path: []const u8) Error!?[]u8 {
    const io = Io.Threaded.global_single_threaded.io();
    var delay_ms: u32 = 10;
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        if (Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(4 * 1024 * 1024))) |bytes| {
            return bytes;
        } else |err| {
            if (err == error.FileNotFound) return null;
            if (err == error.OutOfMemory) return error.OutOfMemory;
            if (attempt + 1 < fs_max_attempts and isTransientFsError(err)) {
                sleepRetryMs(delay_ms);
                delay_ms *= 2;
                continue;
            }
            return error.StorageFailure;
        }
    }
}

pub fn writeProtectedFileAtomic(gpa: Allocator, path: []const u8, contents: []const u8) Error!void {
    const io = Io.Threaded.global_single_threaded.io();
    if (std.fs.path.dirname(path)) |parent| {
        if (parent.len > 0) {
            _ = Io.Dir.cwd().createDirPathStatus(io, parent, dirPermissions()) catch return error.StorageFailure;
        }
    }

    var suffix_bytes: [8]u8 = undefined;
    io.random(&suffix_bytes);
    const suffix_hex = std.fmt.bytesToHex(suffix_bytes, .lower);
    const tmp = try std.fmt.allocPrint(gpa, "{s}.{s}.tmp", .{ path, suffix_hex });
    defer gpa.free(tmp);

    {
        const empty_file = Io.Dir.cwd().createFile(io, tmp, .{
            .truncate = true,
            .permissions = filePermissions(),
        }) catch return error.StorageFailure;
        empty_file.close(io);
    }

    if (builtin.os.tag == .windows) {
        restrictFileToCurrentUserWindows(gpa, tmp) catch {
            Io.Dir.cwd().deleteFile(io, tmp) catch {};
            return error.StorageFailure;
        };
    }

    {
        var file = Io.Dir.cwd().createFile(io, tmp, .{
            .truncate = false,
            .permissions = filePermissions(),
        }) catch {
            Io.Dir.cwd().deleteFile(io, tmp) catch {};
            return error.StorageFailure;
        };
        defer file.close(io);
        file.writeStreamingAll(io, contents) catch {
            Io.Dir.cwd().deleteFile(io, tmp) catch {};
            return error.StorageFailure;
        };
    }

    var delay_ms: u32 = 10;
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        if (Io.Dir.cwd().rename(tmp, Io.Dir.cwd(), path, io)) |_| {
            break;
        } else |err| {
            if (attempt + 1 < fs_max_attempts and isTransientFsError(err)) {
                sleepRetryMs(delay_ms);
                delay_ms *= 2;
                continue;
            }
            Io.Dir.cwd().deleteFile(io, tmp) catch {};
            return error.StorageFailure;
        }
    }

    if (builtin.os.tag == .windows) {
        restrictFileToCurrentUserWindows(gpa, path) catch {};
    }
}

pub fn dirPermissions() Io.File.Permissions {
    return if (builtin.os.tag == .windows or builtin.os.tag == .wasi) .default_dir else .fromMode(0o700);
}

pub fn filePermissions() Io.File.Permissions {
    return if (builtin.os.tag == .windows or builtin.os.tag == .wasi) .default_file else .fromMode(0o600);
}

// ---------------------------------------------------------------------------
// Windows Current-User Protected DACL (`0600` equivalent)
// ---------------------------------------------------------------------------

const win32_acl = if (builtin.os.tag == .windows) struct {
    const HANDLE = std.os.windows.HANDLE;
    const BOOL = std.os.windows.BOOL;
    const DWORD = u32;
    const LPCWSTR = [*:0]const u16;
    const PVOID = *anyopaque;

    const TOKEN_QUERY: DWORD = 0x0008;
    const TokenUser: u32 = 1;
    const ACL_REVISION: DWORD = 2;
    const FILE_ALL_ACCESS: DWORD = 0x001F01FF;
    const SE_FILE_OBJECT: u32 = 1;
    const DACL_SECURITY_INFORMATION: DWORD = 0x00000004;
    const PROTECTED_DACL_SECURITY_INFORMATION: DWORD = 0x80000000;

    const SID_AND_ATTRIBUTES = extern struct {
        Sid: PVOID,
        Attributes: DWORD,
    };

    const TOKEN_USER = extern struct {
        User: SID_AND_ATTRIBUTES,
    };

    const ACL = extern struct {
        AclRevision: u8,
        Sbz1: u8,
        AclSize: u16,
        AceCount: u16,
        Sbz2: u16,
    };

    extern "kernel32" fn GetCurrentProcess() callconv(.winapi) HANDLE;
    extern "advapi32" fn OpenProcessToken(
        ProcessHandle: HANDLE,
        DesiredAccess: DWORD,
        TokenHandle: *HANDLE,
    ) callconv(.winapi) BOOL;
    extern "advapi32" fn GetTokenInformation(
        TokenHandle: HANDLE,
        TokenInformationClass: u32,
        TokenInformation: ?PVOID,
        TokenInformationLength: DWORD,
        ReturnLength: *DWORD,
    ) callconv(.winapi) BOOL;
    extern "advapi32" fn IsValidSid(pSid: PVOID) callconv(.winapi) BOOL;
    extern "advapi32" fn GetLengthSid(pSid: PVOID) callconv(.winapi) DWORD;
    extern "advapi32" fn InitializeAcl(
        pAcl: *ACL,
        nAclLength: DWORD,
        dwAclRevision: DWORD,
    ) callconv(.winapi) BOOL;
    extern "advapi32" fn AddAccessAllowedAce(
        pAcl: *ACL,
        dwAceRevision: DWORD,
        AccessMask: DWORD,
        pSid: PVOID,
    ) callconv(.winapi) BOOL;
    extern "advapi32" fn SetNamedSecurityInfoW(
        pObjectName: LPCWSTR,
        ObjectType: u32,
        SecurityInfo: DWORD,
        psidOwner: ?PVOID,
        psidGroup: ?PVOID,
        pDacl: ?*ACL,
        pSacl: ?PVOID,
    ) callconv(.winapi) DWORD;
    extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(.winapi) BOOL;
} else struct {};

pub fn restrictFileToCurrentUserWindows(gpa: Allocator, path: []const u8) Error!void {
    if (builtin.os.tag != .windows) return;

    var token: win32_acl.HANDLE = undefined;
    if (win32_acl.OpenProcessToken(win32_acl.GetCurrentProcess(), win32_acl.TOKEN_QUERY, &token) == .FALSE) {
        return error.StorageFailure;
    }
    defer _ = win32_acl.CloseHandle(token);

    var needed: win32_acl.DWORD = 0;
    _ = win32_acl.GetTokenInformation(token, win32_acl.TokenUser, null, 0, &needed);
    if (needed == 0 or needed > 16 * 1024) return error.StorageFailure;

    const token_buf = try gpa.alignedAlloc(u8, .of(win32_acl.TOKEN_USER), needed);
    defer gpa.free(token_buf);

    if (win32_acl.GetTokenInformation(token, win32_acl.TokenUser, token_buf.ptr, needed, &needed) == .FALSE) {
        return error.StorageFailure;
    }

    const token_user: *const win32_acl.TOKEN_USER = @ptrCast(token_buf.ptr);
    const user_sid = token_user.User.Sid;
    if (win32_acl.IsValidSid(user_sid) == .FALSE) return error.StorageFailure;

    const sid_len = win32_acl.GetLengthSid(user_sid);
    // ACL header (8 bytes) + ACCESS_ALLOWED_ACE header (8 bytes) + SID length, aligned to DWORD.
    const acl_len: win32_acl.DWORD = std.mem.alignForward(win32_acl.DWORD, @sizeOf(win32_acl.ACL) + 8 + sid_len, 4);
    const acl_buf = try gpa.alignedAlloc(u8, .of(win32_acl.ACL), acl_len);
    defer gpa.free(acl_buf);

    const acl_ptr: *win32_acl.ACL = @ptrCast(acl_buf.ptr);
    if (win32_acl.InitializeAcl(acl_ptr, acl_len, win32_acl.ACL_REVISION) == .FALSE) {
        return error.StorageFailure;
    }
    if (win32_acl.AddAccessAllowedAce(acl_ptr, win32_acl.ACL_REVISION, win32_acl.FILE_ALL_ACCESS, user_sid) == .FALSE) {
        return error.StorageFailure;
    }

    const path_w = std.unicode.utf8ToUtf16LeAllocZ(gpa, path) catch return error.StorageFailure;
    defer gpa.free(path_w);

    const status = win32_acl.SetNamedSecurityInfoW(
        path_w.ptr,
        win32_acl.SE_FILE_OBJECT,
        win32_acl.DACL_SECURITY_INFORMATION | win32_acl.PROTECTED_DACL_SECURITY_INFORMATION,
        null,
        null,
        acl_ptr,
        null,
    );
    if (status != 0) return error.StorageFailure;
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

const FakeGenericStore = struct {
    var map: ?std.StringHashMap([]u8) = null;
    var fail_access: bool = false;

    fn reset(gpa: Allocator) void {
        deinit(gpa);
        map = std.StringHashMap([]u8).init(gpa);
        fail_access = false;
    }

    fn deinit(gpa: Allocator) void {
        if (map) |*m| {
            var it = m.iterator();
            while (it.next()) |kv| {
                gpa.free(kv.key_ptr.*);
                std.crypto.secureZero(u8, kv.value_ptr.*);
                gpa.free(kv.value_ptr.*);
            }
            m.deinit();
            map = null;
        }
    }

    fn makeKey(gpa: Allocator, service: []const u8, account: []const u8) ![]u8 {
        return std.fmt.allocPrint(gpa, "{s}\x1f{s}", .{ service, account });
    }

    fn get(gpa: Allocator, service: []const u8, account: []const u8) keyring_zig.Error![]u8 {
        if (fail_access) return error.NoStorageAccess;
        const m = &(map orelse return error.EntryNotFound);
        const key = makeKey(gpa, service, account) catch return error.OutOfMemory;
        defer gpa.free(key);
        const val = m.get(key) orelse return error.EntryNotFound;
        return gpa.dupe(u8, val) catch error.OutOfMemory;
    }

    fn set(_: Allocator, service: []const u8, account: []const u8, password: []const u8) keyring_zig.Error!void {
        if (fail_access) return error.NoStorageAccess;
        var m = &(map orelse return error.PlatformFailure);
        const key = makeKey(m.allocator, service, account) catch return error.OutOfMemory;
        errdefer m.allocator.free(key);
        const val = m.allocator.dupe(u8, password) catch return error.OutOfMemory;
        errdefer m.allocator.free(val);

        if (m.fetchPut(key, val) catch return error.OutOfMemory) |prev| {
            m.allocator.free(key);
            std.crypto.secureZero(u8, prev.value);
            m.allocator.free(prev.value);
        }
    }

    fn delete(gpa: Allocator, service: []const u8, account: []const u8) keyring_zig.Error!void {
        if (fail_access) return error.NoStorageAccess;
        var m = &(map orelse return error.EntryNotFound);
        const key = makeKey(gpa, service, account) catch return error.OutOfMemory;
        defer gpa.free(key);
        const removed = m.fetchRemove(key) orelse return error.EntryNotFound;
        m.allocator.free(removed.key);
        std.crypto.secureZero(u8, removed.value);
        m.allocator.free(removed.value);
    }
};

test "normalizeServerAlloc distinguishes bare_docker_io and legacy_v1_url" {
    const gpa = std.testing.allocator;

    const bare1 = try normalizeServerAlloc(gpa, "https://index.docker.io/v1/", .bare_docker_io);
    defer gpa.free(bare1);
    try std.testing.expectEqualStrings("docker.io", bare1);

    const bare2 = try normalizeServerAlloc(gpa, "REGISTRY-1.DOCKER.IO", .bare_docker_io);
    defer gpa.free(bare2);
    try std.testing.expectEqualStrings("docker.io", bare2);

    const legacy = try normalizeServerAlloc(gpa, "docker.io", .legacy_v1_url);
    defer gpa.free(legacy);
    try std.testing.expectEqualStrings("https://index.docker.io/v1/", legacy);

    const ghcr = try normalizeServerAlloc(gpa, "https://GHCR.IO/v2/org/repo", .bare_docker_io);
    defer gpa.free(ghcr);
    try std.testing.expectEqualStrings("ghcr.io", ghcr);

    try std.testing.expectError(error.InvalidServer, normalizeServerAlloc(gpa, "[::1]:0", .bare_docker_io));
    try std.testing.expectError(error.InvalidServer, normalizeServerAlloc(gpa, "localhost:0", .bare_docker_io));
    try std.testing.expectError(error.InvalidServer, normalizeServerAlloc(gpa, "user@ghcr.io", .bare_docker_io));
}

test "deterministic generic store + registries.json index round-trip and fail-closed storage" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = Io.Threaded.global_single_threaded.io();
    const tmp_abs = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    defer gpa.free(tmp_abs);

    FakeGenericStore.reset(gpa);
    defer FakeGenericStore.deinit(gpa);

    generic_store_override = .{
        .get = FakeGenericStore.get,
        .set = FakeGenericStore.set,
        .delete = FakeGenericStore.delete,
    };
    defer generic_store_override = null;

    state_dir_override = tmp_abs;
    defer state_dir_override = null;

    try storeGenericCredential(gpa, "https://Registry.Example.com:5000/v2/", "alice", "s3cr3t-token");

    // Lookup without username (as invoked by `docker-credential-keyring get`).
    const got = try getGenericCredential(gpa, "registry.example.com:5000", null);
    defer got.deinit(gpa);
    try std.testing.expectEqual(CredentialKind.basic, got.kind);
    try std.testing.expectEqualStrings("registry.example.com:5000", got.server);
    try std.testing.expectEqualStrings("alice", got.username);
    try std.testing.expectEqualStrings("s3cr3t-token", got.secret);

    // Index file contains username only — never the secret!
    const index_path = try std.fs.path.join(gpa, &.{ tmp_abs, registries_index_filename });
    defer gpa.free(index_path);
    const index_raw = (try readFileIfExists(gpa, index_path)).?;
    defer gpa.free(index_raw);
    try std.testing.expect(std.mem.indexOf(u8, index_raw, "alice") != null);
    try std.testing.expect(std.mem.indexOf(u8, index_raw, "s3cr3t-token") == null);

    const listed = try listGenericIndexAlloc(gpa);
    defer {
        for (listed) |*e| e.deinit(gpa);
        gpa.free(listed);
    }
    try std.testing.expectEqual(@as(usize, 1), listed.len);
    try std.testing.expectEqualStrings("registry.example.com:5000", listed[0].server);
    try std.testing.expectEqualStrings("alice", listed[0].username);

    try deleteGenericCredential(gpa, "registry.example.com:5000");
    try std.testing.expectError(error.EntryNotFound, getGenericCredential(gpa, "registry.example.com:5000", null));

    // Unavailable storage fails closed without writing plaintext to registries.json.
    FakeGenericStore.fail_access = true;
    try std.testing.expectError(error.NoStorageAccess, storeGenericCredential(gpa, "quay.io", "bob", "topsecret"));
    FakeGenericStore.fail_access = false;
    const listed_after = try listGenericIndexAlloc(gpa);
    defer {
        for (listed_after) |*e| e.deinit(gpa);
        gpa.free(listed_after);
    }
    try std.testing.expectEqual(@as(usize, 0), listed_after.len);
}

test "helper wire protocol handles non-newline server input and list output" {
    const gpa = std.testing.allocator;

    var in_reader = Io.Reader.fixed("ghcr.io");
    const srv = try readBoundedStdinLine(gpa, &in_reader, 4096);
    defer gpa.free(srv);
    try std.testing.expectEqualStrings("ghcr.io", srv);

    var store_reader = Io.Reader.fixed("{\"ServerURL\":\"https://index.docker.io/v1/\",\"Username\":\"octocat\",\"Secret\":\"tok_123\"}");
    const payload = try parseHelperStoreStdinAlloc(gpa, &store_reader);
    defer payload.deinit(gpa);
    try std.testing.expectEqualStrings("https://index.docker.io/v1/", payload.server_url);
    try std.testing.expectEqualStrings("octocat", payload.username);
    try std.testing.expectEqualStrings("tok_123", payload.secret);

    var out = Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    const entries = [_]RegistryIndexEntry{
        .{ .server = @constCast("ghcr.io"), .username = @constCast("octocat") },
    };
    try writeHelperListResponse(gpa, &out.writer, &entries);
    try std.testing.expectEqualStrings("{\"ghcr.io\":\"octocat\"}\n", out.written());
}

test "identity-token <token> credentials round-trip losslessly via StoredCredentialProvider" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = Io.Threaded.global_single_threaded.io();
    const tmp_abs = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    defer gpa.free(tmp_abs);

    FakeGenericStore.reset(gpa);
    defer FakeGenericStore.deinit(gpa);

    generic_store_override = .{
        .get = FakeGenericStore.get,
        .set = FakeGenericStore.set,
        .delete = FakeGenericStore.delete,
    };
    defer generic_store_override = null;

    state_dir_override = tmp_abs;
    defer state_dir_override = null;

    const jwt = "eyJhbGciOiJub25lIn0.eyJleHAiOjIwMDAwMDAwMDB9.sig";
    try storeGenericCredential(gpa, "https://myacr.azurecr.io/v2/", identity_token_username, jwt);

    // JWT with a real `exp` claim persists `expires_at` + `until_expiration` without inventing `scopes`.
    const raw_envelope = try FakeGenericStore.get(gpa, "container-registry://myacr.azurecr.io", "default");
    defer {
        std.crypto.secureZero(u8, raw_envelope);
        gpa.free(raw_envelope);
    }
    try std.testing.expect(std.mem.indexOf(u8, raw_envelope, "\"kind\":\"identity_token\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, raw_envelope, "\"expires_at\":2000000000") != null);
    try std.testing.expect(std.mem.indexOf(u8, raw_envelope, "\"cache_policy\":\"until_expiration\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, raw_envelope, "\"scopes\"") == null);

    // Non-JWT opaque `<token>` keeps `expires_at == null` and `cache_policy == eternal`.
    try storeGenericCredential(gpa, "https://opaque.example.io", identity_token_username, "opaque-identity-secret");
    const raw_opaque = try FakeGenericStore.get(gpa, "container-registry://opaque.example.io", "default");
    defer {
        std.crypto.secureZero(u8, raw_opaque);
        gpa.free(raw_opaque);
    }
    try std.testing.expect(std.mem.indexOf(u8, raw_opaque, "\"kind\":\"identity_token\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, raw_opaque, "\"expires_at\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, raw_opaque, "\"cache_policy\":\"eternal\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, raw_opaque, "\"scopes\"") == null);

    const got_any = try getGenericCredentialDetailedAt(gpa, "myacr.azurecr.io", null, 1_900_000_000);
    defer got_any.credential.deinit(gpa);
    try std.testing.expectEqual(CredentialKind.identity_token, got_any.credential.kind);
    try std.testing.expectEqualStrings("myacr.azurecr.io", got_any.credential.server);
    try std.testing.expectEqualStrings(identity_token_username, got_any.credential.username);
    try std.testing.expectEqualStrings(jwt, got_any.credential.secret);
    try std.testing.expectEqual(@as(?i64, 2_000_000_000), got_any.credential.expires_at);

    const got_tok = try getGenericCredentialDetailedAt(gpa, "myacr.azurecr.io", identity_token_username, 1_900_000_000);
    defer got_tok.credential.deinit(gpa);
    try std.testing.expectEqual(CredentialKind.identity_token, got_tok.credential.kind);
    try std.testing.expectEqualStrings(jwt, got_tok.credential.secret);

    // Once `now_seconds >= exp`, lookup fails with AuthenticationFailed instead of returning the expired JWT.
    try std.testing.expectError(
        error.AuthenticationFailed,
        getGenericCredentialDetailedAt(gpa, "myacr.azurecr.io", null, 2_000_000_000),
    );

    // Control characters in username are rejected on store.
    try std.testing.expectError(
        error.InvalidInput,
        storeGenericCredential(gpa, "quay.io", "bad\nuser", "secret"),
    );

    // `.bearer_token` and `.basic` with `<token>` username in `container-registry://` are rejected
    // with `error.StorageFailure` rather than coerced to `<token>`!
    try FakeGenericStore.set(
        gpa,
        "container-registry://quay.io",
        "default",
        "{\"v\":1,\"kind\":\"bearer_token\",\"secret\":\"raw-bearer\",\"cache_policy\":\"eternal\"}",
    );
    try std.testing.expectError(error.StorageFailure, getGenericCredentialDetailedAt(gpa, "quay.io", null, 1_900_000_000));

    try FakeGenericStore.set(
        gpa,
        "container-registry://quay.io",
        "default",
        "{\"v\":1,\"kind\":\"basic\",\"username\":\"<token>\",\"secret\":\"spoof\",\"cache_policy\":\"eternal\"}",
    );
    try std.testing.expectError(error.StorageFailure, getGenericCredentialDetailedAt(gpa, "quay.io", null, 1_900_000_000));
}

test "legacy v0 container-registry record loads cleanly and mismatched username falls back to legacy https" {
    const gpa = std.testing.allocator;

    FakeGenericStore.reset(gpa);
    defer FakeGenericStore.deinit(gpa);

    generic_store_override = .{
        .get = FakeGenericStore.get,
        .set = FakeGenericStore.set,
        .delete = FakeGenericStore.delete,
    };
    defer generic_store_override = null;

    try FakeGenericStore.set(
        gpa,
        "container-registry://quay.io",
        "default",
        "{\"username\":\"legacy-user\",\"secret\":\"legacy-secret\"}",
    );
    try FakeGenericStore.set(gpa, "https://quay.io", "alt-user", "https-fallback-secret");

    const got_v0 = try getGenericCredential(gpa, "quay.io", null);
    defer got_v0.deinit(gpa);
    try std.testing.expectEqual(CredentialKind.basic, got_v0.kind);
    try std.testing.expectEqualStrings("quay.io", got_v0.server);
    try std.testing.expectEqualStrings("legacy-user", got_v0.username);
    try std.testing.expectEqualStrings("legacy-secret", got_v0.secret);

    const got_fb = try getGenericCredentialDetailed(gpa, "quay.io", "alt-user");
    defer got_fb.credential.deinit(gpa);
    try std.testing.expectEqual(GenericLookupSource.legacy_https_service, got_fb.source);
    try std.testing.expectEqualStrings("alt-user", got_fb.credential.username);
    try std.testing.expectEqualStrings("https-fallback-secret", got_fb.credential.secret);

    // An expired primary entry for "alice" does NOT return AuthenticationFailed when querying
    // "alt-user" or "<token>"; it reports EntryNotFound / falls back to https://quay.io!
    const expired_jwt = "eyJhbGciOiJub25lIn0.eyJleHAiOjE2MDAwMDAwMDB9.sig";
    try storeGenericCredential(gpa, "quay.io", "alice", expired_jwt);
    const got_fb_after_exp = try getGenericCredentialDetailedAt(gpa, "quay.io", "alt-user", 1_700_000_000);
    defer got_fb_after_exp.credential.deinit(gpa);
    try std.testing.expectEqual(GenericLookupSource.legacy_https_service, got_fb_after_exp.source);
    try std.testing.expectError(
        error.EntryNotFound,
        getGenericCredentialDetailedAt(gpa, "quay.io", identity_token_username, 1_700_000_000),
    );
    try std.testing.expectError(
        error.AuthenticationFailed,
        getGenericCredentialDetailedAt(gpa, "quay.io", "alice", 1_700_000_000),
    );
}

test "normalizeServerAlloc canonicalizes bracketed IPv6 across keyring and registries.json" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = Io.Threaded.global_single_threaded.io();
    const tmp_abs = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    defer gpa.free(tmp_abs);

    FakeGenericStore.reset(gpa);
    defer FakeGenericStore.deinit(gpa);

    generic_store_override = .{
        .get = FakeGenericStore.get,
        .set = FakeGenericStore.set,
        .delete = FakeGenericStore.delete,
    };
    defer generic_store_override = null;

    state_dir_override = tmp_abs;
    defer state_dir_override = null;

    try storeGenericCredential(gpa, "https://[2001:0DB8:0:0:0:0:0:1]:5000/v2/", "ipv6-user", "ipv6-secret");

    const listed = try listGenericIndexAlloc(gpa);
    defer {
        for (listed) |*e| e.deinit(gpa);
        gpa.free(listed);
    }
    try std.testing.expectEqual(@as(usize, 1), listed.len);
    try std.testing.expectEqualStrings("[2001:db8::1]:5000", listed[0].server);

    try deleteGenericCredential(gpa, "[2001:db8::1]:5000");
    try std.testing.expectError(error.EntryNotFound, getGenericCredential(gpa, "[2001:0db8:0:0:0:0:0:1]:5000", null));

    const listed_after = try listGenericIndexAlloc(gpa);
    defer gpa.free(listed_after);
    try std.testing.expectEqual(@as(usize, 0), listed_after.len);
}

test "live null_backend fails closed with NoStorageAccess without touching registries.json" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = Io.Threaded.global_single_threaded.io();
    const tmp_abs = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    defer gpa.free(tmp_abs);

    const prev_backend = keyring_zig.currentBackend();
    defer keyring_zig.setDefaultBackend(prev_backend) catch {};
    const prev_hook = stored_provider.is_app_backend_disallowed_fn;
    defer stored_provider.is_app_backend_disallowed_fn = prev_hook;

    stored_provider.is_app_backend_disallowed_fn = null;
    generic_store_override = null;
    state_dir_override = tmp_abs;
    defer state_dir_override = null;

    try keyring_zig.setDefaultBackend(.null_backend);

    try std.testing.expectError(
        error.NoStorageAccess,
        storeGenericCredential(gpa, "ghcr.io", "octocat", "ghp_secret"),
    );

    const index_path = try std.fs.path.join(gpa, &.{ tmp_abs, registries_index_filename });
    defer gpa.free(index_path);
    try std.testing.expect((try readFileIfExists(gpa, index_path)) == null);

    const listed = try listGenericIndexAlloc(gpa);
    defer gpa.free(listed);
    try std.testing.expectEqual(@as(usize, 0), listed.len);
}
