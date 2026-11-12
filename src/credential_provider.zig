//! Typed credential-provider contract (`#40`).
//!
//! Defines the standalone, transport-agnostic contract separating credential
//! providers (`get`, `login`, `logout`, optional non-interactive renewal, and
//! ordered `ProviderChain` fallback) from credential storage backends:
//! - Canonical `Target` parsing and normalization (RFC-3986 scheme, lowercase
//!   hostname/IPv4/bracketed IPv6, validated `u16` port `1..65535`, explicit
//!   rejection of userinfo, query, fragment, backslashes, internal whitespace,
//!   control bytes, and unexpected path segments).
//! - Kubernetes `ExecCredential`-style `InteractionPolicy` (`never`,
//!   `if_available`, `always`) with `Provider.executeGet` unconditionally
//!   enforcing `.never` so read lookups never trigger interactive browser or
//!   device prompts.
//! - Cooperative `Deadline` and atomic cancellation budgets with injectable
//!   millisecond clocks for deterministic testing.
//! - Distinct `CredentialSecret` variants (`basic`, `bearer_token`,
//!   `identity_token`) with automatic `std.crypto.secureZero` wiping on `deinit`.
//! - Explicit `CachePolicy` and `CredentialResult` metadata that preserve
//!   unknown `expires_at` / `scopes` as `null` without inventing capabilities.
//! - `ProviderError` classification where only `UnsupportedTarget`,
//!   `UnsupportedOperation`, and `CredentialNotFound` allow `ProviderChain` to
//!   advance to a subsequent provider.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const ProviderError = error{
    UnsupportedTarget,
    UnsupportedOperation,
    CredentialNotFound,
    ReauthenticationRequired,
    StorageUnavailable,
    StorageLocked,
    AccessDenied,
    Cancelled,
    DeadlineExceeded,
    InvalidInput,
    StorageFailure,
    OutOfMemory,
};

/// Return `true` if `ProviderChain` may advance to the next configured provider
/// after receiving `err`.
///
/// Storage, authentication/expiry, lock, permission, cancellation, deadline,
/// and input validation errors must surface directly rather than silently
/// falling back to an unrelated identity.
pub fn allowsProviderFallback(err: ProviderError) bool {
    return switch (err) {
        error.UnsupportedTarget,
        error.UnsupportedOperation,
        error.CredentialNotFound,
        => true,
        error.ReauthenticationRequired,
        error.StorageUnavailable,
        error.StorageLocked,
        error.AccessDenied,
        error.Cancelled,
        error.DeadlineExceeded,
        error.InvalidInput,
        error.StorageFailure,
        error.OutOfMemory,
        => false,
    };
}

pub const Operation = enum {
    get,
    login,
    logout,
};

/// Controls whether an operation may prompt interactively (aligned with
/// Kubernetes `ExecCredential` `interactiveMode`).
pub const InteractionPolicy = enum {
    never,
    if_available,
    always,

    pub fn allowsInteractive(self: InteractionPolicy, interactive_available: bool) bool {
        return switch (self) {
            .never => false,
            .if_available => interactive_available,
            .always => true,
        };
    }
};

pub const ParseTargetOptions = struct {
    default_scheme: ?[]const u8 = "https",
    allow_path_strip: bool = false,
};

pub const Target = struct {
    scheme: []u8,
    host: []u8, // lowercase hostname, IPv4, or bracketed [ipv6]
    port: ?u16 = null,

    pub fn parseAlloc(gpa: Allocator, raw: []const u8, opts: ParseTargetOptions) ProviderError!Target {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len == 0) return error.InvalidInput;

        for (trimmed) |c| {
            if (c == 0 or std.ascii.isControl(c)) return error.InvalidInput;
            if (std.ascii.isWhitespace(c)) return error.InvalidInput;
            if (c == '?' or c == '#' or c == '\\' or c == '@') return error.InvalidInput;
        }

        var raw_scheme: []const u8 = undefined;
        var after_scheme: []const u8 = undefined;
        if (std.mem.indexOf(u8, trimmed, "://")) |scheme_idx| {
            raw_scheme = trimmed[0..scheme_idx];
            if (!isValidScheme(raw_scheme)) return error.InvalidInput;
            after_scheme = trimmed[scheme_idx + 3 ..];
        } else {
            raw_scheme = opts.default_scheme orelse return error.InvalidInput;
            if (!isValidScheme(raw_scheme)) return error.InvalidInput;
            after_scheme = trimmed;
        }

        if (after_scheme.len == 0) return error.InvalidInput;

        var authority = after_scheme;
        if (std.mem.indexOfScalar(u8, after_scheme, '/')) |slash_idx| {
            if (slash_idx == 0) return error.InvalidInput;
            if (!opts.allow_path_strip) {
                if (!std.mem.eql(u8, after_scheme[slash_idx..], "/")) {
                    return error.InvalidInput;
                }
            }
            authority = after_scheme[0..slash_idx];
        }

        if (authority.len == 0) return error.InvalidInput;

        var raw_host: []const u8 = undefined;
        var canonical_ipv6: ?[8]u16 = null;
        var port: ?u16 = null;

        if (authority[0] == '[') {
            const close_idx = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidInput;
            const inner = authority[1..close_idx];
            canonical_ipv6 = parseIpv6(inner) orelse return error.InvalidInput;

            if (close_idx + 1 < authority.len) {
                if (authority[close_idx + 1] != ':') return error.InvalidInput;
                port = try parsePort(authority[close_idx + 2 ..]);
            }
            raw_host = authority[0 .. close_idx + 1];
        } else {
            if (std.mem.indexOfAny(u8, authority, "[]") != null) return error.InvalidInput;

            if (std.mem.indexOfScalar(u8, authority, ':')) |colon_idx| {
                const after_colon = authority[colon_idx + 1 ..];
                if (std.mem.indexOfScalar(u8, after_colon, ':') != null) {
                    return error.InvalidInput;
                }
                raw_host = authority[0..colon_idx];
                port = try parsePort(after_colon);
            } else {
                raw_host = authority;
            }

            if (!isValidHostName(raw_host)) return error.InvalidInput;
        }

        const scheme_copy = try allocLowerAscii(gpa, raw_scheme);
        errdefer gpa.free(scheme_copy);
        const host_copy = if (canonical_ipv6) |groups|
            try formatCanonicalIpv6Alloc(gpa, groups)
        else
            try allocLowerAscii(gpa, raw_host);

        return .{
            .scheme = scheme_copy,
            .host = host_copy,
            .port = port,
        };
    }

    pub fn authorityAlloc(self: Target, gpa: Allocator) ProviderError![]u8 {
        if (self.port) |p| {
            return std.fmt.allocPrint(gpa, "{s}:{d}", .{ self.host, p });
        }
        return gpa.dupe(u8, self.host);
    }

    pub fn formatUriAlloc(self: Target, gpa: Allocator) ProviderError![]u8 {
        if (self.port) |p| {
            return std.fmt.allocPrint(gpa, "{s}://{s}:{d}", .{ self.scheme, self.host, p });
        }
        return std.fmt.allocPrint(gpa, "{s}://{s}", .{ self.scheme, self.host });
    }

    pub fn serviceKeyAlloc(
        self: Target,
        gpa: Allocator,
        namespace_prefix: []const u8,
        include_scheme: bool,
    ) ProviderError![]u8 {
        if (namespace_prefix.len == 0 or hasControlChars(namespace_prefix)) {
            return error.InvalidInput;
        }
        try validateTarget(self);

        const authority = try self.authorityAlloc(gpa);
        defer gpa.free(authority);

        if (include_scheme) {
            if (std.mem.endsWith(u8, namespace_prefix, "://") or std.mem.endsWith(u8, namespace_prefix, "/")) {
                return std.fmt.allocPrint(gpa, "{s}{s}/{s}", .{ namespace_prefix, self.scheme, authority });
            }
            return std.fmt.allocPrint(gpa, "{s}/{s}/{s}", .{ namespace_prefix, self.scheme, authority });
        }
        return std.fmt.allocPrint(gpa, "{s}{s}", .{ namespace_prefix, authority });
    }

    pub fn clone(self: Target, gpa: Allocator) ProviderError!Target {
        const scheme_copy = try gpa.dupe(u8, self.scheme);
        errdefer gpa.free(scheme_copy);
        const host_copy = try gpa.dupe(u8, self.host);
        return .{
            .scheme = scheme_copy,
            .host = host_copy,
            .port = self.port,
        };
    }

    pub fn eql(self: Target, other: Target) bool {
        return self.port == other.port and
            std.mem.eql(u8, self.scheme, other.scheme) and
            std.mem.eql(u8, self.host, other.host);
    }

    pub fn deinit(self: *const Target, gpa: Allocator) void {
        gpa.free(self.scheme);
        gpa.free(self.host);
    }
};

pub const NowMsFn = *const fn () i64;

pub fn defaultNowMs() i64 {
    return std.Io.Clock.real.now(std.Io.Threaded.global_single_threaded.io()).toMilliseconds();
}

pub const Deadline = struct {
    now_ms_fn: NowMsFn = defaultNowMs,
    deadline_ms: ?i64 = null,
    cancelled: ?*const std.atomic.Value(bool) = null,

    pub fn nowMs(self: Deadline) i64 {
        return self.now_ms_fn();
    }

    pub fn nowSeconds(self: Deadline) i64 {
        return @divFloor(self.nowMs(), std.time.ms_per_s);
    }

    pub fn isCancelled(self: Deadline) bool {
        if (self.cancelled) |flag| {
            return flag.load(.acquire);
        }
        return false;
    }

    pub fn isExpired(self: Deadline) bool {
        if (self.deadline_ms) |limit_ms| {
            return self.nowMs() >= limit_ms;
        }
        return false;
    }

    pub fn checkBudget(self: Deadline) ProviderError!void {
        if (self.isCancelled()) return error.Cancelled;
        if (self.isExpired()) return error.DeadlineExceeded;
    }

    pub fn remainingMs(self: Deadline) ?u64 {
        const limit_ms = self.deadline_ms orelse return null;
        const now = self.nowMs();
        if (now >= limit_ms) return 0;
        return @intCast(@as(i128, limit_ms) - @as(i128, now));
    }
};

pub const Request = struct {
    target: Target,
    operation: Operation = .get,
    account: ?[]const u8 = null,
    audience: ?[]const u8 = null,
    scopes: []const []const u8 = &.{},
    interaction: InteractionPolicy = .never,
    deadline: Deadline = .{},

    pub fn validate(self: Request) ProviderError!void {
        try validateTarget(self.target);

        if (self.account) |acc| {
            if (acc.len == 0 or hasControlChars(acc)) return error.InvalidInput;
        }
        if (self.audience) |aud| {
            if (aud.len == 0 or hasControlChars(aud)) return error.InvalidInput;
        }
        for (self.scopes) |scope| {
            if (scope.len == 0 or hasControlChars(scope)) return error.InvalidInput;
        }
    }

    pub fn asNoninteractiveGet(self: Request) Request {
        var copy = self;
        copy.operation = .get;
        copy.interaction = .never;
        return copy;
    }
};

pub const CredentialKind = enum {
    basic,
    bearer_token,
    identity_token,
};

pub const BasicSecret = struct {
    username: []u8,
    secret: []u8,

    pub fn deinit(self: *const BasicSecret, gpa: Allocator) void {
        gpa.free(self.username);
        std.crypto.secureZero(u8, self.secret);
        gpa.free(self.secret);
    }
};

pub const CredentialSecret = union(CredentialKind) {
    basic: BasicSecret,
    bearer_token: []u8,
    identity_token: []u8,

    pub fn kind(self: CredentialSecret) CredentialKind {
        return std.meta.activeTag(self);
    }

    pub fn clone(self: CredentialSecret, gpa: Allocator) ProviderError!CredentialSecret {
        return switch (self) {
            .basic => |b| blk: {
                const username_copy = try gpa.dupe(u8, b.username);
                errdefer gpa.free(username_copy);
                const secret_copy = try gpa.dupe(u8, b.secret);
                break :blk .{
                    .basic = .{
                        .username = username_copy,
                        .secret = secret_copy,
                    },
                };
            },
            .bearer_token => |tok| .{ .bearer_token = try gpa.dupe(u8, tok) },
            .identity_token => |tok| .{ .identity_token = try gpa.dupe(u8, tok) },
        };
    }

    pub fn deinit(self: *const CredentialSecret, gpa: Allocator) void {
        switch (self.*) {
            .basic => |*b| b.deinit(gpa),
            .bearer_token => |tok| {
                std.crypto.secureZero(u8, tok);
                gpa.free(tok);
            },
            .identity_token => |tok| {
                std.crypto.secureZero(u8, tok);
                gpa.free(tok);
            },
        }
    }
};

pub const CachePolicy = enum {
    eternal,
    until_expiration,
    session,
    never,

    pub fn isPersistent(self: CachePolicy) bool {
        return switch (self) {
            .eternal, .until_expiration => true,
            .session, .never => false,
        };
    }
};

pub const CredentialResult = struct {
    secret: CredentialSecret,
    account: ?[]u8 = null,
    expires_at: ?i64 = null,
    cache_policy: CachePolicy = .eternal,
    audience: ?[]u8 = null,
    scopes: ?[][]u8 = null, // null when unknown; never invented!
    supports_noninteractive_renewal: bool = false,

    pub fn isExpiredAt(self: CredentialResult, now_seconds: i64) bool {
        if (self.expires_at) |exp| {
            return exp <= now_seconds;
        }
        return false;
    }

    pub fn validate(self: CredentialResult) ProviderError!void {
        switch (self.secret) {
            .basic => |b| {
                if (b.username.len == 0 or hasControlChars(b.username)) return error.InvalidInput;
                if (b.secret.len == 0 or std.mem.indexOfScalar(u8, b.secret, 0) != null) return error.InvalidInput;
            },
            .bearer_token => |tok| {
                if (tok.len == 0 or std.mem.indexOfScalar(u8, tok, 0) != null) return error.InvalidInput;
            },
            .identity_token => |tok| {
                if (tok.len == 0 or std.mem.indexOfScalar(u8, tok, 0) != null) return error.InvalidInput;
            },
        }

        if (self.cache_policy == .until_expiration and self.expires_at == null) {
            return error.InvalidInput;
        }

        if (self.account) |acc| {
            if (acc.len == 0 or hasControlChars(acc)) return error.InvalidInput;
        }

        if (self.audience) |aud| {
            if (aud.len == 0 or hasControlChars(aud)) return error.InvalidInput;
        }

        if (self.scopes) |scope_list| {
            for (scope_list) |scope| {
                if (scope.len == 0 or hasControlChars(scope)) return error.InvalidInput;
            }
        }
    }

    pub fn clone(self: CredentialResult, gpa: Allocator) ProviderError!CredentialResult {
        var secret_copy = try self.secret.clone(gpa);
        errdefer secret_copy.deinit(gpa);

        const account_copy = if (self.account) |acc| try gpa.dupe(u8, acc) else null;
        errdefer if (account_copy) |acc| gpa.free(acc);

        const audience_copy = if (self.audience) |aud| try gpa.dupe(u8, aud) else null;
        errdefer if (audience_copy) |aud| gpa.free(aud);

        const scopes_copy = if (self.scopes) |scope_list| blk: {
            const list = try gpa.alloc([]u8, scope_list.len);
            var initialized: usize = 0;
            errdefer {
                for (list[0..initialized]) |item| gpa.free(item);
                gpa.free(list);
            }
            for (scope_list, 0..) |scope, idx| {
                list[idx] = try gpa.dupe(u8, scope);
                initialized += 1;
            }
            break :blk list;
        } else null;

        return .{
            .secret = secret_copy,
            .account = account_copy,
            .expires_at = self.expires_at,
            .cache_policy = self.cache_policy,
            .audience = audience_copy,
            .scopes = scopes_copy,
            .supports_noninteractive_renewal = self.supports_noninteractive_renewal,
        };
    }

    pub fn deinit(self: *const CredentialResult, gpa: Allocator) void {
        self.secret.deinit(gpa);
        if (self.account) |acc| gpa.free(acc);
        if (self.audience) |aud| gpa.free(aud);
        if (self.scopes) |scope_list| {
            for (scope_list) |scope| gpa.free(scope);
            gpa.free(scope_list);
        }
    }
};

pub const LoginInput = struct {
    request: Request,
    credential: ?*const CredentialResult = null,
};

pub const Provider = struct {
    name: []const u8,
    ctx: ?*anyopaque = null,
    getFn: *const fn (ctx: ?*anyopaque, gpa: Allocator, request: Request) ProviderError!CredentialResult,
    loginFn: ?*const fn (ctx: ?*anyopaque, gpa: Allocator, input: LoginInput) ProviderError!CredentialResult = null,
    logoutFn: ?*const fn (ctx: ?*anyopaque, gpa: Allocator, request: Request) ProviderError!void = null,
    renewNoninteractiveFn: ?*const fn (
        ctx: ?*anyopaque,
        gpa: Allocator,
        request: Request,
        expired: *const CredentialResult,
    ) ProviderError!CredentialResult = null,

    pub fn executeGet(self: Provider, gpa: Allocator, request: Request) ProviderError!CredentialResult {
        if (request.operation != .get) return error.InvalidInput;
        try request.validate();
        try request.deadline.checkBudget();

        const noninteractive_req = request.asNoninteractiveGet();
        var res = self.getFn(self.ctx, gpa, noninteractive_req) catch |err| {
            if (err != error.OutOfMemory) {
                try request.deadline.checkBudget();
            }
            return err;
        };
        var keep_res = false;
        defer if (!keep_res) res.deinit(gpa);

        try request.deadline.checkBudget();
        try res.validate();

        if (res.isExpiredAt(request.deadline.nowSeconds())) {
            if (res.supports_noninteractive_renewal) {
                if (self.renewNoninteractiveFn) |renew_fn| {
                    try request.deadline.checkBudget();
                    var renewed = renew_fn(self.ctx, gpa, noninteractive_req, &res) catch |err| {
                        if (err != error.OutOfMemory) {
                            try request.deadline.checkBudget();
                        }
                        return switch (err) {
                            error.CredentialNotFound,
                            error.UnsupportedOperation,
                            error.UnsupportedTarget,
                            error.ReauthenticationRequired,
                            => error.ReauthenticationRequired,
                            else => err,
                        };
                    };
                    errdefer renewed.deinit(gpa);

                    try request.deadline.checkBudget();
                    try renewed.validate();
                    if (renewed.isExpiredAt(request.deadline.nowSeconds())) {
                        return error.ReauthenticationRequired;
                    }
                    return renewed;
                }
            }
            return error.ReauthenticationRequired;
        }

        keep_res = true;
        return res;
    }

    pub fn executeLogin(self: Provider, gpa: Allocator, input: LoginInput) ProviderError!CredentialResult {
        if (input.request.operation != .login) return error.InvalidInput;
        try input.request.validate();
        if (input.credential) |cred| {
            try cred.validate();
        }
        try input.request.deadline.checkBudget();

        const login_fn = self.loginFn orelse return error.UnsupportedOperation;
        var result = login_fn(self.ctx, gpa, input) catch |err| {
            if (err != error.OutOfMemory) {
                try input.request.deadline.checkBudget();
            }
            return err;
        };
        errdefer result.deinit(gpa);

        try input.request.deadline.checkBudget();
        try result.validate();
        return result;
    }

    pub fn executeLogout(self: Provider, gpa: Allocator, request: Request) ProviderError!void {
        if (request.operation != .logout) return error.InvalidInput;
        try request.validate();
        try request.deadline.checkBudget();

        const logout_fn = self.logoutFn orelse return error.UnsupportedOperation;
        logout_fn(self.ctx, gpa, request) catch |err| {
            if (err != error.OutOfMemory) {
                try request.deadline.checkBudget();
            }
            return err;
        };
        try request.deadline.checkBudget();
    }
};

pub const ProviderChain = struct {
    providers: []const Provider,

    pub fn get(self: ProviderChain, gpa: Allocator, request: Request) ProviderError!CredentialResult {
        if (request.operation != .get) return error.InvalidInput;
        try request.validate();
        try request.deadline.checkBudget();
        if (self.providers.len == 0) return error.UnsupportedTarget;

        var fallback_err: ?ProviderError = null;
        for (self.providers) |provider| {
            if (provider.executeGet(gpa, request)) |res| {
                return res;
            } else |err| {
                if (!allowsProviderFallback(err)) return err;
                fallback_err = mergeFallbackError(fallback_err, err);
            }
        }
        return fallback_err orelse error.UnsupportedTarget;
    }

    pub fn login(self: ProviderChain, gpa: Allocator, input: LoginInput) ProviderError!CredentialResult {
        if (input.request.operation != .login) return error.InvalidInput;
        try input.request.validate();
        if (input.credential) |cred| {
            try cred.validate();
        }
        try input.request.deadline.checkBudget();
        if (self.providers.len == 0) return error.UnsupportedTarget;

        var fallback_err: ?ProviderError = null;
        for (self.providers) |provider| {
            if (provider.executeLogin(gpa, input)) |res| {
                return res;
            } else |err| {
                if (!allowsProviderFallback(err)) return err;
                fallback_err = mergeFallbackError(fallback_err, err);
            }
        }
        return fallback_err orelse error.UnsupportedTarget;
    }

    pub fn logout(self: ProviderChain, gpa: Allocator, request: Request) ProviderError!void {
        if (request.operation != .logout) return error.InvalidInput;
        try request.validate();
        try request.deadline.checkBudget();
        if (self.providers.len == 0) return error.UnsupportedTarget;

        var fallback_err: ?ProviderError = null;
        for (self.providers) |provider| {
            if (provider.executeLogout(gpa, request)) {
                return;
            } else |err| {
                if (!allowsProviderFallback(err)) return err;
                fallback_err = mergeFallbackError(fallback_err, err);
            }
        }
        return fallback_err orelse error.UnsupportedTarget;
    }
};

// ---------------------------------------------------------------------------
// Internal Validation & Formatting Helpers
// ---------------------------------------------------------------------------

fn hasControlChars(s: []const u8) bool {
    for (s) |c| {
        if (c == 0 or std.ascii.isControl(c)) return true;
    }
    return false;
}

fn isValidScheme(s: []const u8) bool {
    if (s.len == 0) return false;
    if (!std.ascii.isAlphabetic(s[0])) return false;
    for (s[1..]) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '+' and c != '-' and c != '.') {
            return false;
        }
    }
    return true;
}

fn parsePort(port_str: []const u8) ProviderError!u16 {
    if (port_str.len == 0) return error.InvalidInput;
    for (port_str) |c| {
        if (!std.ascii.isDigit(c)) return error.InvalidInput;
    }
    const port = std.fmt.parseUnsigned(u16, port_str, 10) catch return error.InvalidInput;
    if (port == 0) return error.InvalidInput;
    return port;
}

fn validateTarget(target: Target) ProviderError!void {
    if (target.scheme.len == 0 or !isValidScheme(target.scheme)) {
        return error.InvalidInput;
    }
    if (target.host.len == 0 or hasControlChars(target.host)) {
        return error.InvalidInput;
    }
    if (std.mem.indexOfAny(u8, target.host, " \t\r\n?#@\\/") != null) {
        return error.InvalidInput;
    }
    if (target.host[0] == '[') {
        if (target.host[target.host.len - 1] != ']') return error.InvalidInput;
        if (parseIpv6(target.host[1 .. target.host.len - 1]) == null) {
            return error.InvalidInput;
        }
    } else {
        if (!isValidHostName(target.host)) return error.InvalidInput;
    }
    if (target.port) |p| {
        if (p == 0) return error.InvalidInput;
    }
}

fn parseIpv4Tail(s: []const u8) ?[2]u16 {
    if (s.len == 0 or s.len > 15) return null;
    var octets: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var it = std.mem.splitScalar(u8, s, '.');
    while (it.next()) |part| {
        if (octet_idx >= 4) return null;
        if (part.len == 0 or part.len > 3) return null;
        if (part.len > 1 and part[0] == '0') return null;
        for (part) |c| {
            if (!std.ascii.isDigit(c)) return null;
        }
        octets[octet_idx] = std.fmt.parseUnsigned(u8, part, 10) catch return null;
        octet_idx += 1;
    }
    if (octet_idx != 4) return null;
    return .{
        (@as(u16, octets[0]) << 8) | @as(u16, octets[1]),
        (@as(u16, octets[2]) << 8) | @as(u16, octets[3]),
    };
}

fn parseHextet(s: []const u8) ?u16 {
    if (s.len == 0 or s.len > 4) return null;
    for (s) |c| {
        if (!std.ascii.isHex(c)) return null;
    }
    return std.fmt.parseUnsigned(u16, s, 16) catch null;
}

fn parseIpv6SegmentList(
    part: []const u8,
    allow_ipv4_tail: bool,
    out: *[8]u16,
) ?usize {
    if (part.len == 0) return 0;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, part, ':');
    while (it.next()) |tok| {
        const is_last = (it.peek() == null);
        if (std.mem.indexOfScalar(u8, tok, '.') != null) {
            if (!allow_ipv4_tail or !is_last) return null;
            if (count + 2 > 8) return null;
            const v4 = parseIpv4Tail(tok) orelse return null;
            out[count] = v4[0];
            out[count + 1] = v4[1];
            count += 2;
        } else {
            if (count + 1 > 8) return null;
            out[count] = parseHextet(tok) orelse return null;
            count += 1;
        }
    }
    return count;
}

/// Strict RFC 4291 IPv6 literal parser supporting `::` zero-compression and an
/// optional dotted IPv4 tail in the final 32 bits.
pub fn parseIpv6(inner: []const u8) ?[8]u16 {
    if (inner.len == 0) return null;
    if (std.mem.indexOfScalar(u8, inner, ':') == null) return null;

    if (std.mem.indexOf(u8, inner, "::")) |dc_idx| {
        if (std.mem.indexOf(u8, inner[dc_idx + 1 ..], "::") != null) return null;

        const left_str = inner[0..dc_idx];
        const right_str = inner[dc_idx + 2 ..];

        var left_groups: [8]u16 = @splat(0);
        var right_groups: [8]u16 = @splat(0);

        const left_len = parseIpv6SegmentList(left_str, false, &left_groups) orelse return null;
        const right_len = parseIpv6SegmentList(right_str, true, &right_groups) orelse return null;

        if (left_len + right_len >= 8) return null;

        var out: [8]u16 = @splat(0);
        @memcpy(out[0..left_len], left_groups[0..left_len]);
        @memcpy(out[8 - right_len .. 8], right_groups[0..right_len]);
        return out;
    } else {
        var out: [8]u16 = @splat(0);
        const count = parseIpv6SegmentList(inner, true, &out) orelse return null;
        if (count != 8) return null;
        return out;
    }
}

/// Format an IPv6 address in canonical RFC 5952 bracketed form (`[...]`),
/// lowercasing hex digits, stripping leading zeros, and compressing the first
/// longest run of `>= 2` zero hextets as `::`.
pub fn formatCanonicalIpv6Alloc(gpa: Allocator, groups: [8]u16) ProviderError![]u8 {
    var best_start: usize = 0;
    var best_len: usize = 0;

    var i: usize = 0;
    while (i < 8) {
        if (groups[i] == 0) {
            const start = i;
            while (i < 8 and groups[i] == 0) : (i += 1) {}
            const run_len = i - start;
            if (run_len >= 2 and run_len > best_len) {
                best_start = start;
                best_len = run_len;
            }
        } else {
            i += 1;
        }
    }

    var buf: [48]u8 = undefined;
    var pos: usize = 0;
    buf[pos] = '[';
    pos += 1;

    var idx: usize = 0;
    var need_colon = false;
    while (idx < 8) {
        if (best_len >= 2 and idx == best_start) {
            buf[pos] = ':';
            buf[pos + 1] = ':';
            pos += 2;
            idx += best_len;
            need_colon = false;
            continue;
        }
        if (need_colon) {
            buf[pos] = ':';
            pos += 1;
        }
        const written = std.fmt.bufPrint(buf[pos..], "{x}", .{groups[idx]}) catch unreachable;
        pos += written.len;
        need_colon = true;
        idx += 1;
    }

    buf[pos] = ']';
    pos += 1;

    return gpa.dupe(u8, buf[0..pos]);
}

fn isAllAsciiDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

fn isValidHostName(host: []const u8) bool {
    if (host.len == 0 or host.len > 253) return false;
    var labels = std.mem.splitScalar(u8, host, '.');
    var last_label: []const u8 = "";
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') {
                return false;
            }
        }
        last_label = label;
    }
    if (isAllAsciiDigits(last_label)) {
        return parseIpv4Tail(host) != null;
    }
    return true;
}

fn allocLowerAscii(gpa: Allocator, s: []const u8) ProviderError![]u8 {
    const out = try gpa.dupe(u8, s);
    _ = std.ascii.lowerString(out, out);
    return out;
}

fn fallbackErrorRank(err: ProviderError) u8 {
    return switch (err) {
        error.CredentialNotFound => 3,
        error.UnsupportedOperation => 2,
        error.UnsupportedTarget => 1,
        else => unreachable,
    };
}

fn mergeFallbackError(current: ?ProviderError, next: ProviderError) ProviderError {
    const prev = current orelse return next;
    return if (fallbackErrorRank(next) > fallbackErrorRank(prev)) next else prev;
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "allowsProviderFallback classifies every ProviderError variant" {
    try testing.expect(allowsProviderFallback(error.UnsupportedTarget));
    try testing.expect(allowsProviderFallback(error.UnsupportedOperation));
    try testing.expect(allowsProviderFallback(error.CredentialNotFound));

    try testing.expect(!allowsProviderFallback(error.ReauthenticationRequired));
    try testing.expect(!allowsProviderFallback(error.StorageUnavailable));
    try testing.expect(!allowsProviderFallback(error.StorageLocked));
    try testing.expect(!allowsProviderFallback(error.AccessDenied));
    try testing.expect(!allowsProviderFallback(error.Cancelled));
    try testing.expect(!allowsProviderFallback(error.DeadlineExceeded));
    try testing.expect(!allowsProviderFallback(error.InvalidInput));
    try testing.expect(!allowsProviderFallback(error.StorageFailure));
    try testing.expect(!allowsProviderFallback(error.OutOfMemory));
}

test "InteractionPolicy follows Kubernetes ExecCredential semantics" {
    try testing.expect(!InteractionPolicy.never.allowsInteractive(false));
    try testing.expect(!InteractionPolicy.never.allowsInteractive(true));

    try testing.expect(!InteractionPolicy.if_available.allowsInteractive(false));
    try testing.expect(InteractionPolicy.if_available.allowsInteractive(true));

    try testing.expect(InteractionPolicy.always.allowsInteractive(false));
    try testing.expect(InteractionPolicy.always.allowsInteractive(true));
}

test "Target.parseAlloc normalizes case, ports, IPv6, paths, and service keys" {
    const gpa = testing.allocator;

    {
        var t = try Target.parseAlloc(gpa, "  HTTPS://GitHub.COM/  \r\n", .{});
        defer t.deinit(gpa);
        try testing.expectEqualStrings("https", t.scheme);
        try testing.expectEqualStrings("github.com", t.host);
        try testing.expectEqual(@as(?u16, null), t.port);

        const auth = try t.authorityAlloc(gpa);
        defer gpa.free(auth);
        try testing.expectEqualStrings("github.com", auth);

        const uri = try t.formatUriAlloc(gpa);
        defer gpa.free(uri);
        try testing.expectEqualStrings("https://github.com", uri);

        const svc_scheme = try t.serviceKeyAlloc(gpa, "credential-provider://", true);
        defer gpa.free(svc_scheme);
        try testing.expectEqualStrings("credential-provider://https/github.com", svc_scheme);

        const svc_slash = try t.serviceKeyAlloc(gpa, "credential-provider", true);
        defer gpa.free(svc_slash);
        try testing.expectEqualStrings("credential-provider/https/github.com", svc_slash);

        const svc_bare = try t.serviceKeyAlloc(gpa, "container-registry://", false);
        defer gpa.free(svc_bare);
        try testing.expectEqualStrings("container-registry://github.com", svc_bare);
    }

    {
        var t1 = try Target.parseAlloc(gpa, "Registry.Example.IO:5000", .{});
        defer t1.deinit(gpa);
        var t2 = try Target.parseAlloc(gpa, "https://registry.example.io:8443", .{});
        defer t2.deinit(gpa);
        var t1_clone = try t1.clone(gpa);
        defer t1_clone.deinit(gpa);

        try testing.expectEqual(@as(?u16, 5000), t1.port);
        try testing.expectEqual(@as(?u16, 8443), t2.port);
        try testing.expect(t1.eql(t1_clone));
        try testing.expect(!t1.eql(t2));

        const uri1 = try t1.formatUriAlloc(gpa);
        defer gpa.free(uri1);
        try testing.expectEqualStrings("https://registry.example.io:5000", uri1);
    }

    {
        var ipv6 = try Target.parseAlloc(gpa, "HTTP://[2001:DB8::1]:5000/", .{});
        defer ipv6.deinit(gpa);
        var ipv6_expanded = try Target.parseAlloc(gpa, "http://[2001:0DB8:0000:0000:0000:0000:0000:0001]:5000", .{});
        defer ipv6_expanded.deinit(gpa);

        try testing.expect(ipv6.eql(ipv6_expanded));
        try testing.expectEqualStrings("http", ipv6.scheme);
        try testing.expectEqualStrings("[2001:db8::1]", ipv6.host);
        try testing.expectEqualStrings("[2001:db8::1]", ipv6_expanded.host);
        try testing.expectEqual(@as(?u16, 5000), ipv6.port);

        const key = try ipv6.serviceKeyAlloc(gpa, "container-registry://", false);
        defer gpa.free(key);
        const key_expanded = try ipv6_expanded.serviceKeyAlloc(gpa, "container-registry://", false);
        defer gpa.free(key_expanded);
        try testing.expectEqualStrings("container-registry://[2001:db8::1]:5000", key);
        try testing.expectEqualStrings(key, key_expanded);

        // Dotted IPv4 tail in final 32 bits canonicalizes per RFC 5952.
        var v4_mapped = try Target.parseAlloc(gpa, "https://[::FFFF:192.0.2.128]:8443", .{});
        defer v4_mapped.deinit(gpa);
        try testing.expectEqualStrings("[::ffff:c000:280]", v4_mapped.host);

        // Single zero hextet is NOT compressed per RFC 5952 Section 4.2.2.
        var single_zero = try Target.parseAlloc(gpa, "https://[2001:0db8:0000:0001:0001:0001:0001:0001]", .{});
        defer single_zero.deinit(gpa);
        try testing.expectEqualStrings("[2001:db8:0:1:1:1:1:1]", single_zero.host);
    }

    {
        var loopback = try Target.parseAlloc(gpa, "[::1]:1", .{ .default_scheme = "HTTP" });
        defer loopback.deinit(gpa);
        try testing.expectEqualStrings("http", loopback.scheme);
        try testing.expectEqualStrings("[::1]", loopback.host);
        try testing.expectEqual(@as(?u16, 1), loopback.port);

        var max_port = try Target.parseAlloc(gpa, "127.0.0.1:65535", .{});
        defer max_port.deinit(gpa);
        try testing.expectEqual(@as(?u16, 65535), max_port.port);
    }

    {
        var stripped = try Target.parseAlloc(gpa, "https://index.docker.io/v1/", .{
            .allow_path_strip = true,
        });
        defer stripped.deinit(gpa);
        try testing.expectEqualStrings("https", stripped.scheme);
        try testing.expectEqualStrings("index.docker.io", stripped.host);
        try testing.expectEqual(@as(?u16, null), stripped.port);
    }
}

test "Target.parseAlloc rejects malformed targets and unsafe components" {
    const gpa = testing.allocator;

    const invalid_cases = [_][]const u8{
        "",
        "   \t\r\n ",
        "https://",
        "://example.com",
        "1http://example.com",
        "http+bad!://example.com",
        "https://user@example.com",
        "https://user:pass@example.com",
        "user@example.com",
        "https://example.com?token=secret",
        "https://example.com#section",
        "https://example.com\\path",
        "https://exam ple.com",
        "https://example.com\x00evil",
        "\x00https://example.com",
        "https://example.com\x1b",
        "https://example.com/org/repo",
        "https://example.com//",
        "https://example.com:0",
        "https://example.com:65536",
        "https://example.com:70000",
        "https://example.com:",
        "https://example.com:abc",
        "https://:5000",
        "::1",
        "2001:db8::1",
        "https://[::1",
        "https://[]",
        "https://[1:2]",
        "https://[1:2]:5000",
        "https://[:::1]",
        "https://[1:::]",
        "https://[2001:db8::1::2]",
        "https://[1:2:3:4:5:6:7:8:9]",
        "https://[1:2:3:4::5:6:7:8]",
        "https://[2001:0db80::1]",
        "https://[192.0.2.1::1]",
        "https://[::192.0.2.1:1]",
        "https://[::192.0.2.256]",
        "https://[::192.0.2.01]",
        "https://[127.0.0.1]",
        "https://[::1]extra",
        "https://[::1]:0",
        "https://[::1]:70000",
        "https://.example.com",
        "https://example.com.",
        "https://example..com",
        "https://-bad.example.com",
        "https://bad-.example.com",
        "https://bad%2fhost.example.com",
        "https://192.0.2.256",
        "https://0177.0.0.1",
        "https://127.1",
        "https://2130706433",
        "https://example.123",
        "https://" ++ (&@as([64]u8, @splat('a'))) ++ ".example.com",
        "https://" ++ ((&@as([63]u8, @splat('a')) ++ ".") ++ (&@as([63]u8, @splat('a')) ++ ".") ++ (&@as([63]u8, @splat('a')) ++ ".")) ++ (&@as([62]u8, @splat('b'))),
    };

    for (invalid_cases) |raw| {
        try testing.expectError(error.InvalidInput, Target.parseAlloc(gpa, raw, .{}));
    }

    // Without default_scheme, bare hostnames are rejected.
    try testing.expectError(
        error.InvalidInput,
        Target.parseAlloc(gpa, "example.com", .{ .default_scheme = null }),
    );

    // Even with allow_path_strip = true, query/fragment/userinfo/backslash/control bytes are rejected.
    try testing.expectError(
        error.InvalidInput,
        Target.parseAlloc(gpa, "https://example.com/v1/?foo=bar", .{ .allow_path_strip = true }),
    );
    try testing.expectError(
        error.InvalidInput,
        Target.parseAlloc(gpa, "https://user@example.com/v1/", .{ .allow_path_strip = true }),
    );

    // serviceKeyAlloc rejects empty or control-char namespace prefixes.
    var valid = try Target.parseAlloc(gpa, "https://example.com", .{});
    defer valid.deinit(gpa);
    try testing.expectError(error.InvalidInput, valid.serviceKeyAlloc(gpa, "", true));
    try testing.expectError(error.InvalidInput, valid.serviceKeyAlloc(gpa, "bad\nns://", false));
}

test "CredentialSecret, CachePolicy, and CredentialResult preserve metadata without invention" {
    const gpa = testing.allocator;

    try testing.expect(CachePolicy.eternal.isPersistent());
    try testing.expect(CachePolicy.until_expiration.isPersistent());
    try testing.expect(!CachePolicy.session.isPersistent());
    try testing.expect(!CachePolicy.never.isPersistent());

    // Distinct secret variants: basic, bearer_token, identity_token.
    var basic_res: CredentialResult = .{
        .secret = .{
            .basic = .{
                .username = try gpa.dupe(u8, "octocat"),
                .secret = try gpa.dupe(u8, "ghp_secret_value"),
            },
        },
        .account = try gpa.dupe(u8, "octocat"),
        // expires_at and scopes remain null when unknown.
    };
    defer basic_res.deinit(gpa);

    try testing.expectEqual(CredentialKind.basic, basic_res.secret.kind());
    try testing.expectEqual(@as(?i64, null), basic_res.expires_at);
    try testing.expectEqual(@as(?[][]u8, null), basic_res.scopes);
    try testing.expect(!basic_res.isExpiredAt(1_800_000_000));
    try basic_res.validate();

    var basic_clone = try basic_res.clone(gpa);
    defer basic_clone.deinit(gpa);
    try testing.expectEqual(@as(?i64, null), basic_clone.expires_at);
    try testing.expectEqual(@as(?[][]u8, null), basic_clone.scopes);
    try testing.expectEqualStrings("octocat", basic_clone.secret.basic.username);
    try testing.expectEqualStrings("ghp_secret_value", basic_clone.secret.basic.secret);

    var scopes_buf = try gpa.alloc([]u8, 2);
    scopes_buf[0] = try gpa.dupe(u8, "repo");
    scopes_buf[1] = try gpa.dupe(u8, "read:packages");

    var bearer_res: CredentialResult = .{
        .secret = .{ .bearer_token = try gpa.dupe(u8, "eyJ_access_token") },
        .expires_at = 2_000,
        .cache_policy = .until_expiration,
        .audience = try gpa.dupe(u8, "https://management.azure.com/"),
        .scopes = scopes_buf,
        .supports_noninteractive_renewal = true,
    };
    defer bearer_res.deinit(gpa);

    try testing.expectEqual(CredentialKind.bearer_token, bearer_res.secret.kind());
    try bearer_res.validate();
    try testing.expect(!bearer_res.isExpiredAt(1_999));
    try testing.expect(bearer_res.isExpiredAt(2_000));
    try testing.expect(bearer_res.isExpiredAt(2_001));

    var bearer_clone = try bearer_res.clone(gpa);
    defer bearer_clone.deinit(gpa);
    try testing.expectEqual(CredentialKind.bearer_token, bearer_clone.secret.kind());
    try testing.expectEqual(@as(usize, 2), bearer_clone.scopes.?.len);
    try testing.expectEqualStrings("repo", bearer_clone.scopes.?[0]);
    try testing.expectEqualStrings("read:packages", bearer_clone.scopes.?[1]);

    var id_tok_res: CredentialResult = .{
        .secret = .{ .identity_token = try gpa.dupe(u8, "refresh_or_identity_token") },
        .cache_policy = .session,
    };
    defer id_tok_res.deinit(gpa);
    try testing.expectEqual(CredentialKind.identity_token, id_tok_res.secret.kind());
    try id_tok_res.validate();

    // until_expiration without expires_at must fail validation.
    var missing_exp: CredentialResult = .{
        .secret = .{ .bearer_token = try gpa.dupe(u8, "tok") },
        .cache_policy = .until_expiration,
        .expires_at = null,
    };
    defer missing_exp.deinit(gpa);
    try testing.expectError(error.InvalidInput, missing_exp.validate());

    // NUL byte in token or control byte in username/scopes must fail validation.
    var nul_secret: CredentialResult = .{
        .secret = .{ .identity_token = try gpa.dupe(u8, "bad\x00token") },
    };
    defer nul_secret.deinit(gpa);
    try testing.expectError(error.InvalidInput, nul_secret.validate());
}

const TestClock = struct {
    var current_ms: i64 = 1_700_000_000_000;

    fn nowMs() i64 {
        return current_ms;
    }
};

test "Deadline enforces cancellation precedence, expiration, and remainingMs" {
    TestClock.current_ms = 10_000;
    var cancelled = std.atomic.Value(bool).init(false);

    const unbounded: Deadline = .{
        .now_ms_fn = TestClock.nowMs,
        .cancelled = &cancelled,
    };
    try unbounded.checkBudget();
    try testing.expectEqual(@as(?u64, null), unbounded.remainingMs());
    try testing.expectEqual(@as(i64, 10), unbounded.nowSeconds());

    const active: Deadline = .{
        .now_ms_fn = TestClock.nowMs,
        .deadline_ms = 12_500,
        .cancelled = &cancelled,
    };
    try active.checkBudget();
    try testing.expectEqual(@as(?u64, 2_500), active.remainingMs());

    TestClock.current_ms = 12_500;
    try testing.expect(active.isExpired());
    try testing.expectEqual(@as(?u64, 0), active.remainingMs());
    try testing.expectError(error.DeadlineExceeded, active.checkBudget());

    // Cancelled takes strict precedence over DeadlineExceeded.
    cancelled.store(true, .release);
    try testing.expectError(error.Cancelled, active.checkBudget());
}

test "Provider.executeGet forces non-interactive policy and handles expiry and renewal" {
    const gpa = testing.allocator;
    var target = try Target.parseAlloc(gpa, "https://ghcr.io", .{});
    defer target.deinit(gpa);

    const MockState = struct {
        saw_interaction: ?InteractionPolicy = null,
        saw_operation: ?Operation = null,
        expires_at: ?i64 = null,
        supports_renewal: bool = false,
        renew_called: usize = 0,
        advance_ms_on_renew: i64 = 0,
        renewed_expires_at: ?i64 = 2_000,

        fn get(ctx: ?*anyopaque, alloc: Allocator, req: Request) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.saw_interaction = req.interaction;
            self.saw_operation = req.operation;
            return .{
                .secret = .{ .bearer_token = try alloc.dupe(u8, "initial-token") },
                .expires_at = self.expires_at,
                .cache_policy = if (self.expires_at != null) .until_expiration else .eternal,
                .supports_noninteractive_renewal = self.supports_renewal,
            };
        }

        fn renew(
            ctx: ?*anyopaque,
            alloc: Allocator,
            req: Request,
            expired: *const CredentialResult,
        ) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.renew_called += 1;
            if (req.interaction != .never) return error.InvalidInput;
            if (!std.mem.eql(u8, expired.secret.bearer_token, "initial-token")) {
                return error.StorageFailure;
            }
            TestClock.current_ms += self.advance_ms_on_renew;
            return .{
                .secret = .{ .bearer_token = try alloc.dupe(u8, "renewed-token") },
                .expires_at = self.renewed_expires_at,
                .cache_policy = if (self.renewed_expires_at != null) .until_expiration else .session,
                .supports_noninteractive_renewal = true,
            };
        }
    };

    // 1. Caller passes interaction = .always, but executeGet forces .never.
    TestClock.current_ms = 1_000_000; // 1_000s
    var state: MockState = .{ .expires_at = 1_500 };
    const provider_no_renew: Provider = .{
        .name = "mock",
        .ctx = &state,
        .getFn = MockState.get,
    };

    var ok_res = try provider_no_renew.executeGet(gpa, .{
        .target = target,
        .operation = .get,
        .interaction = .always,
        .deadline = .{ .now_ms_fn = TestClock.nowMs, .deadline_ms = 1_005_000 },
    });
    defer ok_res.deinit(gpa);
    try testing.expectEqual(InteractionPolicy.never, state.saw_interaction.?);
    try testing.expectEqual(Operation.get, state.saw_operation.?);
    try testing.expectEqualStrings("initial-token", ok_res.secret.bearer_token);

    // 2. Expired credential without non-interactive renewal -> ReauthenticationRequired.
    TestClock.current_ms = 1_500_000; // 1_500s == expires_at
    try testing.expectError(
        error.ReauthenticationRequired,
        provider_no_renew.executeGet(gpa, .{
            .target = target,
            .operation = .get,
            .interaction = .always,
            .deadline = .{ .now_ms_fn = TestClock.nowMs },
        }),
    );

    // 3. Expired credential WITH non-interactive renewal within deadline succeeds.
    state = .{
        .expires_at = 1_500,
        .supports_renewal = true,
        .advance_ms_on_renew = 200,
        .renewed_expires_at = 2_500,
    };
    const provider_with_renew: Provider = .{
        .name = "mock-renew",
        .ctx = &state,
        .getFn = MockState.get,
        .renewNoninteractiveFn = MockState.renew,
    };

    var renewed = try provider_with_renew.executeGet(gpa, .{
        .target = target,
        .operation = .get,
        .interaction = .if_available,
        .deadline = .{ .now_ms_fn = TestClock.nowMs, .deadline_ms = 1_501_000 },
    });
    defer renewed.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), state.renew_called);
    try testing.expectEqualStrings("renewed-token", renewed.secret.bearer_token);

    // 4. Renewal exceeding deadline budget returns DeadlineExceeded and cleans up.
    TestClock.current_ms = 1_500_000;
    state.advance_ms_on_renew = 2_000;
    try testing.expectError(
        error.DeadlineExceeded,
        provider_with_renew.executeGet(gpa, .{
            .target = target,
            .operation = .get,
            .deadline = .{ .now_ms_fn = TestClock.nowMs, .deadline_ms = 1_501_000 },
        }),
    );
}

test "ProviderChain advances only on fallback-eligible errors and halts on authoritative errors" {
    const gpa = testing.allocator;
    var target = try Target.parseAlloc(gpa, "https://registry.example.com", .{});
    defer target.deinit(gpa);

    const StubProvider = struct {
        result_err: ?ProviderError = null,
        token: []const u8 = "fallback-token",
        calls: usize = 0,

        fn get(ctx: ?*anyopaque, alloc: Allocator, _: Request) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.calls += 1;
            if (self.result_err) |err| return err;
            return .{
                .secret = .{ .identity_token = try alloc.dupe(u8, self.token) },
            };
        }

        fn logout(ctx: ?*anyopaque, _: Allocator, _: Request) ProviderError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.calls += 1;
            if (self.result_err) |err| return err;
        }
    };

    // Empty chain returns UnsupportedTarget for valid requests.
    const empty_chain: ProviderChain = .{ .providers = &.{} };
    try testing.expectError(error.UnsupportedTarget, empty_chain.get(gpa, .{ .target = target }));

    // Fallback errors advance to the next provider.
    const fallback_errors = [_]ProviderError{
        error.UnsupportedTarget,
        error.UnsupportedOperation,
        error.CredentialNotFound,
    };
    for (fallback_errors) |fb_err| {
        var first: StubProvider = .{ .result_err = fb_err };
        var second: StubProvider = .{ .token = "second-wins" };
        const providers = [_]Provider{
            .{ .name = "first", .ctx = &first, .getFn = StubProvider.get },
            .{ .name = "second", .ctx = &second, .getFn = StubProvider.get },
        };
        const chain: ProviderChain = .{ .providers = &providers };
        var res = try chain.get(gpa, .{ .target = target });
        defer res.deinit(gpa);

        try testing.expectEqual(@as(usize, 1), first.calls);
        try testing.expectEqual(@as(usize, 1), second.calls);
        try testing.expectEqualStrings("second-wins", res.secret.identity_token);
    }

    // When all providers fall through, CredentialNotFound wins over UnsupportedOperation/UnsupportedTarget.
    {
        var p1: StubProvider = .{ .result_err = error.UnsupportedTarget };
        var p2: StubProvider = .{ .result_err = error.CredentialNotFound };
        var p3: StubProvider = .{ .result_err = error.UnsupportedOperation };
        const providers = [_]Provider{
            .{ .name = "p1", .ctx = &p1, .getFn = StubProvider.get, .logoutFn = StubProvider.logout },
            .{ .name = "p2", .ctx = &p2, .getFn = StubProvider.get, .logoutFn = StubProvider.logout },
            .{ .name = "p3", .ctx = &p3, .getFn = StubProvider.get, .logoutFn = StubProvider.logout },
        };
        const chain: ProviderChain = .{ .providers = &providers };
        try testing.expectError(error.CredentialNotFound, chain.get(gpa, .{ .target = target }));
        try testing.expectError(
            error.CredentialNotFound,
            chain.logout(gpa, .{ .target = target, .operation = .logout }),
        );
    }

    // Non-fallback errors MUST halt immediately without calling subsequent providers.
    const halting_errors = [_]ProviderError{
        error.ReauthenticationRequired,
        error.StorageUnavailable,
        error.StorageLocked,
        error.AccessDenied,
        error.Cancelled,
        error.DeadlineExceeded,
        error.InvalidInput,
        error.StorageFailure,
    };
    for (halting_errors) |halt_err| {
        var first: StubProvider = .{ .result_err = halt_err };
        var second: StubProvider = .{ .token = "must-never-be-called" };
        const providers = [_]Provider{
            .{ .name = "first", .ctx = &first, .getFn = StubProvider.get },
            .{ .name = "second", .ctx = &second, .getFn = StubProvider.get },
        };
        const chain: ProviderChain = .{ .providers = &providers };
        try testing.expectError(halt_err, chain.get(gpa, .{ .target = target }));
        try testing.expectEqual(@as(usize, 1), first.calls);
        try testing.expectEqual(@as(usize, 0), second.calls);
    }
}

test "Provider and ProviderChain login/logout lifecycle, renewal failure mapping, and OOM safety" {
    const gpa = testing.allocator;
    try testing.expect(defaultNowMs() > 1_700_000_000_000);

    var target = try Target.parseAlloc(gpa, "https://packages.example.com:8443", .{});
    defer target.deinit(gpa);

    // Renewal failure with CredentialNotFound/UnsupportedOperation maps to ReauthenticationRequired
    // so a chain never falls back to a lower-priority identity when an expired credential exists.
    const ExpiredRenewFail = struct {
        renew_err: ProviderError = error.UnsupportedOperation,

        fn get(_: ?*anyopaque, alloc: Allocator, _: Request) ProviderError!CredentialResult {
            return .{
                .secret = .{ .bearer_token = try alloc.dupe(u8, "expired-tok") },
                .expires_at = 100,
                .cache_policy = .until_expiration,
                .supports_noninteractive_renewal = true,
            };
        }

        fn renew(
            ctx: ?*anyopaque,
            alloc: Allocator,
            _: Request,
            _: *const CredentialResult,
        ) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (self.renew_err == error.ReauthenticationRequired) {
                // Return still-expired credential to verify post-renewal expiry check.
                return .{
                    .secret = .{ .bearer_token = try alloc.dupe(u8, "still-expired") },
                    .expires_at = 100,
                    .cache_policy = .until_expiration,
                };
            }
            return self.renew_err;
        }
    };

    const FallbackTrap = struct {
        called: bool = false,
        fn get(ctx: ?*anyopaque, alloc: Allocator, _: Request) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.called = true;
            return .{ .secret = .{ .bearer_token = try alloc.dupe(u8, "wrong-identity") } };
        }
    };

    TestClock.current_ms = 200_000; // 200s > 100s
    var exp_state: ExpiredRenewFail = .{ .renew_err = error.CredentialNotFound };
    var trap: FallbackTrap = .{};
    const renew_chain_providers = [_]Provider{
        .{
            .name = "expired-primary",
            .ctx = &exp_state,
            .getFn = ExpiredRenewFail.get,
            .renewNoninteractiveFn = ExpiredRenewFail.renew,
        },
        .{
            .name = "fallback-trap",
            .ctx = &trap,
            .getFn = FallbackTrap.get,
        },
    };
    const renew_chain: ProviderChain = .{ .providers = &renew_chain_providers };
    try testing.expectError(
        error.ReauthenticationRequired,
        renew_chain.get(gpa, .{
            .target = target,
            .deadline = .{ .now_ms_fn = TestClock.nowMs },
        }),
    );
    try testing.expect(!trap.called);

    // Still-expired renewed token also maps to ReauthenticationRequired without leaking.
    exp_state.renew_err = error.ReauthenticationRequired;
    try testing.expectError(
        error.ReauthenticationRequired,
        renew_chain.get(gpa, .{
            .target = target,
            .deadline = .{ .now_ms_fn = TestClock.nowMs },
        }),
    );
    try testing.expect(!trap.called);

    // Login and logout chain across read-only providers to a writable provider.
    const ReadOnlyProvider = struct {
        fn get(_: ?*anyopaque, _: Allocator, _: Request) ProviderError!CredentialResult {
            return error.UnsupportedTarget;
        }
    };
    const WritableProvider = struct {
        logged_in: usize = 0,
        logged_out: usize = 0,

        fn get(_: ?*anyopaque, _: Allocator, _: Request) ProviderError!CredentialResult {
            return error.CredentialNotFound;
        }

        fn login(ctx: ?*anyopaque, alloc: Allocator, input: LoginInput) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.logged_in += 1;
            if (input.credential) |cred| {
                return cred.clone(alloc);
            }
            return .{
                .secret = .{
                    .basic = .{
                        .username = try alloc.dupe(u8, "alice"),
                        .secret = try alloc.dupe(u8, "s3cr3t"),
                    },
                },
            };
        }

        fn logout(ctx: ?*anyopaque, _: Allocator, _: Request) ProviderError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.logged_out += 1;
        }
    };

    var writable: WritableProvider = .{};
    const rw_providers = [_]Provider{
        .{ .name = "readonly", .getFn = ReadOnlyProvider.get },
        .{
            .name = "writable",
            .ctx = &writable,
            .getFn = WritableProvider.get,
            .loginFn = WritableProvider.login,
            .logoutFn = WritableProvider.logout,
        },
    };
    const rw_chain: ProviderChain = .{ .providers = &rw_providers };

    // Wrong operation tag rejected.
    try testing.expectError(
        error.InvalidInput,
        rw_chain.login(gpa, .{ .request = .{ .target = target, .operation = .get } }),
    );
    try testing.expectError(
        error.InvalidInput,
        rw_chain.logout(gpa, .{ .target = target, .operation = .get }),
    );

    var seeded: CredentialResult = .{
        .secret = .{
            .basic = .{
                .username = try gpa.dupe(u8, "deploy-bot"),
                .secret = try gpa.dupe(u8, "pat_12345"),
            },
        },
        .account = try gpa.dupe(u8, "deploy-bot"),
    };
    defer seeded.deinit(gpa);

    var login_res = try rw_chain.login(gpa, .{
        .request = .{
            .target = target,
            .operation = .login,
            .interaction = .if_available,
        },
        .credential = &seeded,
    });
    defer login_res.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), writable.logged_in);
    try testing.expectEqualStrings("deploy-bot", login_res.secret.basic.username);

    try rw_chain.logout(gpa, .{
        .target = target,
        .operation = .logout,
    });
    try testing.expectEqual(@as(usize, 1), writable.logged_out);

    // Exhaustive OOM leak check across parse, format, service key, Target.clone, and CredentialResult.clone.
    const scopes_seed = try gpa.alloc([]u8, 2);
    scopes_seed[0] = try gpa.dupe(u8, "s1");
    scopes_seed[1] = try gpa.dupe(u8, "s2");
    var full_seed: CredentialResult = .{
        .secret = .{
            .basic = .{
                .username = try gpa.dupe(u8, "user"),
                .secret = try gpa.dupe(u8, "secret"),
            },
        },
        .account = try gpa.dupe(u8, "acct"),
        .audience = try gpa.dupe(u8, "https://api.example.com"),
        .scopes = scopes_seed,
    };
    defer full_seed.deinit(gpa);

    const oomRun = struct {
        fn run(alloc: Allocator, seed: *const CredentialResult) !void {
            var t = try Target.parseAlloc(alloc, "HTTPS://[2001:DB8::1]:8443/", .{});
            defer t.deinit(alloc);

            const auth = try t.authorityAlloc(alloc);
            defer alloc.free(auth);

            const uri = try t.formatUriAlloc(alloc);
            defer alloc.free(uri);

            const key = try t.serviceKeyAlloc(alloc, "credential-provider://", true);
            defer alloc.free(key);

            var t_clone = try t.clone(alloc);
            defer t_clone.deinit(alloc);

            var cloned = try seed.clone(alloc);
            defer cloned.deinit(alloc);
        }
    }.run;

    try testing.checkAllAllocationFailures(gpa, oomRun, .{&full_seed});
}
