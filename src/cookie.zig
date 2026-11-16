//! `keyring cookie` — Encrypted, chunked browser cookie-jar storage and
//! ephemeral private-directory execution across OS keyrings and encrypted stores.
//!
//! Storage layout under service `browser-cookie://<profile>`:
//! - Account `manifest`: JSON metadata
//!   `{"v":1,"chunks":N,"encoding":"zlib+base64"|"base64","sha256":"<hex>","gen":"<12-hex>","domains":[...]}`
//!   where `sha256` is computed over the canonical compact CDP JSON array.
//! - Accounts `chunk-<gen>-0` .. `chunk-<gen>-{N-1}` (legacy `chunk-0` .. `chunk-{N-1}`
//!   supported on read): printable Base64 ASCII slices, each at most
//!   `max_chunk_bytes` (1,800 bytes), fitting comfortably within Windows
//!   Credential Manager's 2,560-byte `CRED_MAX_CREDENTIAL_BLOB_SIZE` limit as
//!   well as macOS Keychain, Linux Secret Service, and `file` stores.
const std = @import("std");
const builtin = @import("builtin");
const keyring_zig = @import("keyring_zig");
const ado = @import("ado.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const flate = std.compress.flate;

pub const service_prefix = "browser-cookie://";
pub const manifest_account = "manifest";
pub const chunk_account_prefix = "chunk-";
pub const max_chunk_bytes: usize = 1800;
pub const manifest_version: u32 = 1;
pub const manifest_gen_hex_len: usize = 12;
pub const max_profile_len: usize = 256;
pub const max_cookie_input_bytes: usize = 16 * 1024 * 1024;
pub const max_chunks: usize = 16384;

pub const usage_text =
    \\usage: keyring cookie <subcommand> [options]
    \\
    \\Subcommands:
    \\  import <profile> [<file|->] [--domain <suffix>]...
    \\      Import cookies from CDP/Playwright JSON or Netscape cookies.txt.
    \\  export <profile> [--format cdp|netscape]
    \\      Export stored cookies to stdout (default: cdp).
    \\  status <profile>
    \\      Show cookie count, unique domains, and expiry summary (no values).
    \\  delete <profile>
    \\      Delete all stored chunks and manifest for <profile>.
    \\  exec <profile> [--update] [--format cdp|netscape] [--domain <suffix>]... -- <cmd> [args...]
    \\      Materialize cookies into an ephemeral 0700 directory (/dev/shm RAM-backed
    \\      tmpfs on Linux when available, private 0700 temp directory via
    \\      TMPDIR/TEMP/TMP on macOS/Windows), substitute {cookie} and {cookie_jar}
    \\      (and set KEYRING_COOKIE_FILE / KEYRING_COOKIE_JAR_FILE), run <cmd>,
    \\      optionally merge updated cookies back into keyring (--update), and
    \\      zero-wipe + delete ephemeral files.
    \\
;

pub const SecretError = error{
    EntryNotFound,
    NoStorageAccess,
    Locked,
    StorageFailure,
    OutOfMemory,
};

pub const CookieError = SecretError || error{
    InvalidProfile,
    InvalidCookieFormat,
    IncompatibleNetscapeCookie,
    EmptyCookieJar,
    CorruptCookieJar,
    IntegrityCheckFailed,
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

var secret_store_override: ?SecretStore = null;
var runtime_env_map: ?*const std.process.Environ.Map = null;
var ephemeral_base_dir_override: ?[]const u8 = null;

pub fn setRuntimeEnvMap(env_map: ?*const std.process.Environ.Map) void {
    runtime_env_map = env_map;
}

pub fn setTestOverrides(store: ?SecretStore, base_dir: ?[]const u8) void {
    secret_store_override = store;
    ephemeral_base_dir_override = base_dir;
}

fn activeSecretStore() SecretStore {
    return secret_store_override orelse live_secret_store;
}

fn isStorageDisabled() bool {
    if (secret_store_override != null) return false;
    return keyring_zig.currentBackend() == .null_backend;
}

fn liveSecretGet(gpa: Allocator, service: []const u8, account: []const u8) SecretError![]u8 {
    if (isStorageDisabled()) return error.NoStorageAccess;
    return keyring_zig.getAlloc(gpa, service, account) catch |err| mapKeyringError(err);
}

fn liveSecretSet(gpa: Allocator, service: []const u8, account: []const u8, value: []const u8) SecretError!void {
    if (isStorageDisabled()) return error.NoStorageAccess;
    return keyring_zig.setAlloc(gpa, service, account, value) catch |err| mapKeyringError(err);
}

fn liveSecretDelete(gpa: Allocator, service: []const u8, account: []const u8) SecretError!void {
    if (isStorageDisabled()) return error.NoStorageAccess;
    return keyring_zig.deleteAlloc(gpa, service, account) catch |err| mapKeyringError(err);
}

fn mapKeyringError(err: keyring_zig.Error) SecretError {
    return switch (err) {
        error.EntryNotFound => error.EntryNotFound,
        error.Locked => error.Locked,
        error.NoStorageAccess => error.NoStorageAccess,
        error.OutOfMemory => error.OutOfMemory,
        else => error.StorageFailure,
    };
}

/// Allocator wrapper that zeroes every freed or shrunk allocation so intermediate
/// JSON serialization, decompression, and parsing buffers never leave plaintext
/// cookie values in heap memory.
const ZeroOnFreeAllocator = struct {
    backing: Allocator,

    fn allocator(self: *ZeroOnFreeAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = Allocator.noRemap,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *ZeroOnFreeAllocator = @ptrCast(@alignCast(ctx));
        return self.backing.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *ZeroOnFreeAllocator = @ptrCast(@alignCast(ctx));
        if (new_len < memory.len) {
            std.crypto.secureZero(u8, memory[new_len..]);
        }
        return self.backing.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *ZeroOnFreeAllocator = @ptrCast(@alignCast(ctx));
        std.crypto.secureZero(u8, memory);
        self.backing.rawFree(memory, alignment, ret_addr);
    }
};

// ---------------------------------------------------------------------------
// Data Types & CLI Parsing
// ---------------------------------------------------------------------------

pub const Format = enum {
    cdp,
    netscape,

    pub fn fromString(raw: []const u8) ?Format {
        if (std.ascii.eqlIgnoreCase(raw, "cdp") or std.ascii.eqlIgnoreCase(raw, "json")) return .cdp;
        if (std.ascii.eqlIgnoreCase(raw, "netscape")) return .netscape;
        return null;
    }

    pub fn defaultCookieFilename(self: Format) []const u8 {
        return switch (self) {
            .cdp => "cookies.json",
            .netscape => "cookies.txt",
        };
    }
};

pub const SameSite = enum {
    strict,
    lax,
    none,

    pub fn fromString(raw: []const u8) error{InvalidCookieFormat}!?SameSite {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len == 0 or std.ascii.eqlIgnoreCase(trimmed, "unspecified")) return null;
        if (std.ascii.eqlIgnoreCase(trimmed, "strict")) return .strict;
        if (std.ascii.eqlIgnoreCase(trimmed, "lax")) return .lax;
        if (std.ascii.eqlIgnoreCase(trimmed, "none") or
            std.ascii.eqlIgnoreCase(trimmed, "no_restriction"))
        {
            return .none;
        }
        return error.InvalidCookieFormat;
    }

    pub fn asCdpString(self: SameSite) []const u8 {
        return switch (self) {
            .strict => "Strict",
            .lax => "Lax",
            .none => "None",
        };
    }
};

pub const Cookie = struct {
    name: []const u8,
    value: []const u8,
    domain: []const u8,
    path: []const u8 = "/",
    /// Unix timestamp in seconds for persistent cookies, or `null` for session cookies.
    expires: ?f64 = null,
    http_only: bool = false,
    secure: bool = false,
    same_site: ?SameSite = null,
};

pub const Manifest = struct {
    v: u32 = manifest_version,
    chunks: usize,
    encoding: []const u8,
    sha256: []const u8,
    gen: ?[]const u8 = null,
    domains: []const []const u8 = &.{},

    pub fn deinit(self: *const Manifest, gpa: Allocator) void {
        gpa.free(self.encoding);
        gpa.free(self.sha256);
        if (self.gen) |g| gpa.free(g);
        for (self.domains) |d| gpa.free(d);
        if (self.domains.len > 0) gpa.free(self.domains);
    }
};

const ManifestWire = struct {
    v: u32 = manifest_version,
    chunks: usize,
    encoding: []const u8,
    sha256: []const u8,
    gen: ?[]const u8 = null,
    domains: ?[]const []const u8 = null,
};

pub const ImportOptions = struct {
    profile: []const u8,
    source: ?[]const u8 = null,
    raw_args: []const []const u8 = &.{},
};

pub const ExportOptions = struct {
    profile: []const u8,
    format: Format = .cdp,
};

pub const ExecOptions = struct {
    profile: []const u8,
    update: bool = false,
    format: Format = .cdp,
    raw_head_args: []const []const u8 = &.{},
    argv: []const []const u8,
};

pub const Subcommand = union(enum) {
    help,
    import_cmd: ImportOptions,
    export_cmd: ExportOptions,
    status: struct { profile: []const u8 },
    delete: struct { profile: []const u8 },
    exec: ExecOptions,
};

pub fn isValidProfile(profile: []const u8) bool {
    if (profile.len == 0 or profile.len > max_profile_len) return false;
    for (profile) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-')) {
            return false;
        }
    }
    return true;
}

pub fn parseArgs(args: []const []const u8) ?Subcommand {
    if (args.len == 0) return null;
    const sub = args[0];
    const rest = args[1..];

    if (std.mem.eql(u8, sub, "--help") or
        std.mem.eql(u8, sub, "-h") or
        std.mem.eql(u8, sub, "help"))
    {
        return if (rest.len == 0) .help else null;
    }
    if (std.mem.eql(u8, sub, "import")) return parseImportArgs(rest);
    if (std.mem.eql(u8, sub, "export")) return parseExportArgs(rest);
    if (std.mem.eql(u8, sub, "status")) {
        if (rest.len == 1 and (std.mem.eql(u8, rest[0], "--help") or std.mem.eql(u8, rest[0], "-h"))) return .help;
        if (rest.len != 1 or rest[0].len == 0 or std.mem.startsWith(u8, rest[0], "-")) return null;
        return .{ .status = .{ .profile = rest[0] } };
    }
    if (std.mem.eql(u8, sub, "delete")) {
        if (rest.len == 1 and (std.mem.eql(u8, rest[0], "--help") or std.mem.eql(u8, rest[0], "-h"))) return .help;
        if (rest.len != 1 or rest[0].len == 0 or std.mem.startsWith(u8, rest[0], "-")) return null;
        return .{ .delete = .{ .profile = rest[0] } };
    }
    if (std.mem.eql(u8, sub, "exec")) return parseExecArgs(rest);
    return null;
}

fn hasNonEmptyDomainToken(raw: []const u8) bool {
    var it = std.mem.splitScalar(u8, raw, ',');
    var found = false;
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t");
        const bare = std.mem.trimStart(u8, trimmed, ".");
        if (!isValidDomainChars(bare)) return false;
        found = true;
    }
    return found;
}

fn parseImportArgs(args: []const []const u8) ?Subcommand {
    var profile: ?[]const u8 = null;
    var source: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return .help;
        } else if (std.mem.eql(u8, arg, "--domain")) {
            if (i + 1 >= args.len or !hasNonEmptyDomainToken(args[i + 1])) return null;
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--domain=")) {
            const val = arg["--domain=".len..];
            if (!hasNonEmptyDomainToken(val)) return null;
            i += 1;
        } else if (std.mem.startsWith(u8, arg, "-") and !std.mem.eql(u8, arg, "-")) {
            return null;
        } else {
            if (profile == null) {
                if (std.mem.eql(u8, arg, "-")) return null;
                profile = arg;
            } else if (source == null) {
                if (arg.len == 0) return null;
                source = arg;
            } else {
                return null;
            }
            i += 1;
        }
    }

    const prof = profile orelse return null;
    return .{
        .import_cmd = .{
            .profile = prof,
            .source = source,
            .raw_args = args,
        },
    };
}

fn appendNormalizedDomainSuffix(gpa: Allocator, list: *std.ArrayList([]const u8), raw_part: []const u8) Allocator.Error!void {
    const bare = stripLeadingDots(raw_part);
    if (bare.len == 0) return;
    const norm = try normalizedDomainAlloc(gpa, bare);
    for (list.items) |existing| {
        if (std.mem.eql(u8, existing, norm)) {
            gpa.free(norm);
            return;
        }
    }
    errdefer gpa.free(norm);
    try list.append(gpa, norm);
}

fn collectDomainSuffixes(gpa: Allocator, raw_args: []const []const u8) ![][]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |item| gpa.free(item);
        list.deinit(gpa);
    }

    var i: usize = 0;
    while (i < raw_args.len) {
        const arg = raw_args[i];
        if (std.mem.eql(u8, arg, "--domain")) {
            var it = std.mem.splitScalar(u8, raw_args[i + 1], ',');
            while (it.next()) |part| {
                try appendNormalizedDomainSuffix(gpa, &list, part);
            }
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--domain=")) {
            var it = std.mem.splitScalar(u8, arg["--domain=".len..], ',');
            while (it.next()) |part| {
                try appendNormalizedDomainSuffix(gpa, &list, part);
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    return list.toOwnedSlice(gpa);
}

fn parseExportArgs(args: []const []const u8) ?Subcommand {
    var profile: ?[]const u8 = null;
    var format: Format = .cdp;

    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return .help;
        } else if (std.mem.eql(u8, arg, "--format")) {
            if (i + 1 >= args.len) return null;
            format = Format.fromString(args[i + 1]) orelse return null;
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--format=")) {
            format = Format.fromString(arg["--format=".len..]) orelse return null;
            i += 1;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return null;
        } else {
            if (profile != null or arg.len == 0) return null;
            profile = arg;
            i += 1;
        }
    }

    const prof = profile orelse return null;
    return .{
        .export_cmd = .{
            .profile = prof,
            .format = format,
        },
    };
}

fn parseExecArgs(args: []const []const u8) ?Subcommand {
    var dash_dash: ?usize = null;
    for (args, 0..) |arg, idx| {
        if (std.mem.eql(u8, arg, "--")) {
            dash_dash = idx;
            break;
        }
    }
    if (dash_dash == null) {
        for (args) |arg| {
            if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return .help;
        }
        return null;
    }

    const head = args[0..dash_dash.?];
    const argv = args[dash_dash.? + 1 ..];
    if (argv.len == 0 or argv[0].len == 0) return null;

    var profile: ?[]const u8 = null;
    var update = false;
    var format: Format = .cdp;

    var i: usize = 0;
    while (i < head.len) {
        const arg = head[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return .help;
        } else if (std.mem.eql(u8, arg, "--update")) {
            update = true;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--format")) {
            if (i + 1 >= head.len) return null;
            format = Format.fromString(head[i + 1]) orelse return null;
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--format=")) {
            format = Format.fromString(arg["--format=".len..]) orelse return null;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--domain")) {
            if (i + 1 >= head.len or !hasNonEmptyDomainToken(head[i + 1])) return null;
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--domain=")) {
            if (!hasNonEmptyDomainToken(arg["--domain=".len..])) return null;
            i += 1;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return null;
        } else {
            if (profile != null or arg.len == 0) return null;
            profile = arg;
            i += 1;
        }
    }

    const prof = profile orelse return null;
    return .{
        .exec = .{
            .profile = prof,
            .update = update,
            .format = format,
            .raw_head_args = head,
            .argv = argv,
        },
    };
}

// ---------------------------------------------------------------------------
// Domain Normalization, Filtering, Parsing, Serialization & Merge
// ---------------------------------------------------------------------------

/// Strip all leading `.` characters from a domain string.
pub fn stripLeadingDots(domain: []const u8) []const u8 {
    return std.mem.trimStart(u8, std.mem.trim(u8, domain, " \t"), ".");
}

fn hasInvalidFieldControlChars(s: []const u8, allow_tab: bool) bool {
    for (s) |c| {
        if (c == 0 or c == 0x7f) return true;
        if (c < 0x20 and !(allow_tab and c == '\t')) return true;
    }
    return false;
}

fn isValidDomainChars(bare: []const u8) bool {
    if (bare.len == 0) return false;
    for (bare) |c| {
        if (c <= 0x20 or c == 0x7f or c == '/' or c == '\\' or c == '\t') return false;
    }
    return true;
}

/// Canonicalize a cookie domain: lowercase ASCII letters, preserve at most one
/// leading `.` when `leading_dot` is true, and validate characters.
fn canonicalizeDomainAlloc(gpa: Allocator, raw_domain: []const u8, force_leading_dot: ?bool) error{ OutOfMemory, InvalidCookieFormat }![]u8 {
    const trimmed = std.mem.trim(u8, raw_domain, " \t");
    if (trimmed.len == 0) return error.InvalidCookieFormat;
    const had_leading_dot = trimmed[0] == '.';
    const bare = std.mem.trimStart(u8, trimmed, ".");
    if (!isValidDomainChars(bare)) return error.InvalidCookieFormat;

    const want_dot = force_leading_dot orelse had_leading_dot;
    const out_len = bare.len + @as(usize, if (want_dot) 1 else 0);
    const out = try gpa.alloc(u8, out_len);
    var offset: usize = 0;
    if (want_dot) {
        out[0] = '.';
        offset = 1;
    }
    for (bare, 0..) |c, idx| {
        out[offset + idx] = std.ascii.toLower(c);
    }
    return out;
}

/// Allocate normalized domain key (no leading `.`, ASCII lowercased).
pub fn normalizedDomainAlloc(gpa: Allocator, domain: []const u8) Allocator.Error![]u8 {
    const bare = stripLeadingDots(domain);
    const out = try gpa.alloc(u8, bare.len);
    for (bare, 0..) |c, idx| {
        out[idx] = std.ascii.toLower(c);
    }
    return out;
}

/// Check whether `cookie_domain` matches `suffix` (either exact domain match or
/// subdomain ending with `.<suffix>`, case-insensitively after stripping leading `.`).
pub fn matchesDomainSuffix(cookie_domain: []const u8, suffix: []const u8) bool {
    const dom = stripLeadingDots(cookie_domain);
    const suf = stripLeadingDots(suffix);
    if (dom.len == 0 or suf.len == 0) return false;
    if (std.ascii.eqlIgnoreCase(dom, suf)) return true;
    if (dom.len > suf.len and
        dom[dom.len - suf.len - 1] == '.' and
        std.ascii.endsWithIgnoreCase(dom, suf))
    {
        return true;
    }
    return false;
}

pub fn matchesAnyDomainSuffix(cookie_domain: []const u8, suffixes: []const []const u8) bool {
    if (suffixes.len == 0) return true;
    for (suffixes) |suf| {
        if (matchesDomainSuffix(cookie_domain, suf)) return true;
    }
    return false;
}

fn dupeCookie(gpa: Allocator, c: Cookie) Allocator.Error!Cookie {
    const name = try gpa.dupe(u8, c.name);
    errdefer gpa.free(name);
    const value = try gpa.dupe(u8, c.value);
    errdefer gpa.free(value);
    const domain = try gpa.dupe(u8, c.domain);
    errdefer gpa.free(domain);
    const path = try gpa.dupe(u8, c.path);
    return .{
        .name = name,
        .value = value,
        .domain = domain,
        .path = path,
        .expires = c.expires,
        .http_only = c.http_only,
        .secure = c.secure,
        .same_site = c.same_site,
    };
}

fn freeCookie(gpa: Allocator, c: *const Cookie) void {
    std.crypto.secureZero(u8, @constCast(c.name));
    gpa.free(c.name);
    std.crypto.secureZero(u8, @constCast(c.value));
    gpa.free(c.value);
    gpa.free(c.domain);
    gpa.free(c.path);
}

pub fn freeCookies(gpa: Allocator, cookies: []const Cookie) void {
    for (cookies) |*c| freeCookie(gpa, c);
    gpa.free(cookies);
}

fn hasLeadingDot(domain: []const u8) bool {
    const trimmed = std.mem.trim(u8, domain, " \t");
    return trimmed.len > 0 and trimmed[0] == '.';
}

fn sameCookieIdentity(a: Cookie, b: Cookie) bool {
    if (!std.mem.eql(u8, a.name, b.name)) return false;
    if (!std.mem.eql(u8, a.path, b.path)) return false;
    if (hasLeadingDot(a.domain) != hasLeadingDot(b.domain)) return false;
    return std.ascii.eqlIgnoreCase(stripLeadingDots(a.domain), stripLeadingDots(b.domain));
}

fn cookieLessThan(_: void, a: Cookie, b: Cookie) bool {
    const a_norm = stripLeadingDots(a.domain);
    const b_norm = stripLeadingDots(b.domain);
    const dom_order = std.ascii.orderIgnoreCase(a_norm, b_norm);
    if (dom_order != .eq) return dom_order == .lt;
    const a_dot = hasLeadingDot(a.domain);
    const b_dot = hasLeadingDot(b.domain);
    if (a_dot != b_dot) return !a_dot and b_dot;
    const path_order = std.mem.order(u8, a.path, b.path);
    if (path_order != .eq) return path_order == .lt;
    return std.mem.order(u8, a.name, b.name) == .lt;
}

fn isCookieExpiredAt(c: Cookie, now_epoch: i64) bool {
    if (now_epoch <= 0) return false;
    if (c.expires) |exp| {
        if (exp > 0 and exp < @as(f64, @floatFromInt(now_epoch))) {
            return true;
        }
    }
    return false;
}

/// Merge `incoming` cookies onto `existing` keyed by `(name, domain, path)`
/// (preserving host-only vs `.domain` distinction).
pub fn mergeCookiesAlloc(
    gpa: Allocator,
    existing: []const Cookie,
    incoming: []const Cookie,
) Allocator.Error![]Cookie {
    return mergeCookiesForUpdateAlloc(gpa, existing, incoming, &.{}, 0);
}

/// Merge `incoming` cookies onto `existing` for `exec --update`:
/// 1. Retains `existing` cookies across unvisited domains,
/// 2. Filters `incoming` cookies against `allowed_domains` (when non-empty),
/// 3. Upserts matching cookies by `(name, domain, path)`, and
/// 4. Prunes expired non-session cookies (`expires > 0 and expires < now_epoch`)
///    when `now_epoch > 0` so `Max-Age=0` / `expires=1` deletions take effect.
pub fn mergeCookiesForUpdateAlloc(
    gpa: Allocator,
    existing: []const Cookie,
    incoming: []const Cookie,
    allowed_domains: []const []const u8,
    now_epoch: i64,
) Allocator.Error![]Cookie {
    var list: std.ArrayList(Cookie) = .empty;
    errdefer {
        for (list.items) |*c| freeCookie(gpa, c);
        list.deinit(gpa);
    }

    for (existing) |c| {
        try upsertIntoCookieList(gpa, &list, c);
    }
    for (incoming) |c| {
        if (!matchesAnyDomainSuffix(c.domain, allowed_domains)) continue;
        try upsertIntoCookieList(gpa, &list, c);
    }

    if (now_epoch > 0) {
        var write_idx: usize = 0;
        for (list.items) |c| {
            if (isCookieExpiredAt(c, now_epoch)) {
                freeCookie(gpa, &c);
            } else {
                list.items[write_idx] = c;
                write_idx += 1;
            }
        }
        list.items.len = write_idx;
    }

    std.mem.sort(Cookie, list.items, {}, cookieLessThan);
    return list.toOwnedSlice(gpa);
}

fn upsertOwnedCookieIntoList(gpa: Allocator, list: *std.ArrayList(Cookie), owned_cookie: Cookie) Allocator.Error!void {
    errdefer freeCookie(gpa, &owned_cookie);

    for (list.items) |*slot| {
        if (sameCookieIdentity(slot.*, owned_cookie)) {
            freeCookie(gpa, slot);
            slot.* = owned_cookie;
            return;
        }
    }
    try list.append(gpa, owned_cookie);
}

fn upsertIntoCookieList(gpa: Allocator, list: *std.ArrayList(Cookie), candidate: Cookie) Allocator.Error!void {
    const cloned = try dupeCookie(gpa, candidate);
    try upsertOwnedCookieIntoList(gpa, list, cloned);
}

fn wipeJsonValue(val: *std.json.Value) void {
    switch (val.*) {
        .string => |s| std.crypto.secureZero(u8, @constCast(s)),
        .number_string => |s| std.crypto.secureZero(u8, @constCast(s)),
        .array => |*arr| {
            for (arr.items) |*elem| wipeJsonValue(elem);
        },
        .object => |*obj| {
            var it = obj.iterator();
            while (it.next()) |entry| {
                std.crypto.secureZero(u8, @constCast(entry.key_ptr.*));
                wipeJsonValue(entry.value_ptr);
            }
        },
        else => {},
    }
}

/// Auto-detect and parse cookies from CDP JSON array, Playwright `storageState`
/// (`{ "cookies": [...] }`), or Netscape `cookies.txt`.
pub fn parseCookiesAutoAlloc(
    gpa: Allocator,
    raw_input: []const u8,
) (Allocator.Error || error{InvalidCookieFormat})![]Cookie {
    var zero_alloc: ZeroOnFreeAllocator = .{ .backing = gpa };
    const z_gpa = zero_alloc.allocator();

    const without_bom = if (std.mem.startsWith(u8, raw_input, "\xEF\xBB\xBF"))
        raw_input[3..]
    else
        raw_input;
    const trimmed = std.mem.trim(u8, without_bom, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidCookieFormat;

    if (trimmed[0] == '[' or trimmed[0] == '{') {
        return parseCookiesJsonAlloc(gpa, z_gpa, trimmed);
    }
    return parseCookiesNetscapeAlloc(gpa, trimmed);
}

fn parseCookiesJsonAlloc(
    out_gpa: Allocator,
    scratch_gpa: Allocator,
    trimmed_json: []const u8,
) (Allocator.Error || error{InvalidCookieFormat})![]Cookie {
    var parsed = std.json.parseFromSlice(std.json.Value, scratch_gpa, trimmed_json, .{
        .allocate = .alloc_always,
    }) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidCookieFormat,
    };
    defer {
        wipeJsonValue(&parsed.value);
        parsed.deinit();
    }

    const items: []const std.json.Value = switch (parsed.value) {
        .array => |arr| arr.items,
        .object => |obj| blk: {
            const cookies_val = obj.get("cookies") orelse return error.InvalidCookieFormat;
            switch (cookies_val) {
                .array => |arr| break :blk arr.items,
                else => return error.InvalidCookieFormat,
            }
        },
        else => return error.InvalidCookieFormat,
    };

    var list: std.ArrayList(Cookie) = .empty;
    errdefer {
        for (list.items) |*c| freeCookie(out_gpa, c);
        list.deinit(out_gpa);
    }

    for (items) |item| {
        const obj = switch (item) {
            .object => |o| o,
            else => return error.InvalidCookieFormat,
        };

        const raw_name = switch (obj.get("name") orelse return error.InvalidCookieFormat) {
            .string => |s| s,
            else => return error.InvalidCookieFormat,
        };
        if (raw_name.len == 0 or hasInvalidFieldControlChars(raw_name, false)) {
            return error.InvalidCookieFormat;
        }

        const raw_value = switch (obj.get("value") orelse return error.InvalidCookieFormat) {
            .string => |s| s,
            else => return error.InvalidCookieFormat,
        };
        if (hasInvalidFieldControlChars(raw_value, true)) {
            return error.InvalidCookieFormat;
        }

        const raw_domain = switch (obj.get("domain") orelse return error.InvalidCookieFormat) {
            .string => |s| s,
            else => return error.InvalidCookieFormat,
        };

        const raw_path: []const u8 = if (obj.get("path")) |pv| switch (pv) {
            .string => |s| if (s.len == 0) "/" else s,
            .null => "/",
            else => return error.InvalidCookieFormat,
        } else "/";
        if (hasInvalidFieldControlChars(raw_path, false)) {
            return error.InvalidCookieFormat;
        }

        const is_session: bool = if (obj.get("session")) |sv| switch (sv) {
            .bool => |b| b,
            .null => false,
            else => return error.InvalidCookieFormat,
        } else false;

        const exp_val = obj.get("expires") orelse obj.get("expirationDate");
        const expires: ?f64 = if (is_session)
            null
        else if (exp_val) |ev| switch (ev) {
            .null => null,
            .integer => |iv| if (iv <= 0) null else @floatFromInt(iv),
            .float => |fv| if (!std.math.isFinite(fv) or fv <= 0) null else fv,
            else => return error.InvalidCookieFormat,
        } else null;

        const http_only: bool = if (obj.get("httpOnly")) |hv| switch (hv) {
            .bool => |b| b,
            .null => false,
            else => return error.InvalidCookieFormat,
        } else false;

        const secure: bool = if (obj.get("secure")) |sv| switch (sv) {
            .bool => |b| b,
            .null => false,
            else => return error.InvalidCookieFormat,
        } else false;

        const same_site: ?SameSite = if (obj.get("sameSite")) |ssv| switch (ssv) {
            .null => null,
            .string => |s| try SameSite.fromString(s),
            else => return error.InvalidCookieFormat,
        } else null;

        const candidate: Cookie = blk: {
            const domain = try canonicalizeDomainAlloc(out_gpa, raw_domain, null);
            errdefer out_gpa.free(domain);
            const name = try out_gpa.dupe(u8, raw_name);
            errdefer {
                std.crypto.secureZero(u8, name);
                out_gpa.free(name);
            }
            const value = try out_gpa.dupe(u8, raw_value);
            errdefer {
                std.crypto.secureZero(u8, value);
                out_gpa.free(value);
            }
            const path = try out_gpa.dupe(u8, raw_path);
            break :blk .{
                .name = name,
                .value = value,
                .domain = domain,
                .path = path,
                .expires = expires,
                .http_only = http_only,
                .secure = secure,
                .same_site = same_site,
            };
        };
        try upsertOwnedCookieIntoList(out_gpa, &list, candidate);
    }

    std.mem.sort(Cookie, list.items, {}, cookieLessThan);
    return list.toOwnedSlice(out_gpa);
}

fn parseNetscapeBool(raw: []const u8) error{InvalidCookieFormat}!bool {
    const t = std.mem.trim(u8, raw, " \r");
    if (std.ascii.eqlIgnoreCase(t, "TRUE")) return true;
    if (std.ascii.eqlIgnoreCase(t, "FALSE")) return false;
    return error.InvalidCookieFormat;
}

fn parseCookiesNetscapeAlloc(
    gpa: Allocator,
    input: []const u8,
) (Allocator.Error || error{InvalidCookieFormat})![]Cookie {
    var list: std.ArrayList(Cookie) = .empty;
    errdefer {
        for (list.items) |*c| freeCookie(gpa, c);
        list.deinit(gpa);
    }

    const http_only_prefix = "#HttpOnly_";
    var saw_any_record_or_comment = false;
    var lines = std.mem.splitScalar(u8, input, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        const trimmed_left = std.mem.trimStart(u8, line, " \t");
        if (trimmed_left.len == 0) continue;

        var http_only = false;
        var payload_line = line;
        if (std.ascii.startsWithIgnoreCase(line, http_only_prefix)) {
            http_only = true;
            payload_line = line[http_only_prefix.len..];
        } else if (trimmed_left[0] == '#') {
            saw_any_record_or_comment = true;
            continue;
        }

        var cols: [7][]const u8 = undefined;
        var col_idx: usize = 0;
        var col_it = std.mem.splitScalar(u8, payload_line, '\t');
        while (col_it.next()) |col| {
            if (col_idx >= 7) return error.InvalidCookieFormat;
            cols[col_idx] = col;
            col_idx += 1;
        }
        if (col_idx != 7) return error.InvalidCookieFormat;
        saw_any_record_or_comment = true;

        const include_subdomains = try parseNetscapeBool(cols[1]);
        const secure = try parseNetscapeBool(cols[3]);
        const exp_i64 = std.fmt.parseInt(i64, std.mem.trim(u8, cols[4], " "), 10) catch
            return error.InvalidCookieFormat;
        const expires: ?f64 = if (exp_i64 <= 0) null else @floatFromInt(exp_i64);

        const raw_name = cols[5];
        if (raw_name.len == 0 or hasInvalidFieldControlChars(raw_name, false)) {
            return error.InvalidCookieFormat;
        }
        const raw_value = cols[6];
        if (hasInvalidFieldControlChars(raw_value, false)) {
            return error.InvalidCookieFormat;
        }

        const raw_path = if (cols[2].len == 0) "/" else cols[2];
        if (hasInvalidFieldControlChars(raw_path, false)) {
            return error.InvalidCookieFormat;
        }

        const candidate: Cookie = blk: {
            const domain = try canonicalizeDomainAlloc(gpa, cols[0], include_subdomains);
            errdefer gpa.free(domain);
            const name = try gpa.dupe(u8, raw_name);
            errdefer {
                std.crypto.secureZero(u8, name);
                gpa.free(name);
            }
            const value = try gpa.dupe(u8, raw_value);
            errdefer {
                std.crypto.secureZero(u8, value);
                gpa.free(value);
            }
            const path = try gpa.dupe(u8, raw_path);
            break :blk .{
                .name = name,
                .value = value,
                .domain = domain,
                .path = path,
                .expires = expires,
                .http_only = http_only,
                .secure = secure,
                .same_site = null,
            };
        };
        try upsertOwnedCookieIntoList(gpa, &list, candidate);
    }

    if (!saw_any_record_or_comment) return error.InvalidCookieFormat;
    std.mem.sort(Cookie, list.items, {}, cookieLessThan);
    return list.toOwnedSlice(gpa);
}

/// Serialize cookies to canonical compact CDP JSON array (no trailing newline).
pub fn serializeCookiesCdpAlloc(gpa: Allocator, cookies: []const Cookie) Allocator.Error![]u8 {
    var zero_alloc: ZeroOnFreeAllocator = .{ .backing = gpa };
    const z_gpa = zero_alloc.allocator();

    var out: Io.Writer.Allocating = .init(z_gpa);
    defer out.deinit();

    var jw: std.json.Stringify = .{
        .writer = &out.writer,
        .options = .{},
    };

    jw.beginArray() catch return error.OutOfMemory;
    for (cookies) |c| {
        jw.beginObject() catch return error.OutOfMemory;

        jw.objectField("name") catch return error.OutOfMemory;
        jw.write(c.name) catch return error.OutOfMemory;

        jw.objectField("value") catch return error.OutOfMemory;
        jw.write(c.value) catch return error.OutOfMemory;

        jw.objectField("domain") catch return error.OutOfMemory;
        jw.write(c.domain) catch return error.OutOfMemory;

        jw.objectField("path") catch return error.OutOfMemory;
        jw.write(if (c.path.len == 0) "/" else c.path) catch return error.OutOfMemory;

        jw.objectField("expires") catch return error.OutOfMemory;
        if (c.expires) |exp| {
            if (exp > 0 and @floor(exp) == exp and exp <= 9_007_199_254_740_991.0) {
                const exp_int: i64 = @intFromFloat(exp);
                jw.write(exp_int) catch return error.OutOfMemory;
            } else if (exp > 0) {
                jw.write(exp) catch return error.OutOfMemory;
            } else {
                jw.write(@as(i32, -1)) catch return error.OutOfMemory;
            }
        } else {
            jw.write(@as(i32, -1)) catch return error.OutOfMemory;
        }

        jw.objectField("httpOnly") catch return error.OutOfMemory;
        jw.write(c.http_only) catch return error.OutOfMemory;

        jw.objectField("secure") catch return error.OutOfMemory;
        jw.write(c.secure) catch return error.OutOfMemory;

        if (c.same_site) |ss| {
            jw.objectField("sameSite") catch return error.OutOfMemory;
            jw.write(ss.asCdpString()) catch return error.OutOfMemory;
        }

        jw.endObject() catch return error.OutOfMemory;
    }
    jw.endArray() catch return error.OutOfMemory;

    return gpa.dupe(u8, out.written());
}

fn sanitizeNetscapeToken(s: []const u8) error{IncompatibleNetscapeCookie}![]const u8 {
    for (s) |c| {
        if (c == '\t' or c == '\r' or c == '\n' or c == 0 or c < 0x20 or c == 0x7f) {
            return error.IncompatibleNetscapeCookie;
        }
    }
    return s;
}

/// Serialize cookies to Netscape `cookies.txt` format.
pub fn serializeCookiesNetscapeAlloc(
    gpa: Allocator,
    cookies: []const Cookie,
) (Allocator.Error || error{IncompatibleNetscapeCookie})![]u8 {
    var zero_alloc: ZeroOnFreeAllocator = .{ .backing = gpa };
    const z_gpa = zero_alloc.allocator();

    var out: Io.Writer.Allocating = .init(z_gpa);
    defer out.deinit();

    out.writer.writeAll("# Netscape HTTP Cookie File\n") catch return error.OutOfMemory;
    for (cookies) |c| {
        const domain = try sanitizeNetscapeToken(c.domain);
        const path = try sanitizeNetscapeToken(if (c.path.len == 0) "/" else c.path);
        const name = try sanitizeNetscapeToken(c.name);
        const value = try sanitizeNetscapeToken(c.value);

        const include_subdomains = domain.len > 0 and domain[0] == '.';
        const expiry: i64 = if (c.expires) |exp|
            if (exp > 0 and exp < @as(f64, @floatFromInt(std.math.maxInt(i64))))
                @intFromFloat(@floor(exp))
            else
                0
        else
            0;

        out.writer.print(
            "{s}{s}\t{s}\t{s}\t{s}\t{d}\t{s}\t{s}\n",
            .{
                if (c.http_only) "#HttpOnly_" else "",
                domain,
                if (include_subdomains) "TRUE" else "FALSE",
                path,
                if (c.secure) "TRUE" else "FALSE",
                expiry,
                name,
                value,
            },
        ) catch return error.OutOfMemory;
    }

    return gpa.dupe(u8, out.written());
}

pub fn serializeCookiesAlloc(
    gpa: Allocator,
    cookies: []const Cookie,
    format: Format,
) (Allocator.Error || error{IncompatibleNetscapeCookie})![]u8 {
    return switch (format) {
        .cdp => serializeCookiesCdpAlloc(gpa, cookies),
        .netscape => serializeCookiesNetscapeAlloc(gpa, cookies),
    };
}

// ---------------------------------------------------------------------------
// Multi-Backend Chunked + Compressed Storage (`browser-cookie://<profile>`)
// ---------------------------------------------------------------------------

pub fn serviceNameAlloc(gpa: Allocator, profile: []const u8) Allocator.Error![]u8 {
    return std.fmt.allocPrint(gpa, "{s}{s}", .{ service_prefix, profile });
}

fn isValidGenTag(gen: []const u8) bool {
    if (gen.len == 0 or gen.len > 32) return false;
    for (gen) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-')) {
            return false;
        }
    }
    return true;
}

fn sameGenTag(a: ?[]const u8, b: ?[]const u8) bool {
    const a_eff: ?[]const u8 = if (a) |s| (if (s.len > 0) s else null) else null;
    const b_eff: ?[]const u8 = if (b) |s| (if (s.len > 0) s else null) else null;
    if (a_eff == null and b_eff == null) return true;
    if (a_eff == null or b_eff == null) return false;
    return std.mem.eql(u8, a_eff.?, b_eff.?);
}

fn chunkAccountBuf(gen: ?[]const u8, index: usize, buf: *[64]u8) []const u8 {
    if (gen) |g| {
        if (g.len > 0) {
            return std.fmt.bufPrint(buf, "{s}{s}-{d}", .{ chunk_account_prefix, g, index }) catch unreachable;
        }
    }
    return std.fmt.bufPrint(buf, "{s}{d}", .{ chunk_account_prefix, index }) catch unreachable;
}

fn serializeManifestJsonAlloc(gpa: Allocator, m: Manifest) Allocator.Error![]u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();

    var jw: std.json.Stringify = .{
        .writer = &out.writer,
        .options = .{},
    };

    jw.beginObject() catch return error.OutOfMemory;
    jw.objectField("v") catch return error.OutOfMemory;
    jw.write(m.v) catch return error.OutOfMemory;
    jw.objectField("chunks") catch return error.OutOfMemory;
    jw.write(m.chunks) catch return error.OutOfMemory;
    jw.objectField("encoding") catch return error.OutOfMemory;
    jw.write(m.encoding) catch return error.OutOfMemory;
    jw.objectField("sha256") catch return error.OutOfMemory;
    jw.write(m.sha256) catch return error.OutOfMemory;
    if (m.gen) |g| {
        if (g.len > 0) {
            jw.objectField("gen") catch return error.OutOfMemory;
            jw.write(g) catch return error.OutOfMemory;
        }
    }
    if (m.domains.len > 0) {
        jw.objectField("domains") catch return error.OutOfMemory;
        jw.beginArray() catch return error.OutOfMemory;
        for (m.domains) |d| {
            jw.write(d) catch return error.OutOfMemory;
        }
        jw.endArray() catch return error.OutOfMemory;
    }
    jw.endObject() catch return error.OutOfMemory;

    return gpa.dupe(u8, out.written());
}

fn dupeDomainsSliceAlloc(gpa: Allocator, domains: []const []const u8) Allocator.Error![]const []const u8 {
    if (domains.len == 0) return &.{};
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |item| gpa.free(item);
        list.deinit(gpa);
    }
    for (domains) |d| {
        try appendNormalizedDomainSuffix(gpa, &list, d);
    }
    return list.toOwnedSlice(gpa);
}

fn compressZlibAlloc(gpa: Allocator, input: []const u8) Allocator.Error!?[]u8 {
    var zero_alloc: ZeroOnFreeAllocator = .{ .backing = gpa };
    const z_gpa = zero_alloc.allocator();

    const window_buf = try z_gpa.alloc(u8, flate.max_window_len);
    defer z_gpa.free(window_buf);

    var out = try Io.Writer.Allocating.initCapacity(z_gpa, 64);
    defer out.deinit();

    const comp = try z_gpa.create(flate.Compress);
    defer z_gpa.destroy(comp);

    comp.* = flate.Compress.init(&out.writer, window_buf, .zlib, .default) catch return null;
    comp.writer.writeAll(input) catch return null;
    comp.finish() catch return null;

    return try gpa.dupe(u8, out.written());
}

fn decompressZlibAlloc(gpa: Allocator, compressed: []const u8) (Allocator.Error || error{CorruptCookieJar})![]u8 {
    var zero_alloc: ZeroOnFreeAllocator = .{ .backing = gpa };
    const z_gpa = zero_alloc.allocator();

    const window_buf = try z_gpa.alloc(u8, flate.max_window_len);
    defer z_gpa.free(window_buf);

    var fixed_in: Io.Reader = .fixed(compressed);
    const decomp = try z_gpa.create(flate.Decompress);
    defer z_gpa.destroy(decomp);
    decomp.* = flate.Decompress.init(&fixed_in, .zlib, window_buf);

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(z_gpa);

    decomp.reader.appendRemaining(z_gpa, &list, .limited(max_cookie_input_bytes)) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.CorruptCookieJar,
    };

    return gpa.dupe(u8, list.items);
}

pub fn saveProfileCookies(
    gpa: Allocator,
    store: SecretStore,
    profile: []const u8,
    cookies: []const Cookie,
) CookieError!Manifest {
    return saveProfileCookiesWithDomains(gpa, store, profile, cookies, &.{});
}

pub fn saveProfileCookiesWithDomains(
    gpa: Allocator,
    store: SecretStore,
    profile: []const u8,
    cookies: []const Cookie,
    domains: []const []const u8,
) CookieError!Manifest {
    if (!isValidProfile(profile)) return error.InvalidProfile;

    var zero_alloc: ZeroOnFreeAllocator = .{ .backing = gpa };
    const z_gpa = zero_alloc.allocator();

    const service = try serviceNameAlloc(z_gpa, profile);
    defer z_gpa.free(service);

    // Inspect previous manifest (if present) so old generation chunks are
    // removed ONLY AFTER the new generation chunks and manifest are committed.
    var old_chunks: usize = 0;
    var old_gen: ?[]u8 = null;
    defer if (old_gen) |g| z_gpa.free(g);

    if (store.get(z_gpa, service, manifest_account)) |prev_raw| {
        defer z_gpa.free(prev_raw);
        if (std.json.parseFromSlice(ManifestWire, z_gpa, prev_raw, .{
            .ignore_unknown_fields = true,
        })) |prev_parsed| {
            defer prev_parsed.deinit();
            old_chunks = @min(prev_parsed.value.chunks, max_chunks);
            if (prev_parsed.value.gen) |pg| {
                if (isValidGenTag(pg)) {
                    old_gen = try z_gpa.dupe(u8, pg);
                }
            }
        } else |_| {}
    } else |err| switch (err) {
        error.EntryNotFound => {},
        else => return err,
    }

    const sorted = try z_gpa.alloc(Cookie, cookies.len);
    defer z_gpa.free(sorted);
    @memcpy(sorted, cookies);
    std.mem.sort(Cookie, sorted, {}, cookieLessThan);

    const canonical_json = try serializeCookiesCdpAlloc(z_gpa, sorted);
    defer z_gpa.free(canonical_json);

    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(canonical_json, &digest, .{});
    const sha256_hex_arr = std.fmt.bytesToHex(digest, .lower);
    const new_gen: []const u8 = sha256_hex_arr[0..manifest_gen_hex_len];

    const maybe_compressed = try compressZlibAlloc(z_gpa, canonical_json);
    defer if (maybe_compressed) |comp_bytes| z_gpa.free(comp_bytes);

    const use_zlib = if (maybe_compressed) |comp_bytes| comp_bytes.len < canonical_json.len else false;
    const raw_payload = if (use_zlib) maybe_compressed.? else canonical_json;
    const encoding_name: []const u8 = if (use_zlib) "zlib+base64" else "base64";

    const b64_len = std.base64.standard.Encoder.calcSize(raw_payload.len);
    const b64_buf = try z_gpa.alloc(u8, b64_len);
    defer z_gpa.free(b64_buf);
    const b64_payload = std.base64.standard.Encoder.encode(b64_buf, raw_payload);

    const num_chunks: usize = if (b64_payload.len == 0)
        1
    else
        (b64_payload.len + max_chunk_bytes - 1) / max_chunk_bytes;
    if (num_chunks > max_chunks) return error.StorageFailure;

    const norm_domains = try dupeDomainsSliceAlloc(z_gpa, domains);
    defer {
        for (norm_domains) |d| z_gpa.free(d);
        if (norm_domains.len > 0) z_gpa.free(norm_domains);
    }

    // 1. Write all new generation chunks FIRST (`chunk-<new_gen>-0..N-1`).
    //    If a failure occurs before manifest commit and `new_gen != old_gen`,
    //    clean up partially written new-gen chunks while leaving old-gen intact.
    var written_new_chunks: usize = 0;
    var manifest_committed = false;
    errdefer if (!manifest_committed and !sameGenTag(old_gen, new_gen)) {
        var cleanup_idx: usize = 0;
        while (cleanup_idx < written_new_chunks) : (cleanup_idx += 1) {
            var acct_buf: [64]u8 = undefined;
            store.delete(z_gpa, service, chunkAccountBuf(new_gen, cleanup_idx, &acct_buf)) catch {};
        }
    };

    var idx: usize = 0;
    while (idx < num_chunks) : (idx += 1) {
        const start = idx * max_chunk_bytes;
        const end = @min(start + max_chunk_bytes, b64_payload.len);
        const chunk_slice = b64_payload[start..end];
        std.debug.assert(chunk_slice.len <= max_chunk_bytes and chunk_slice.len <= 2000);
        var acct_buf: [64]u8 = undefined;
        try store.set(z_gpa, service, chunkAccountBuf(new_gen, idx, &acct_buf), chunk_slice);
        written_new_chunks = idx + 1;
    }

    // 2. Write `manifest` SECOND — atomic commit point switching active generation.
    const manifest_val: Manifest = .{
        .v = manifest_version,
        .chunks = num_chunks,
        .encoding = encoding_name,
        .sha256 = &sha256_hex_arr,
        .gen = new_gen,
        .domains = norm_domains,
    };
    const manifest_json = try serializeManifestJsonAlloc(z_gpa, manifest_val);
    defer z_gpa.free(manifest_json);
    try store.set(z_gpa, service, manifest_account, manifest_json);
    manifest_committed = true;

    // 3. Delete previous generation's chunks ONLY AFTER the new manifest is committed.
    if (old_chunks > 0 and !sameGenTag(old_gen, new_gen)) {
        var stale_idx: usize = 0;
        while (stale_idx < old_chunks) : (stale_idx += 1) {
            var acct_buf: [64]u8 = undefined;
            store.delete(z_gpa, service, chunkAccountBuf(old_gen, stale_idx, &acct_buf)) catch |err| switch (err) {
                error.EntryNotFound => {},
                else => return err,
            };
        }
    } else if (old_chunks > num_chunks) {
        var stale_idx = num_chunks;
        while (stale_idx < old_chunks) : (stale_idx += 1) {
            var acct_buf: [64]u8 = undefined;
            store.delete(z_gpa, service, chunkAccountBuf(new_gen, stale_idx, &acct_buf)) catch |err| switch (err) {
                error.EntryNotFound => {},
                else => return err,
            };
        }
    }

    const enc_out = try gpa.dupe(u8, encoding_name);
    errdefer gpa.free(enc_out);
    const sha_out = try gpa.dupe(u8, &sha256_hex_arr);
    errdefer gpa.free(sha_out);
    const gen_out = try gpa.dupe(u8, new_gen);
    errdefer gpa.free(gen_out);
    const domains_out = try dupeDomainsSliceAlloc(gpa, norm_domains);

    return .{
        .v = manifest_version,
        .chunks = num_chunks,
        .encoding = enc_out,
        .sha256 = sha_out,
        .gen = gen_out,
        .domains = domains_out,
    };
}

pub const LoadedProfile = struct {
    manifest: Manifest,
    cookies: []Cookie,

    pub fn deinit(self: *const LoadedProfile, gpa: Allocator) void {
        self.manifest.deinit(gpa);
        freeCookies(gpa, self.cookies);
    }
};

pub fn loadProfileCookies(
    gpa: Allocator,
    store: SecretStore,
    profile: []const u8,
) CookieError!LoadedProfile {
    if (!isValidProfile(profile)) return error.InvalidProfile;

    var zero_alloc: ZeroOnFreeAllocator = .{ .backing = gpa };
    const z_gpa = zero_alloc.allocator();

    const service = try serviceNameAlloc(z_gpa, profile);
    defer z_gpa.free(service);

    const manifest_raw = try store.get(z_gpa, service, manifest_account);
    defer z_gpa.free(manifest_raw);

    var manifest_parsed = std.json.parseFromSlice(ManifestWire, z_gpa, manifest_raw, .{
        .ignore_unknown_fields = true,
    }) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.CorruptCookieJar,
    };
    defer manifest_parsed.deinit();

    const m = manifest_parsed.value;
    if (m.v != manifest_version or m.chunks == 0 or m.chunks > max_chunks) {
        return error.CorruptCookieJar;
    }
    if (m.sha256.len != Sha256.digest_length * 2) return error.CorruptCookieJar;
    var expected_digest: [Sha256.digest_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&expected_digest, m.sha256) catch return error.CorruptCookieJar;

    const eff_gen: ?[]const u8 = if (m.gen) |g| blk: {
        if (g.len == 0) break :blk null;
        if (!isValidGenTag(g)) return error.CorruptCookieJar;
        break :blk g;
    } else null;

    if (m.domains) |doms| {
        for (doms) |d| {
            if (!isValidDomainChars(stripLeadingDots(d))) return error.CorruptCookieJar;
        }
    }

    var joined_b64: std.ArrayList(u8) = .empty;
    defer joined_b64.deinit(z_gpa);

    var idx: usize = 0;
    while (idx < m.chunks) : (idx += 1) {
        var acct_buf: [64]u8 = undefined;
        const chunk = store.get(z_gpa, service, chunkAccountBuf(eff_gen, idx, &acct_buf)) catch |err| switch (err) {
            error.EntryNotFound => return error.CorruptCookieJar,
            else => return err,
        };
        defer z_gpa.free(chunk);
        try joined_b64.appendSlice(z_gpa, std.mem.trim(u8, chunk, " \t\r\n"));
    }

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(joined_b64.items) catch
        return error.CorruptCookieJar;
    if (decoded_len > max_cookie_input_bytes) return error.CorruptCookieJar;
    const decoded_bytes = try z_gpa.alloc(u8, decoded_len);
    defer z_gpa.free(decoded_bytes);
    std.base64.standard.Decoder.decode(decoded_bytes, joined_b64.items) catch
        return error.CorruptCookieJar;

    const canonical_json: []u8 = if (std.mem.eql(u8, m.encoding, "zlib+base64"))
        try decompressZlibAlloc(z_gpa, decoded_bytes)
    else if (std.mem.eql(u8, m.encoding, "base64"))
        try z_gpa.dupe(u8, decoded_bytes)
    else
        return error.CorruptCookieJar;
    defer z_gpa.free(canonical_json);

    var actual_digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(canonical_json, &actual_digest, .{});
    if (!std.crypto.timing_safe.eql([Sha256.digest_length]u8, actual_digest, expected_digest)) {
        return error.IntegrityCheckFailed;
    }

    const cookies = parseCookiesJsonAlloc(gpa, z_gpa, canonical_json) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidCookieFormat => error.CorruptCookieJar,
    };
    errdefer freeCookies(gpa, cookies);

    const enc_copy = try gpa.dupe(u8, m.encoding);
    errdefer gpa.free(enc_copy);
    const sha_copy = try gpa.dupe(u8, m.sha256);
    errdefer gpa.free(sha_copy);
    const gen_copy: ?[]const u8 = if (eff_gen) |g| try gpa.dupe(u8, g) else null;
    errdefer if (gen_copy) |g| gpa.free(g);
    const domains_copy = try dupeDomainsSliceAlloc(gpa, m.domains orelse &.{});

    return .{
        .manifest = .{
            .v = m.v,
            .chunks = m.chunks,
            .encoding = enc_copy,
            .sha256 = sha_copy,
            .gen = gen_copy,
            .domains = domains_copy,
        },
        .cookies = cookies,
    };
}

pub fn deleteProfileCookies(gpa: Allocator, store: SecretStore, profile: []const u8) CookieError!void {
    if (!isValidProfile(profile)) return error.InvalidProfile;

    var zero_alloc: ZeroOnFreeAllocator = .{ .backing = gpa };
    const z_gpa = zero_alloc.allocator();

    const service = try serviceNameAlloc(z_gpa, profile);
    defer z_gpa.free(service);

    var had_manifest = false;
    var chunk_bound: usize = 0;
    var manifest_gen: ?[]u8 = null;
    defer if (manifest_gen) |g| z_gpa.free(g);

    if (store.get(z_gpa, service, manifest_account)) |manifest_raw| {
        defer z_gpa.free(manifest_raw);
        had_manifest = true;
        if (std.json.parseFromSlice(ManifestWire, z_gpa, manifest_raw, .{ .ignore_unknown_fields = true })) |parsed| {
            defer parsed.deinit();
            chunk_bound = @min(parsed.value.chunks, max_chunks);
            if (parsed.value.gen) |pg| {
                if (isValidGenTag(pg)) {
                    manifest_gen = try z_gpa.dupe(u8, pg);
                }
            }
        } else |_| {
            chunk_bound = 0;
        }
    } else |err| switch (err) {
        error.EntryNotFound => {},
        else => return err,
    }

    var deleted_any = false;
    if (chunk_bound > 0) {
        var idx: usize = 0;
        while (idx < chunk_bound) : (idx += 1) {
            var acct_buf: [64]u8 = undefined;
            store.delete(z_gpa, service, chunkAccountBuf(manifest_gen, idx, &acct_buf)) catch |err| switch (err) {
                error.EntryNotFound => continue,
                else => return err,
            };
            deleted_any = true;
        }
    } else {
        // Recover legacy un-tagged chunks if manifest was absent or corrupted.
        var idx: usize = 0;
        while (idx < 1024) : (idx += 1) {
            var acct_buf: [64]u8 = undefined;
            store.delete(z_gpa, service, chunkAccountBuf(null, idx, &acct_buf)) catch |err| switch (err) {
                error.EntryNotFound => break,
                else => return err,
            };
            deleted_any = true;
        }
    }

    if (had_manifest) {
        store.delete(z_gpa, service, manifest_account) catch |err| switch (err) {
            error.EntryNotFound => {},
            else => return err,
        };
        deleted_any = true;
    }

    if (!deleted_any) return error.EntryNotFound;
}

// ---------------------------------------------------------------------------
// Status Metadata & Civil UTC Formatting
// ---------------------------------------------------------------------------

pub const JarStatus = struct {
    total_cookies: usize,
    unique_domains: usize,
    active_cookies: usize,
    expired_cookies: usize,
    session_cookies: usize,
    earliest_expiry_epoch: ?i64,
};

pub fn computeJarStatus(gpa: Allocator, cookies: []const Cookie, now_epoch: i64) Allocator.Error!JarStatus {
    var domains: std.StringHashMapUnmanaged(void) = .empty;
    defer {
        var key_it = domains.keyIterator();
        while (key_it.next()) |k| gpa.free(k.*);
        domains.deinit(gpa);
    }

    var active: usize = 0;
    var expired: usize = 0;
    var session_count: usize = 0;
    var earliest_epoch: ?i64 = null;

    for (cookies) |c| {
        const norm_dom = try normalizedDomainAlloc(gpa, c.domain);
        const gop = try domains.getOrPut(gpa, norm_dom);
        if (gop.found_existing) gpa.free(norm_dom);

        if (c.expires) |exp| {
            if (exp > 0 and exp < @as(f64, @floatFromInt(std.math.maxInt(i64)))) {
                const epoch_sec: i64 = @intFromFloat(@floor(exp));
                if (epoch_sec <= now_epoch) {
                    expired += 1;
                } else {
                    active += 1;
                }
                if (earliest_epoch == null or epoch_sec < earliest_epoch.?) {
                    earliest_epoch = epoch_sec;
                }
            } else {
                session_count += 1;
                active += 1;
            }
        } else {
            session_count += 1;
            active += 1;
        }
    }

    return .{
        .total_cookies = cookies.len,
        .unique_domains = domains.count(),
        .active_cookies = active,
        .expired_cookies = expired,
        .session_cookies = session_count,
        .earliest_expiry_epoch = earliest_epoch,
    };
}

pub fn formatUnixEpochIso8601(epoch_sec: i64, buf: *[32]u8) []const u8 {
    const days = @divFloor(epoch_sec, 86400);
    const rem_sec: u64 = @intCast(epoch_sec - days * 86400);
    const hour: u64 = rem_sec / 3600;
    const minute: u64 = (rem_sec % 3600) / 60;
    const second: u64 = rem_sec % 60;

    const z = days + 719468;
    const era = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe: u64 = @intCast(z - era * 146097);
    const yoe: u64 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const y: i64 = @as(i64, @intCast(yoe)) + era * 400;
    const doy: u64 = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const mp: u64 = (5 * doy + 2) / 153;
    const day: u64 = doy - (153 * mp + 2) / 5 + 1;
    const month: u64 = if (mp < 10) mp + 3 else mp - 9;
    const year: i64 = y + (if (month <= 2) @as(i64, 1) else 0);

    if (year >= 0 and year <= 9999) {
        const y_u: u64 = @intCast(year);
        return std.fmt.bufPrint(
            buf,
            "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z",
            .{ y_u, month, day, hour, minute, second },
        ) catch unreachable;
    }
    return std.fmt.bufPrint(
        buf,
        "{d}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z",
        .{ year, month, day, hour, minute, second },
    ) catch unreachable;
}

// ---------------------------------------------------------------------------
// Ephemeral Directory, Placeholder Substitution & Secure Wipe (`exec`)
// ---------------------------------------------------------------------------

pub fn substituteCookiePlaceholdersAlloc(
    gpa: Allocator,
    arg: []const u8,
    cookie_path: []const u8,
    cookie_jar_path: []const u8,
) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    var pos: usize = 0;
    while (pos < arg.len) {
        if (std.mem.startsWith(u8, arg[pos..], "{cookie_jar}")) {
            try out.appendSlice(gpa, cookie_jar_path);
            pos += "{cookie_jar}".len;
        } else if (std.mem.startsWith(u8, arg[pos..], "{cookie}")) {
            try out.appendSlice(gpa, cookie_path);
            pos += "{cookie}".len;
        } else {
            try out.append(gpa, arg[pos]);
            pos += 1;
        }
    }
    return out.toOwnedSlice(gpa);
}

fn isPosix() bool {
    return builtin.os.tag != .windows and builtin.os.tag != .wasi;
}

fn privateDirPermissions() Io.File.Permissions {
    return if (comptime isPosix()) .fromMode(0o700) else .default_dir;
}

fn privateFilePermissions() Io.File.Permissions {
    return if (comptime isPosix()) .fromMode(0o600) else .default_file;
}

fn isWritableDirectory(io: Io, path: []const u8) bool {
    if (path.len == 0) return false;
    const st = Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    if (st.kind != .directory) return false;
    Io.Dir.cwd().access(io, path, .{ .write = true }) catch return false;
    return true;
}

fn getEnvVarOwned(gpa: Allocator, name: []const u8) ?[]u8 {
    if (runtime_env_map) |env_map| {
        if (env_map.get(name)) |v| return gpa.dupe(u8, v) catch null;
        return null;
    }
    if (builtin.os.tag == .wasi) return null;
    if (builtin.os.tag == .windows) {
        var map = std.process.Environ.createMap(.{ .block = .global }, gpa) catch return null;
        defer map.deinit();
        if (map.get(name)) |v| return gpa.dupe(u8, v) catch null;
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

fn tryCreateRandomCookieSubdirAlloc(gpa: Allocator, io: Io, base_dir: []const u8) ![]u8 {
    var attempt: usize = 0;
    while (attempt < 16) : (attempt += 1) {
        var rand_bytes: [16]u8 = undefined;
        io.randomSecure(&rand_bytes) catch io.random(&rand_bytes);
        const hex_suffix = std.fmt.bytesToHex(rand_bytes, .lower);
        const dir_name = try std.fmt.allocPrint(gpa, "keyring-cookie-{s}", .{hex_suffix});
        defer gpa.free(dir_name);
        const full_dir = try std.fs.path.join(gpa, &.{ base_dir, dir_name });
        errdefer gpa.free(full_dir);

        Io.Dir.cwd().createDir(io, full_dir, privateDirPermissions()) catch |err| switch (err) {
            error.PathAlreadyExists => {
                gpa.free(full_dir);
                continue;
            },
            else => return err,
        };
        return full_dir;
    }
    return error.StorageFailure;
}

fn createEphemeralCookieDirAlloc(gpa: Allocator, io: Io) ![]u8 {
    if (ephemeral_base_dir_override) |override_dir| {
        return tryCreateRandomCookieSubdirAlloc(gpa, io, override_dir);
    }
    if (builtin.os.tag == .linux and isWritableDirectory(io, "/dev/shm")) {
        if (tryCreateRandomCookieSubdirAlloc(gpa, io, "/dev/shm")) |dir| {
            return dir;
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {},
        }
    }
    const env_candidates = [_][]const u8{ "TMPDIR", "TEMP", "TMP" };

    for (env_candidates) |env_name| {
        if (getEnvVarOwned(gpa, env_name)) |dir| {
            defer gpa.free(dir);
            const trimmed = std.mem.trimEnd(u8, dir, "/\\");
            if (trimmed.len > 0 and isWritableDirectory(io, trimmed)) {
                if (tryCreateRandomCookieSubdirAlloc(gpa, io, trimmed)) |created| {
                    return created;
                } else |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => {},
                }
            }
        }
    }

    if (builtin.os.tag == .windows) {
        if (getEnvVarOwned(gpa, "LOCALAPPDATA")) |local_app_data| {
            defer gpa.free(local_app_data);
            const win_temp = try std.fs.path.join(gpa, &.{ std.mem.trimEnd(u8, local_app_data, "/\\"), "Temp" });
            defer gpa.free(win_temp);
            if (isWritableDirectory(io, win_temp)) {
                if (tryCreateRandomCookieSubdirAlloc(gpa, io, win_temp)) |created| {
                    return created;
                } else |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => {},
                }
            }
        }
    }

    return tryCreateRandomCookieSubdirAlloc(gpa, io, "/tmp");
}

fn overwriteAndUnlinkFileInDir(io: Io, dir: Io.Dir, sub_path: []const u8) void {
    const st = dir.statFile(io, sub_path, .{ .follow_symlinks = false }) catch {
        dir.deleteFile(io, sub_path) catch {};
        return;
    };
    if (st.kind == .file and st.size > 0) {
        if (dir.openFile(io, sub_path, .{ .mode = .read_write, .follow_symlinks = false })) |file| {
            var zeros: [4096]u8 = @splat(0);
            var offset: u64 = 0;
            while (offset < st.size) {
                const rem = st.size - offset;
                const chunk_len: usize = @intCast(@min(rem, @as(u64, zeros.len)));
                file.writePositionalAll(io, zeros[0..chunk_len], offset) catch break;
                offset += chunk_len;
            }
            file.sync(io) catch {};
            file.close(io);
        } else |_| {}
    }
    dir.deleteFile(io, sub_path) catch {};
}

fn wipeDirContentsRecursive(io: Io, dir: Io.Dir, depth: usize) void {
    if (depth > 8) return;
    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        switch (entry.kind) {
            .directory => {
                if (dir.openDir(io, entry.name, .{ .iterate = true, .follow_symlinks = false })) |subdir| {
                    var sub = subdir;
                    wipeDirContentsRecursive(io, sub, depth + 1);
                    sub.close(io);
                } else |_| {}
                dir.deleteDir(io, entry.name) catch {
                    dir.deleteTree(io, entry.name) catch {};
                };
            },
            else => overwriteAndUnlinkFileInDir(io, dir, entry.name),
        }
    }
}

fn wipeAndRemoveEphemeralDir(io: Io, dir_path: []const u8) void {
    if (Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true, .follow_symlinks = false })) |opened| {
        var dir = opened;
        wipeDirContentsRecursive(io, dir, 0);
        dir.close(io);
    } else |_| {}

    Io.Dir.cwd().deleteDir(io, dir_path) catch {
        Io.Dir.cwd().deleteTree(io, dir_path) catch {};
    };
}

fn buildChildEnvironMap(
    gpa: Allocator,
    cookie_file_path: []const u8,
    cookie_jar_path: []const u8,
) !std.process.Environ.Map {
    var env_map = if (runtime_env_map) |parent_map|
        try parent_map.clone(gpa)
    else
        try std.process.Environ.createMap(ado.currentProcessEnviron(), gpa);
    errdefer env_map.deinit();

    try env_map.put("KEYRING_COOKIE_FILE", cookie_file_path);
    try env_map.put("KEYRING_COOKIE_JAR_FILE", cookie_jar_path);
    return env_map;
}

// ---------------------------------------------------------------------------
// Command Execution Entry Point
// ---------------------------------------------------------------------------

pub fn run(
    gpa: Allocator,
    io: Io,
    subcmd: Subcommand,
    stdin: *Io.Reader,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    return switch (subcmd) {
        .help => {
            try stdout.writeAll(usage_text);
            try stdout.flush();
            return 0;
        },
        .import_cmd => |opts| runImport(gpa, io, opts, stdin, stdout, stderr),
        .export_cmd => |opts| runExport(gpa, opts, stdout, stderr),
        .status => |opts| runStatus(gpa, io, opts.profile, stdout, stderr),
        .delete => |opts| runDelete(gpa, opts.profile, stdout, stderr),
        .exec => |opts| runExec(gpa, io, opts, stdout, stderr),
    };
}

fn reportCookieError(stderr: *Io.Writer, context: []const u8, profile: []const u8, err: CookieError) !u8 {
    switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidProfile => {
            try stderr.print(
                "keyring: cookie {s}: invalid profile '{s}' (expected [A-Za-z0-9._-]+)\n",
                .{ context, profile },
            );
            try stderr.flush();
            return 2;
        },
        error.EntryNotFound => {
            try stderr.print("keyring: cookie {s}: profile '{s}' not found\n", .{ context, profile });
            try stderr.flush();
            return 3;
        },
        error.Locked => {
            try stderr.print("keyring: cookie {s}: OS keyring is locked (run 'keyring unlock' first)\n", .{context});
            try stderr.flush();
            return 1;
        },
        error.NoStorageAccess => {
            try stderr.print(
                "keyring: cookie {s}: no storage access to OS keyring (run 'keyring diagnose' for guidance)\n",
                .{context},
            );
            try stderr.flush();
            return 4;
        },
        error.InvalidCookieFormat => {
            try stderr.print("keyring: cookie {s}: invalid cookie format (expected CDP/Playwright JSON or Netscape cookies.txt)\n", .{context});
            try stderr.flush();
            return 1;
        },
        error.IncompatibleNetscapeCookie => {
            try stderr.print(
                "keyring: cookie {s}: cookie contains tab or control characters incompatible with Netscape cookies.txt (use --format cdp)\n",
                .{context},
            );
            try stderr.flush();
            return 1;
        },
        error.EmptyCookieJar => {
            try stderr.print("keyring: cookie {s}: no matching cookies to store\n", .{context});
            try stderr.flush();
            return 1;
        },
        error.CorruptCookieJar => {
            try stderr.print("keyring: cookie {s}: stored cookie jar for '{s}' is incomplete or corrupted\n", .{ context, profile });
            try stderr.flush();
            return 1;
        },
        error.IntegrityCheckFailed => {
            try stderr.print("keyring: cookie {s}: SHA-256 integrity check failed for profile '{s}'\n", .{ context, profile });
            try stderr.flush();
            return 1;
        },
        error.StorageFailure => {
            try stderr.print("keyring: cookie {s}: failed to access OS keyring storage\n", .{context});
            try stderr.flush();
            return 1;
        },
    }
}

fn readStdinBytesAlloc(gpa: Allocator, stdin: *Io.Reader) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer {
        std.crypto.secureZero(u8, list.items);
        list.deinit(gpa);
    }
    stdin.appendRemaining(gpa, &list, .limited(max_cookie_input_bytes)) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.StreamTooLong,
    };
    return list.toOwnedSlice(gpa);
}

fn runImport(
    gpa: Allocator,
    io: Io,
    opts: ImportOptions,
    stdin: *Io.Reader,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    if (!isValidProfile(opts.profile)) {
        return reportCookieError(stderr, "import", opts.profile, error.InvalidProfile);
    }
    if (isStorageDisabled()) {
        return reportCookieError(stderr, "import", opts.profile, error.NoStorageAccess);
    }

    var zero_alloc: ZeroOnFreeAllocator = .{ .backing = gpa };
    const z_gpa = zero_alloc.allocator();
    var arena_state = std.heap.ArenaAllocator.init(z_gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const suffixes = try collectDomainSuffixes(a, opts.raw_args);

    const raw_bytes: []u8 = if (opts.source == null or std.mem.eql(u8, opts.source.?, "-"))
        readStdinBytesAlloc(a, stdin) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                try stderr.writeAll("keyring: cookie import: failed to read cookie input from stdin\n");
                try stderr.flush();
                return 1;
            },
        }
    else
        Io.Dir.cwd().readFileAlloc(io, opts.source.?, a, .limited(max_cookie_input_bytes)) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.FileNotFound => {
                try stderr.print("keyring: cookie import: file not found: {s}\n", .{opts.source.?});
                try stderr.flush();
                return 3;
            },
            else => {
                try stderr.print("keyring: cookie import: failed to read {s}\n", .{opts.source.?});
                try stderr.flush();
                return 1;
            },
        };
    defer std.crypto.secureZero(u8, raw_bytes);

    const parsed_cookies = parseCookiesAutoAlloc(a, raw_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidCookieFormat => return reportCookieError(stderr, "import", opts.profile, error.InvalidCookieFormat),
    };
    defer freeCookies(a, parsed_cookies);

    var filtered: std.ArrayList(Cookie) = .empty;
    for (parsed_cookies) |c| {
        if (matchesAnyDomainSuffix(c.domain, suffixes)) {
            try filtered.append(a, c);
        }
    }

    if (filtered.items.len == 0) {
        return reportCookieError(stderr, "import", opts.profile, error.EmptyCookieJar);
    }

    const store = activeSecretStore();
    const manifest = saveProfileCookiesWithDomains(a, store, opts.profile, filtered.items, suffixes) catch |err| {
        return reportCookieError(stderr, "import", opts.profile, err);
    };

    const status = try computeJarStatus(a, filtered.items, unixNow(io));
    try stdout.print(
        "Imported {d} cookie(s) across {d} domain(s) into profile '{s}' ({d} chunk(s), {s}).\n",
        .{ status.total_cookies, status.unique_domains, opts.profile, manifest.chunks, manifest.encoding },
    );
    try stdout.flush();
    return 0;
}

fn runExport(
    gpa: Allocator,
    opts: ExportOptions,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    if (!isValidProfile(opts.profile)) {
        return reportCookieError(stderr, "export", opts.profile, error.InvalidProfile);
    }
    if (isStorageDisabled()) {
        return reportCookieError(stderr, "export", opts.profile, error.NoStorageAccess);
    }

    var zero_alloc: ZeroOnFreeAllocator = .{ .backing = gpa };
    const z_gpa = zero_alloc.allocator();

    const store = activeSecretStore();
    const loaded = loadProfileCookies(z_gpa, store, opts.profile) catch |err| {
        return reportCookieError(stderr, "export", opts.profile, err);
    };
    defer loaded.deinit(z_gpa);

    const output = serializeCookiesAlloc(z_gpa, loaded.cookies, opts.format) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.IncompatibleNetscapeCookie => return reportCookieError(stderr, "export", opts.profile, error.IncompatibleNetscapeCookie),
    };
    defer z_gpa.free(output);

    try stdout.writeAll(output);
    if (output.len == 0 or output[output.len - 1] != '\n') {
        try stdout.writeByte('\n');
    }
    try stdout.flush();
    return 0;
}

fn unixNow(io: Io) i64 {
    return Io.Clock.real.now(io).toSeconds();
}

fn runStatus(
    gpa: Allocator,
    io: Io,
    profile: []const u8,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    if (!isValidProfile(profile)) {
        return reportCookieError(stderr, "status", profile, error.InvalidProfile);
    }
    if (isStorageDisabled()) {
        return reportCookieError(stderr, "status", profile, error.NoStorageAccess);
    }

    var zero_alloc: ZeroOnFreeAllocator = .{ .backing = gpa };
    const z_gpa = zero_alloc.allocator();

    const store = activeSecretStore();
    const loaded = loadProfileCookies(z_gpa, store, profile) catch |err| {
        return reportCookieError(stderr, "status", profile, err);
    };
    defer loaded.deinit(z_gpa);

    const status = try computeJarStatus(z_gpa, loaded.cookies, unixNow(io));

    try stdout.print("profile: {s}\n", .{profile});
    try stdout.print("service: {s}{s}\n", .{ service_prefix, profile });
    try stdout.print("chunks: {d} ({s})\n", .{ loaded.manifest.chunks, loaded.manifest.encoding });
    try stdout.print("cookies: {d}\n", .{status.total_cookies});
    try stdout.print("domains: {d}\n", .{status.unique_domains});
    try stdout.print(
        "active: {d} ({d} session)\n",
        .{ status.active_cookies, status.session_cookies },
    );
    try stdout.print("expired: {d}\n", .{status.expired_cookies});
    if (status.earliest_expiry_epoch) |epoch| {
        var iso_buf: [32]u8 = undefined;
        const iso = formatUnixEpochIso8601(epoch, &iso_buf);
        try stdout.print("earliest_expiry: {d} ({s})\n", .{ epoch, iso });
    } else {
        try stdout.writeAll("earliest_expiry: none (session only)\n");
    }
    try stdout.flush();
    return 0;
}

fn runDelete(
    gpa: Allocator,
    profile: []const u8,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    if (!isValidProfile(profile)) {
        return reportCookieError(stderr, "delete", profile, error.InvalidProfile);
    }
    if (isStorageDisabled()) {
        return reportCookieError(stderr, "delete", profile, error.NoStorageAccess);
    }

    const store = activeSecretStore();
    deleteProfileCookies(gpa, store, profile) catch |err| {
        return reportCookieError(stderr, "delete", profile, err);
    };

    try stdout.print("Deleted cookie profile '{s}'.\n", .{profile});
    try stdout.flush();
    return 0;
}

fn exitCodeFromTerm(term_result: std.process.Child.Term) u8 {
    return switch (term_result) {
        .exited => |code| code,
        .signal => |sig| blk: {
            const raw_sig: u32 = @intCast(@backingInt(sig));
            const clamped: u8 = @intCast(@min(raw_sig, 127));
            break :blk 128 +| clamped;
        },
        .stopped, .unknown => 1,
    };
}

var exec_received_signal: std.atomic.Value(u32) = .init(0);
var exec_active_child_pid: std.atomic.Value(i64) = .init(0);

const PosixSignalGuard = if (isPosix()) struct {
    const guarded_signals = [_]std.posix.SIG{ .INT, .TERM, .HUP, .QUIT };

    prev_actions: [guarded_signals.len]std.posix.Sigaction,

    fn sigactionHandler(
        sig: std.posix.SIG,
        info: *const std.posix.siginfo_t,
        _: ?*anyopaque,
    ) callconv(.c) void {
        const sig_num: u32 = @intCast(@backingInt(sig));
        _ = exec_received_signal.cmpxchgStrong(0, sig_num, .acq_rel, .acquire);
        // Terminal Ctrl-C / Ctrl-\ (si_code > 0, e.g. SI_KERNEL) is already
        // delivered to the whole foreground process group including the child.
        // Forward SIGTERM/SIGHUP unconditionally, and forward SIGINT/SIGQUIT
        // only when sent directly via kill()/sigqueue() (si_code <= 0).
        const should_forward = switch (sig) {
            .INT, .QUIT => info.code <= 0,
            else => true,
        };
        if (should_forward) {
            const pid_i64 = exec_active_child_pid.load(.acquire);
            if (pid_i64 > 0) {
                const pid: std.posix.pid_t = @intCast(pid_i64);
                std.posix.kill(pid, sig) catch {};
            }
        }
    }

    fn install() @This() {
        exec_received_signal.store(0, .release);
        exec_active_child_pid.store(0, .release);

        var prev: [guarded_signals.len]std.posix.Sigaction = undefined;
        // Install a custom handler function (NOT SIG.IGN, because SIG.IGN is
        // inherited across execve whereas caught handlers reset to SIG.DFL).
        const act: std.posix.Sigaction = .{
            .handler = .{ .sigaction = sigactionHandler },
            .mask = std.posix.sigemptyset(),
            .flags = std.posix.SA.SIGINFO,
        };
        for (guarded_signals, 0..) |sig, idx| {
            std.posix.sigaction(sig, &act, &prev[idx]);
        }
        return .{ .prev_actions = prev };
    }

    fn registerChild(child_id: ?std.process.Child.Id) void {
        if (child_id) |pid| {
            if (pid > 0) {
                exec_active_child_pid.store(@intCast(pid), .release);
                const pending = exec_received_signal.load(.acquire);
                if (pending != 0) {
                    forwardSignalNumber(pid, pending);
                }
            }
        }
    }

    fn clearChild() void {
        exec_active_child_pid.store(0, .release);
    }

    fn forwardSignalNumber(pid: std.posix.pid_t, sig_num: u32) void {
        for (guarded_signals) |candidate| {
            if (@as(u32, @intCast(@backingInt(candidate))) == sig_num) {
                std.posix.kill(pid, candidate) catch {};
                return;
            }
        }
        std.posix.kill(pid, .TERM) catch {};
    }

    fn receivedSignalExitCode() ?u8 {
        const sig_num = exec_received_signal.load(.acquire);
        if (sig_num == 0) return null;
        return 128 +| @as(u8, @intCast(@min(sig_num, 127)));
    }

    fn restore(self: *const @This()) void {
        exec_active_child_pid.store(0, .release);
        for (guarded_signals, 0..) |sig, idx| {
            std.posix.sigaction(sig, &self.prev_actions[idx], null);
        }
    }
} else if (builtin.os.tag == .windows) struct {
    const WIN_BOOL = i32;
    const CTRL_C_EVENT: u32 = 0;
    const CTRL_BREAK_EVENT: u32 = 1;
    const CTRL_CLOSE_EVENT: u32 = 2;

    const HandlerRoutine = *const fn (dwCtrlType: u32) callconv(.winapi) WIN_BOOL;
    extern "kernel32" fn SetConsoleCtrlHandler(HandlerRoutine: ?HandlerRoutine, Add: WIN_BOOL) callconv(.winapi) WIN_BOOL;

    registered: bool,

    fn ctrlHandler(ctrl_type: u32) callconv(.winapi) WIN_BOOL {
        switch (ctrl_type) {
            CTRL_C_EVENT, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT => {
                // Record SIGINT-equivalent (2 => exit 130) and return TRUE so
                // keyring stays alive to wait for the child and wipe temp files.
                _ = exec_received_signal.cmpxchgStrong(0, 2, .acq_rel, .acquire);
                return 1;
            },
            else => return 0,
        }
    }

    fn install() @This() {
        exec_received_signal.store(0, .release);
        exec_active_child_pid.store(0, .release);
        const ok = SetConsoleCtrlHandler(ctrlHandler, 1) != 0;
        return .{ .registered = ok };
    }

    fn registerChild(_: ?std.process.Child.Id) void {}
    fn clearChild() void {}

    fn receivedSignalExitCode() ?u8 {
        const sig_num = exec_received_signal.load(.acquire);
        if (sig_num == 0) return null;
        return 128 +| @as(u8, @intCast(@min(sig_num, 127)));
    }

    fn restore(self: *const @This()) void {
        if (self.registered) {
            _ = SetConsoleCtrlHandler(ctrlHandler, 0);
        }
    }
} else struct {
    fn install() @This() {
        exec_received_signal.store(0, .release);
        exec_active_child_pid.store(0, .release);
        return .{};
    }
    fn registerChild(_: ?std.process.Child.Id) void {}
    fn clearChild() void {}
    fn receivedSignalExitCode() ?u8 {
        return null;
    }
    fn restore(_: *const @This()) void {}
};

fn runExec(
    gpa: Allocator,
    io: Io,
    opts: ExecOptions,
    _: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    if (!isValidProfile(opts.profile)) {
        return reportCookieError(stderr, "exec", opts.profile, error.InvalidProfile);
    }
    if (isStorageDisabled()) {
        return reportCookieError(stderr, "exec", opts.profile, error.NoStorageAccess);
    }

    var zero_alloc: ZeroOnFreeAllocator = .{ .backing = gpa };
    const z_gpa = zero_alloc.allocator();
    var arena_state = std.heap.ArenaAllocator.init(z_gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const exec_domains = try collectDomainSuffixes(a, opts.raw_head_args);

    const store = activeSecretStore();
    const loaded = loadProfileCookies(a, store, opts.profile) catch |err| {
        return reportCookieError(stderr, "exec", opts.profile, err);
    };
    defer loaded.deinit(a);

    const cookies_for_child: []const Cookie = if (exec_domains.len == 0)
        loaded.cookies
    else blk: {
        var subset: std.ArrayList(Cookie) = .empty;
        for (loaded.cookies) |c| {
            if (matchesAnyDomainSuffix(c.domain, exec_domains)) {
                try subset.append(a, c);
            }
        }
        break :blk subset.items;
    };

    const rendered = serializeCookiesAlloc(a, cookies_for_child, opts.format) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.IncompatibleNetscapeCookie => return reportCookieError(stderr, "exec", opts.profile, error.IncompatibleNetscapeCookie),
    };
    defer std.crypto.secureZero(u8, rendered);

    // Install POSIX signal handlers BEFORE creating the ephemeral cookie
    // directory so LIFO `defer` runs `wipeAndRemoveEphemeralDir` while signals
    // are still caught, then restores the previous signal dispositions.
    const sig_guard = PosixSignalGuard.install();
    defer sig_guard.restore();

    const eph_dir = createEphemeralCookieDirAlloc(a, io) catch {
        try stderr.writeAll("keyring: cookie exec: failed to create ephemeral cookie directory\n");
        try stderr.flush();
        return 1;
    };
    defer wipeAndRemoveEphemeralDir(io, eph_dir);

    if (PosixSignalGuard.receivedSignalExitCode()) |sig_exit| {
        return sig_exit;
    }

    const cookie_file_path = try std.fs.path.join(a, &.{ eph_dir, opts.format.defaultCookieFilename() });
    const cookie_jar_path = try std.fs.path.join(a, &.{ eph_dir, "cookie-jar.json" });

    {
        var cookie_file = Io.Dir.cwd().createFile(io, cookie_file_path, .{
            .exclusive = true,
            .permissions = privateFilePermissions(),
        }) catch {
            try stderr.writeAll("keyring: cookie exec: failed to write ephemeral cookie file\n");
            try stderr.flush();
            return 1;
        };
        defer cookie_file.close(io);
        cookie_file.writeStreamingAll(io, rendered) catch {
            try stderr.writeAll("keyring: cookie exec: failed to write ephemeral cookie file\n");
            try stderr.flush();
            return 1;
        };
        if (rendered.len == 0 or rendered[rendered.len - 1] != '\n') {
            cookie_file.writeStreamingAll(io, "\n") catch {
                try stderr.writeAll("keyring: cookie exec: failed to write ephemeral cookie file\n");
                try stderr.flush();
                return 1;
            };
        }
    }

    if (PosixSignalGuard.receivedSignalExitCode()) |sig_exit| {
        return sig_exit;
    }

    const child_argv = try a.alloc([]const u8, opts.argv.len);
    for (opts.argv, 0..) |raw_arg, idx| {
        child_argv[idx] = try substituteCookiePlaceholdersAlloc(a, raw_arg, cookie_file_path, cookie_jar_path);
    }

    var child_env = try buildChildEnvironMap(a, cookie_file_path, cookie_jar_path);
    defer child_env.deinit();

    var child = std.process.spawn(io, .{
        .argv = child_argv,
        .environ_map = &child_env,
        .stdin = .inherit,
        .stdout = .inherit,
        .stderr = .inherit,
    }) catch |err| {
        try stderr.print("keyring: cookie exec: failed to spawn '{s}': {s}\n", .{ child_argv[0], @errorName(err) });
        try stderr.flush();
        return 1;
    };

    PosixSignalGuard.registerChild(child.id);
    const child_term = child.wait(io) catch |err| {
        PosixSignalGuard.clearChild();
        child.kill(io);
        if (PosixSignalGuard.receivedSignalExitCode()) |sig_exit| {
            return sig_exit;
        }
        try stderr.print("keyring: cookie exec: failed waiting for '{s}': {s}\n", .{ child_argv[0], @errorName(err) });
        try stderr.flush();
        return 1;
    };
    PosixSignalGuard.clearChild();

    if (PosixSignalGuard.receivedSignalExitCode()) |sig_exit| {
        return sig_exit;
    }

    const child_exit = exitCodeFromTerm(child_term);

    if (opts.update) {
        if (Io.Dir.cwd().readFileAlloc(io, cookie_jar_path, a, .limited(max_cookie_input_bytes))) |updated_bytes| {
            defer std.crypto.secureZero(u8, updated_bytes);
            if (std.mem.trim(u8, updated_bytes, " \t\r\n").len > 0) {
                if (parseCookiesAutoAlloc(a, updated_bytes)) |incoming_cookies| {
                    defer freeCookies(a, incoming_cookies);

                    // Enforce both stored manifest domain scope (if any) and
                    // optional `exec --domain` filter so third-party domains
                    // visited during browser sessions never pollute a scoped jar.
                    var scoped_incoming: std.ArrayList(Cookie) = .empty;
                    for (incoming_cookies) |c| {
                        if (!matchesAnyDomainSuffix(c.domain, loaded.manifest.domains)) continue;
                        if (!matchesAnyDomainSuffix(c.domain, exec_domains)) continue;
                        try scoped_incoming.append(a, c);
                    }

                    const merged = try mergeCookiesForUpdateAlloc(
                        a,
                        loaded.cookies,
                        scoped_incoming.items,
                        &.{},
                        unixNow(io),
                    );
                    defer freeCookies(a, merged);
                    _ = saveProfileCookiesWithDomains(
                        a,
                        store,
                        opts.profile,
                        merged,
                        loaded.manifest.domains,
                    ) catch |err| {
                        return reportCookieError(stderr, "exec", opts.profile, err);
                    };
                } else |parse_err| switch (parse_err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.InvalidCookieFormat => {
                        try stderr.writeAll("keyring: cookie exec: updated cookie jar has invalid format\n");
                        try stderr.flush();
                        return if (child_exit != 0) child_exit else 1;
                    },
                }
            }
        } else |read_err| switch (read_err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.FileNotFound => {},
            else => {
                try stderr.writeAll("keyring: cookie exec: failed to read updated cookie jar\n");
                try stderr.flush();
                return if (child_exit != 0) child_exit else 1;
            },
        }
    }

    return child_exit;
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

const MockKeyring = struct {
    const EntryMap = std.StringHashMapUnmanaged([]u8);

    var gpa_ref: Allocator = undefined;
    var entries: EntryMap = .empty;

    fn init(gpa: Allocator) void {
        gpa_ref = gpa;
        entries = .empty;
    }

    fn deinit() void {
        var it = entries.iterator();
        while (it.next()) |kv| {
            gpa_ref.free(kv.key_ptr.*);
            std.crypto.secureZero(u8, kv.value_ptr.*);
            gpa_ref.free(kv.value_ptr.*);
        }
        entries.deinit(gpa_ref);
        entries = .empty;
    }

    fn makeKey(gpa: Allocator, service: []const u8, account: []const u8) SecretError![]u8 {
        return std.fmt.allocPrint(gpa, "{s}\x00{s}", .{ service, account }) catch error.OutOfMemory;
    }

    fn get(gpa: Allocator, service: []const u8, account: []const u8) SecretError![]u8 {
        const composite = try makeKey(gpa_ref, service, account);
        defer gpa_ref.free(composite);
        const val = entries.get(composite) orelse return error.EntryNotFound;
        return gpa.dupe(u8, val) catch error.OutOfMemory;
    }

    fn set(_: Allocator, service: []const u8, account: []const u8, value: []const u8) SecretError!void {
        const composite = try makeKey(gpa_ref, service, account);
        errdefer gpa_ref.free(composite);
        const val_copy = gpa_ref.dupe(u8, value) catch return error.OutOfMemory;
        errdefer gpa_ref.free(val_copy);

        const gop = entries.getOrPut(gpa_ref, composite) catch return error.OutOfMemory;
        if (gop.found_existing) {
            gpa_ref.free(composite);
            std.crypto.secureZero(u8, gop.value_ptr.*);
            gpa_ref.free(gop.value_ptr.*);
        }
        gop.value_ptr.* = val_copy;
    }

    fn delete(_: Allocator, service: []const u8, account: []const u8) SecretError!void {
        const composite = try makeKey(gpa_ref, service, account);
        defer gpa_ref.free(composite);
        const removed = entries.fetchRemove(composite) orelse return error.EntryNotFound;
        gpa_ref.free(removed.key);
        std.crypto.secureZero(u8, removed.value);
        gpa_ref.free(removed.value);
    }

    const store: SecretStore = .{
        .get = get,
        .set = set,
        .delete = delete,
    };
};

test "CDP JSON array, Playwright storageState wrapper, and Netscape #HttpOnly_ roundtrip" {
    const gpa = std.testing.allocator;

    const playwright_json =
        \\{
        \\  "cookies": [
        \\    {
        \\      "name": "__Secure-session",
        \\      "value": "s3cr3t_tok_1",
        \\      "domain": ".Example.COM",
        \\      "path": "/",
        \\      "expires": 1800000000,
        \\      "httpOnly": true,
        \\      "secure": true,
        \\      "sameSite": "Lax"
        \\    },
        \\    {
        \\      "name": "session_id",
        \\      "value": "ephem_42",
        \\      "domain": "app.example.com",
        \\      "path": "",
        \\      "expires": -1,
        \\      "httpOnly": false,
        \\      "secure": true,
        \\      "sameSite": "Strict"
        \\    }
        \\  ],
        \\  "origins": []
        \\}
    ;

    const from_pw = try parseCookiesAutoAlloc(gpa, playwright_json);
    defer freeCookies(gpa, from_pw);
    try std.testing.expectEqual(@as(usize, 2), from_pw.len);

    // Sorted by normalized domain: app.example.com then example.com.
    try std.testing.expectEqualStrings("app.example.com", from_pw[0].domain);
    try std.testing.expectEqualStrings("/", from_pw[0].path);
    try std.testing.expect(from_pw[0].expires == null);
    try std.testing.expectEqual(SameSite.strict, from_pw[0].same_site.?);

    try std.testing.expectEqualStrings(".example.com", from_pw[1].domain);
    try std.testing.expectEqual(@as(f64, 1800000000), from_pw[1].expires.?);
    try std.testing.expect(from_pw[1].http_only);
    try std.testing.expect(from_pw[1].secure);
    try std.testing.expectEqual(SameSite.lax, from_pw[1].same_site.?);

    // Export to CDP JSON array and parse back.
    const cdp_json = try serializeCookiesCdpAlloc(gpa, from_pw);
    defer gpa.free(cdp_json);
    const from_cdp = try parseCookiesAutoAlloc(gpa, cdp_json);
    defer freeCookies(gpa, from_cdp);
    try std.testing.expectEqual(@as(usize, 2), from_cdp.len);
    try std.testing.expectEqualStrings("__Secure-session", from_cdp[1].name);
    try std.testing.expectEqualStrings("s3cr3t_tok_1", from_cdp[1].value);
    try std.testing.expectEqual(SameSite.lax, from_cdp[1].same_site.?);

    // Export to Netscape cookies.txt (including #HttpOnly_) and round-trip back.
    const netscape_txt = try serializeCookiesNetscapeAlloc(gpa, from_cdp);
    defer gpa.free(netscape_txt);
    try std.testing.expect(std.mem.indexOf(u8, netscape_txt, "#HttpOnly_.example.com\tTRUE\t/\tTRUE\t1800000000\t__Secure-session\ts3cr3t_tok_1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, netscape_txt, "app.example.com\tFALSE\t/\tTRUE\t0\tsession_id\tephem_42\n") != null);

    const netscape_with_comments =
        "# Netscape HTTP Cookie File\n" ++
        "# Generated for curl / browser interop\n\n" ++
        "#HttpOnly_.example.com\tTRUE\t/\tTRUE\t1800000000\t__Secure-session\ts3cr3t_tok_1\n" ++
        "app.example.com\tFALSE\t/app\tTRUE\t0\tsession_id\tephem_42\n";
    const from_netscape = try parseCookiesAutoAlloc(gpa, netscape_with_comments);
    defer freeCookies(gpa, from_netscape);
    try std.testing.expectEqual(@as(usize, 2), from_netscape.len);
    try std.testing.expectEqualStrings("app.example.com", from_netscape[0].domain);
    try std.testing.expectEqualStrings("/app", from_netscape[0].path);
    try std.testing.expect(!from_netscape[0].http_only);
    try std.testing.expect(from_netscape[0].expires == null);

    try std.testing.expectEqualStrings(".example.com", from_netscape[1].domain);
    try std.testing.expect(from_netscape[1].http_only);
    try std.testing.expect(from_netscape[1].secure);
    try std.testing.expectEqual(@as(f64, 1800000000), from_netscape[1].expires.?);
}

test "domain suffix matching accepts exact and subdomains while rejecting badexample.com" {
    try std.testing.expect(matchesDomainSuffix("example.com", "example.com"));
    try std.testing.expect(matchesDomainSuffix(".example.com", "example.com"));
    try std.testing.expect(matchesDomainSuffix(".EXAMPLE.COM", ".example.com"));
    try std.testing.expect(matchesDomainSuffix("app.example.com", "example.com"));
    try std.testing.expect(matchesDomainSuffix(".sub.app.example.com", "example.com"));

    // Must NOT match partial host suffix without dot boundary!
    try std.testing.expect(!matchesDomainSuffix("badexample.com", "example.com"));
    try std.testing.expect(!matchesDomainSuffix(".badexample.com", "example.com"));
    try std.testing.expect(!matchesDomainSuffix("example.com.attacker.invalid", "example.com"));
    try std.testing.expect(!matchesDomainSuffix("", "example.com"));
    try std.testing.expect(!matchesDomainSuffix("example.com", ""));

    // Profile identifier validation.
    try std.testing.expect(isValidProfile("alice"));
    try std.testing.expect(isValidProfile("work.staging-01_a"));
    try std.testing.expect(!isValidProfile(""));
    try std.testing.expect(!isValidProfile("alice/bob"));
    try std.testing.expect(!isValidProfile("alice bob"));
    try std.testing.expect(!isValidProfile("alice:bob"));
}

test "45-cookie (>10 KB) multi-chunk split, reassembly, SHA-256 tamper detection, and 8->1 stale chunk cleanup" {
    const gpa = std.testing.allocator;
    MockKeyring.init(gpa);
    defer MockKeyring.deinit();

    const profile = "alice";
    const service = "browser-cookie://alice";

    // Build a deterministic 45-cookie (> 10 KB) synthetic example.com jar whose
    // high-entropy session tokens span 8 chunks under max_chunk_bytes = 1800.
    var cookies_45: std.ArrayList(Cookie) = .empty;
    defer {
        for (cookies_45.items) |*c| freeCookie(gpa, c);
        cookies_45.deinit(gpa);
    }

    var idx: usize = 0;
    while (idx < 45) : (idx += 1) {
        const name = try std.fmt.allocPrint(gpa, "cookie_tok_{d:0>2}", .{idx});
        errdefer gpa.free(name);
        const domain = try std.fmt.allocPrint(
            gpa,
            "{s}",
            .{if (idx % 2 == 0) ".example.com" else "app.example.com"},
        );
        errdefer gpa.free(domain);
        const path = try gpa.dupe(u8, "/");
        errdefer gpa.free(path);

        // 6 * 32 + 16 = 208 pseudo-random bytes -> 278 base64url chars per cookie.
        var raw_secret: [208]u8 = undefined;
        var blk_i: usize = 0;
        while (blk_i < 7) : (blk_i += 1) {
            var seed_buf: [64]u8 = undefined;
            const seed = try std.fmt.bufPrint(&seed_buf, "synthetic-example-seed-{d}-{d}", .{ idx, blk_i });
            var h: [32]u8 = undefined;
            Sha256.hash(seed, &h, .{});
            const off = blk_i * 32;
            const copy_len = @min(@as(usize, 32), raw_secret.len - off);
            @memcpy(raw_secret[off..][0..copy_len], h[0..copy_len]);
        }
        const val_len = std.base64.url_safe_no_pad.Encoder.calcSize(raw_secret.len);
        const value = try gpa.alloc(u8, val_len);
        _ = std.base64.url_safe_no_pad.Encoder.encode(value, &raw_secret);

        try cookies_45.append(gpa, .{
            .name = name,
            .value = value,
            .domain = domain,
            .path = path,
            .expires = @floatFromInt(1893456000 + @as(i64, @intCast(idx)) * 60),
            .http_only = true,
            .secure = true,
            .same_site = .lax,
        });
    }

    const raw_json_45 = try serializeCookiesCdpAlloc(gpa, cookies_45.items);
    defer gpa.free(raw_json_45);
    try std.testing.expect(raw_json_45.len > 10 * 1024);

    const manifest_8 = try saveProfileCookies(gpa, MockKeyring.store, profile, cookies_45.items);
    defer manifest_8.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 8), manifest_8.chunks);
    try std.testing.expect(manifest_8.gen != null);
    const gen_8 = manifest_8.gen.?;
    try std.testing.expectEqual(@as(usize, manifest_gen_hex_len), gen_8.len);

    // Every stored chunk must be <= max_chunk_bytes (1800) and <= 2000 ASCII bytes.
    var c_idx: usize = 0;
    while (c_idx < manifest_8.chunks) : (c_idx += 1) {
        var acct_buf: [64]u8 = undefined;
        const chunk_val = try MockKeyring.get(gpa, service, chunkAccountBuf(gen_8, c_idx, &acct_buf));
        defer gpa.free(chunk_val);
        try std.testing.expect(chunk_val.len > 0 and chunk_val.len <= max_chunk_bytes);
        try std.testing.expect(chunk_val.len <= 2000);
        for (chunk_val) |ch| try std.testing.expect(std.ascii.isPrint(ch));
    }

    // Reassemble and verify all 45 cookies match exactly.
    const loaded_45 = try loadProfileCookies(gpa, MockKeyring.store, profile);
    defer loaded_45.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 45), loaded_45.cookies.len);

    const roundtrip_json = try serializeCookiesCdpAlloc(gpa, loaded_45.cookies);
    defer gpa.free(roundtrip_json);
    const expected_sorted = try gpa.alloc(Cookie, cookies_45.items.len);
    defer gpa.free(expected_sorted);
    @memcpy(expected_sorted, cookies_45.items);
    std.mem.sort(Cookie, expected_sorted, {}, cookieLessThan);
    const expected_sorted_json = try serializeCookiesCdpAlloc(gpa, expected_sorted);
    defer gpa.free(expected_sorted_json);
    try std.testing.expectEqualStrings(expected_sorted_json, roundtrip_json);

    // Tamper test 1: corrupting a chunk byte is rejected on load.
    {
        var chunk3_buf: [64]u8 = undefined;
        const chunk3_acct = chunkAccountBuf(gen_8, 3, &chunk3_buf);
        const orig_chunk_3 = try MockKeyring.get(gpa, service, chunk3_acct);
        defer gpa.free(orig_chunk_3);
        const tampered = try gpa.dupe(u8, orig_chunk_3);
        defer gpa.free(tampered);
        tampered[10] = if (tampered[10] == 'A') 'B' else 'A';
        try MockKeyring.set(gpa, service, chunk3_acct, tampered);

        const tamper_res = loadProfileCookies(gpa, MockKeyring.store, profile);
        try std.testing.expect(std.meta.isError(tamper_res));

        try MockKeyring.set(gpa, service, chunk3_acct, orig_chunk_3);
    }

    // Tamper test 2: valid zlib+base64 payload with wrong manifest SHA-256 triggers IntegrityCheckFailed.
    {
        const orig_manifest = try MockKeyring.get(gpa, service, "manifest");
        defer gpa.free(orig_manifest);

        const forged_manifest = try std.fmt.allocPrint(
            gpa,
            "{{\"v\":1,\"chunks\":8,\"encoding\":\"zlib+base64\",\"sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"gen\":\"{s}\"}}",
            .{gen_8},
        );
        defer gpa.free(forged_manifest);
        try MockKeyring.set(gpa, service, "manifest", forged_manifest);
        try std.testing.expectError(error.IntegrityCheckFailed, loadProfileCookies(gpa, MockKeyring.store, profile));

        try MockKeyring.set(gpa, service, "manifest", orig_manifest);
    }

    // Overwrite the 8-chunk profile with a 1-cookie jar -> new generation with 1 chunk,
    // and ALL 8 old generation chunks (`chunk-<gen_8>-0..7`) are deleted!
    const single_cookie = [_]Cookie{
        .{
            .name = "__Secure-session",
            .value = "short_val",
            .domain = ".example.com",
            .path = "/",
            .expires = 1900000000,
            .http_only = true,
            .secure = true,
            .same_site = .lax,
        },
    };
    const manifest_1 = try saveProfileCookies(gpa, MockKeyring.store, profile, &single_cookie);
    defer manifest_1.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 1), manifest_1.chunks);
    const gen_1 = manifest_1.gen.?;
    try std.testing.expect(!std.mem.eql(u8, gen_8, gen_1));

    var new_chunk0_buf: [64]u8 = undefined;
    const chunk0 = try MockKeyring.get(gpa, service, chunkAccountBuf(gen_1, 0, &new_chunk0_buf));
    defer gpa.free(chunk0);

    var stale_i: usize = 0;
    while (stale_i < 8) : (stale_i += 1) {
        var acct_buf: [64]u8 = undefined;
        try std.testing.expectError(
            error.EntryNotFound,
            MockKeyring.get(gpa, service, chunkAccountBuf(gen_8, stale_i, &acct_buf)),
        );
    }

    const loaded_1 = try loadProfileCookies(gpa, MockKeyring.store, profile);
    defer loaded_1.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 1), loaded_1.cookies.len);
    try std.testing.expectEqualStrings("short_val", loaded_1.cookies[0].value);
}

test "status output summarizes metadata without ever printing cookie values" {
    const gpa = std.testing.allocator;
    const io = Io.Threaded.global_single_threaded.io();
    MockKeyring.init(gpa);
    defer MockKeyring.deinit();
    setTestOverrides(MockKeyring.store, null);
    defer setTestOverrides(null, null);

    const sensitive_value_1 = "SUPER_SECRET_COOKIE_VALUE_DO_NOT_PRINT_99182";
    const sensitive_value_2 = "ANOTHER_SENSITIVE_TOKEN_VALUE_77410";
    const initial = [_]Cookie{
        .{
            .name = "__Secure-session",
            .value = sensitive_value_1,
            .domain = ".example.com",
            .path = "/",
            .expires = 4102444800, // 2100-01-01T00:00:00Z
            .http_only = true,
            .secure = true,
            .same_site = .lax,
        },
        .{
            .name = "legacy_tok",
            .value = sensitive_value_2,
            .domain = "auth.example.com",
            .path = "/",
            .expires = 1000000000, // expired
            .http_only = true,
            .secure = true,
        },
        .{
            .name = "ephemeral",
            .value = "SESSION_SECRET_VALUE_555",
            .domain = "app.example.com",
            .path = "/",
            .expires = null,
        },
    };
    const m = try saveProfileCookies(gpa, MockKeyring.store, "alice", &initial);
    m.deinit(gpa);

    var empty_in: Io.Reader = .fixed("");
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err_out: Io.Writer.Allocating = .init(gpa);
    defer err_out.deinit();

    const rc = try run(gpa, io, .{ .status = .{ .profile = "alice" } }, &empty_in, &out.writer, &err_out.writer);
    try std.testing.expectEqual(@as(u8, 0), rc);

    const text = out.written();
    try std.testing.expect(std.mem.indexOf(u8, text, "profile: alice\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "cookies: 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "domains: 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "active: 2 (1 session)\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "expired: 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "earliest_expiry: 1000000000 (2001-09-09T01:46:40Z)\n") != null);

    // Must NEVER expose any cookie secret value!
    try std.testing.expect(std.mem.indexOf(u8, text, sensitive_value_1) == null);
    try std.testing.expect(std.mem.indexOf(u8, text, sensitive_value_2) == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "SESSION_SECRET_VALUE_555") == null);
}

test "exec --update substitutes placeholders, rotates cookies preserving unvisited domains, and deletes /dev/shm dir" {
    if (comptime !isPosix()) return error.SkipZigTest;

    const gpa = std.testing.allocator;
    var threaded = Io.Threaded.init(gpa, .{ .environ = ado.currentProcessEnviron() });
    defer threaded.deinit();
    const io = threaded.io();
    MockKeyring.init(gpa);
    defer MockKeyring.deinit();
    setTestOverrides(MockKeyring.store, null);
    defer setTestOverrides(null, null);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [4096]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const record_path = try std.fmt.allocPrint(gpa, "{s}/exec-observed.txt", .{root_buf[0..root_len]});
    defer gpa.free(record_path);

    const initial_cookies = [_]Cookie{
        .{
            .name = "__Secure-session",
            .value = "initial_session_v1",
            .domain = ".example.com",
            .path = "/",
            .expires = 1850000000,
            .http_only = true,
            .secure = true,
            .same_site = .lax,
        },
        .{
            .name = "sso_ticket",
            .value = "keep_auth_domain_cookie",
            .domain = "auth.example.com",
            .path = "/",
            .expires = 1860000000,
            .http_only = true,
            .secure = true,
            .same_site = .strict,
        },
    };
    const m = try saveProfileCookies(gpa, MockKeyring.store, "alice", &initial_cookies);
    m.deinit(gpa);

    // Child shell verifies both standalone "{cookie}" and inline "--jar={cookie_jar}"
    // plus KEYRING_COOKIE_FILE / KEYRING_COOKIE_JAR_FILE, records the ephemeral
    // directory path, and writes rotated + new cookies to {cookie_jar}.
    const sh_script =
        \\set -eu
        \\COOKIE_ARG="$1"
        \\INLINE_ARG="$2"
        \\RECORD_FILE="$3"
        \\JAR_FROM_INLINE="${INLINE_ARG#--jar=}"
        \\[ "$COOKIE_ARG" = "$KEYRING_COOKIE_FILE" ]
        \\[ "$JAR_FROM_INLINE" = "$KEYRING_COOKIE_JAR_FILE" ]
        \\[ -f "$COOKIE_ARG" ]
        \\grep -Fq "initial_session_v1" "$COOKIE_ARG"
        \\dirname "$COOKIE_ARG" > "$RECORD_FILE"
        \\cat > "$KEYRING_COOKIE_JAR_FILE" <<'EOF'
        \\[
        \\  {
        \\    "name": "__Secure-session",
        \\    "value": "rotated_session_v2",
        \\    "domain": ".example.com",
        \\    "path": "/",
        \\    "expires": 1910000000,
        \\    "httpOnly": true,
        \\    "secure": true,
        \\    "sameSite": "Lax"
        \\  },
        \\  {
        \\    "name": "csrf_token",
        \\    "value": "fresh_csrf_99",
        \\    "domain": "app.example.com",
        \\    "path": "/",
        \\    "expires": 1910003600,
        \\    "httpOnly": false,
        \\    "secure": true,
        \\    "sameSite": "Strict"
        \\  }
        \\]
        \\EOF
    ;

    const exec_argv = [_][]const u8{
        "/bin/sh",
        "-c",
        sh_script,
        "sh",
        "{cookie}",
        "--jar={cookie_jar}",
        record_path,
    };

    var empty_in: Io.Reader = .fixed("");
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err_out: Io.Writer.Allocating = .init(gpa);
    defer err_out.deinit();

    const rc = try run(
        gpa,
        io,
        .{
            .exec = .{
                .profile = "alice",
                .update = true,
                .format = .cdp,
                .argv = &exec_argv,
            },
        },
        &empty_in,
        &out.writer,
        &err_out.writer,
    );
    try std.testing.expectEqual(@as(u8, 0), rc);

    const recorded_raw = try Io.Dir.cwd().readFileAlloc(io, record_path, gpa, .limited(4096));
    defer gpa.free(recorded_raw);
    const eph_dir_used = std.mem.trim(u8, recorded_raw, " \t\r\n");
    try std.testing.expect(eph_dir_used.len > 0);
    if (builtin.os.tag == .linux and isWritableDirectory(io, "/dev/shm")) {
        try std.testing.expect(std.mem.startsWith(u8, eph_dir_used, "/dev/shm/keyring-cookie-"));
    }

    // Verify the ephemeral directory was completely deleted after exec returned.
    try std.testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().statFile(io, eph_dir_used, .{}),
    );

    // Verify rotated __Secure-session + new csrf_token + preserved auth.example.com sso_ticket!
    const updated = try loadProfileCookies(gpa, MockKeyring.store, "alice");
    defer updated.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 3), updated.cookies.len);

    // Sorted by normalized domain: app.example.com, auth.example.com, example.com.
    try std.testing.expectEqualStrings("app.example.com", updated.cookies[0].domain);
    try std.testing.expectEqualStrings("csrf_token", updated.cookies[0].name);
    try std.testing.expectEqualStrings("fresh_csrf_99", updated.cookies[0].value);

    try std.testing.expectEqualStrings("auth.example.com", updated.cookies[1].domain);
    try std.testing.expectEqualStrings("sso_ticket", updated.cookies[1].name);
    try std.testing.expectEqualStrings("keep_auth_domain_cookie", updated.cookies[1].value);

    try std.testing.expectEqualStrings(".example.com", updated.cookies[2].domain);
    try std.testing.expectEqualStrings("__Secure-session", updated.cookies[2].name);
    try std.testing.expectEqualStrings("rotated_session_v2", updated.cookies[2].value);
    try std.testing.expectEqual(@as(f64, 1910000000), updated.cookies[2].expires.?);
}

test "end-to-end cookie import -> status -> export -> delete with KEYRING_BACKEND=file" {
    if (comptime !isPosix()) return error.SkipZigTest;
    if (!@hasField(keyring_zig.Backend, "file")) return error.SkipZigTest;

    const gpa = std.testing.allocator;
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [4096]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const store_path = try std.fmt.allocPrint(gpa, "{s}/cookie-vault.bin", .{root_buf[0..root_len]});
    defer gpa.free(store_path);

    const prev_backend = keyring_zig.currentBackend();
    keyring_zig.setDefaultBackend(.file) catch |err| switch (err) {
        error.BackendUnavailable => return error.SkipZigTest,
    };
    defer keyring_zig.setDefaultBackend(prev_backend) catch {};

    setTestOverrides(null, null);

    // Temporarily append KEYRING_BACKEND=file, KEYRING_FILE_PATH, and KEYRING_FILE_PASSPHRASE to std.c.environ.
    const saved_environ = std.c.environ;
    defer std.c.environ = saved_environ;

    var base_count: usize = 0;
    while (saved_environ[base_count] != null) : (base_count += 1) {}

    var env_entries = try gpa.alloc(?[*:0]u8, base_count + 4);
    defer gpa.free(env_entries);

    var kept: usize = 0;
    var scan: usize = 0;
    while (scan < base_count) : (scan += 1) {
        const entry = saved_environ[scan].?;
        const span = std.mem.span(entry);
        if (std.mem.startsWith(u8, span, "KEYRING_BACKEND=") or
            std.mem.startsWith(u8, span, "KEYRING_FILE_PATH=") or
            std.mem.startsWith(u8, span, "KEYRING_FILE_PASSPHRASE="))
        {
            continue;
        }
        env_entries[kept] = entry;
        kept += 1;
    }

    const env_backend = try std.fmt.allocPrintSentinel(gpa, "KEYRING_BACKEND=file", .{}, 0);
    defer gpa.free(env_backend);
    const env_file_path = try std.fmt.allocPrintSentinel(gpa, "KEYRING_FILE_PATH={s}", .{store_path}, 0);
    defer gpa.free(env_file_path);
    const env_pass = try std.fmt.allocPrintSentinel(gpa, "KEYRING_FILE_PASSPHRASE=test-file-passphrase-example", .{}, 0);
    defer gpa.free(env_pass);

    env_entries[kept] = env_backend.ptr;
    env_entries[kept + 1] = env_file_path.ptr;
    env_entries[kept + 2] = env_pass.ptr;
    env_entries[kept + 3] = null;
    std.c.environ = @ptrCast(env_entries[0 .. kept + 3 :null]);

    // 1. Import filtering --domain example.com (must keep .example.com & app.example.com, drop badexample.com).
    const input_json =
        \\[
        \\  {"name":"__Secure-session","value":"file_backend_val","domain":".example.com","path":"/","expires":1950000000,"httpOnly":true,"secure":true,"sameSite":"Lax"},
        \\  {"name":"sub_tok","value":"sub_val","domain":"app.example.com","path":"/","expires":1950000000,"httpOnly":false,"secure":true},
        \\  {"name":"evil_tok","value":"must_be_filtered","domain":"badexample.com","path":"/","expires":1950000000,"httpOnly":false,"secure":true}
        \\]
    ;
    const raw_import_args = [_][]const u8{ "work", "-", "--domain", "example.com" };
    const imp_subcmd = parseArgs(&.{ "import", "work", "-", "--domain", "example.com" }).?;

    {
        var stdin_r: Io.Reader = .fixed(input_json);
        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var err_out: Io.Writer.Allocating = .init(gpa);
        defer err_out.deinit();
        _ = raw_import_args;

        const rc = try run(gpa, io, imp_subcmd, &stdin_r, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), rc);
        try std.testing.expect(std.mem.indexOf(u8, out.written(), "Imported 2 cookie(s)") != null);
    }

    // 2. Export and verify badexample.com was excluded and encrypted store round-tripped.
    {
        var empty_in: Io.Reader = .fixed("");
        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var err_out: Io.Writer.Allocating = .init(gpa);
        defer err_out.deinit();

        const rc = try run(
            gpa,
            io,
            .{ .export_cmd = .{ .profile = "work", .format = .cdp } },
            &empty_in,
            &out.writer,
            &err_out.writer,
        );
        try std.testing.expectEqual(@as(u8, 0), rc);
        try std.testing.expect(std.mem.indexOf(u8, out.written(), "file_backend_val") != null);
        try std.testing.expect(std.mem.indexOf(u8, out.written(), "sub_val") != null);
        try std.testing.expect(std.mem.indexOf(u8, out.written(), "badexample.com") == null);
        try std.testing.expect(std.mem.indexOf(u8, out.written(), "must_be_filtered") == null);
    }

    // 3. Delete profile and verify subsequent export returns exit code 3.
    {
        var empty_in: Io.Reader = .fixed("");
        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var err_out: Io.Writer.Allocating = .init(gpa);
        defer err_out.deinit();

        const del_rc = try run(gpa, io, .{ .delete = .{ .profile = "work" } }, &empty_in, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), del_rc);
    }
    {
        var empty_in: Io.Reader = .fixed("");
        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var err_out: Io.Writer.Allocating = .init(gpa);
        defer err_out.deinit();

        const exp_rc = try run(
            gpa,
            io,
            .{ .export_cmd = .{ .profile = "work", .format = .cdp } },
            &empty_in,
            &out.writer,
            &err_out.writer,
        );
        try std.testing.expectEqual(@as(u8, 3), exp_rc);
    }
}

test "parseCookiesAutoAlloc handles every OOM failure point without leaks or double-frees" {
    const Runner = struct {
        fn runAllFormats(alloc: Allocator) !void {
            const cdp_with_dups =
                \\[
                \\  {"name":"__Secure-session","value":"first_v","domain":".example.com","path":"/","expires":1900000000,"httpOnly":true,"secure":true,"sameSite":"Lax"},
                \\  {"name":"__Secure-session","value":"second_v","domain":".example.com","path":"/","expires":1900000600,"httpOnly":true,"secure":true,"sameSite":"Strict"},
                \\  {"name":"host_tok","value":"host_only_v","domain":"example.com","path":"/app","expires":-1,"httpOnly":false,"secure":true}
                \\]
            ;
            const parsed_cdp = try parseCookiesAutoAlloc(alloc, cdp_with_dups);
            freeCookies(alloc, parsed_cdp);

            const pw_wrapper =
                \\{"cookies":[{"name":"sid","value":"abc","domain":"app.example.com","path":"/","expires":1900000000,"httpOnly":true,"secure":true}]}
            ;
            const parsed_pw = try parseCookiesAutoAlloc(alloc, pw_wrapper);
            freeCookies(alloc, parsed_pw);

            const netscape_with_dups =
                "# Netscape HTTP Cookie File\n" ++
                "#HttpOnly_.example.com\tTRUE\t/\tTRUE\t1900000000\t__Secure-session\tv1\n" ++
                "#HttpOnly_.example.com\tTRUE\t/\tTRUE\t1900000500\t__Secure-session\tv2\n" ++
                "example.com\tFALSE\t/\tTRUE\t0\thost_only\thv1\n";
            const parsed_ns = try parseCookiesAutoAlloc(alloc, netscape_with_dups);
            freeCookies(alloc, parsed_ns);
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, Runner.runAllFormats, .{});
}

test "atomic generation writes preserve previous jar on mid-save failure and upgrade legacy chunks" {
    const gpa = std.testing.allocator;
    MockKeyring.init(gpa);
    defer MockKeyring.deinit();

    const profile = "alice";
    const service = "browser-cookie://alice";

    // 1. Seed a legacy manifest without `"gen"` (`chunk-0`), verify it loads, and
    //    verify saving upgrades to `chunk-<gen>-0` and deletes legacy `chunk-0`.
    {
        const legacy_cookies = [_]Cookie{
            .{
                .name = "legacy_sid",
                .value = "legacy_v1",
                .domain = ".example.com",
                .path = "/",
                .expires = 1900000000,
                .http_only = true,
                .secure = true,
            },
        };
        const legacy_json = try serializeCookiesCdpAlloc(gpa, &legacy_cookies);
        defer gpa.free(legacy_json);

        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(legacy_json, &digest, .{});
        const hex_sha = std.fmt.bytesToHex(digest, .lower);

        const b64_len = std.base64.standard.Encoder.calcSize(legacy_json.len);
        const b64_buf = try gpa.alloc(u8, b64_len);
        defer gpa.free(b64_buf);
        const b64_str = std.base64.standard.Encoder.encode(b64_buf, legacy_json);

        const legacy_manifest = try std.fmt.allocPrint(
            gpa,
            "{{\"v\":1,\"chunks\":1,\"encoding\":\"base64\",\"sha256\":\"{s}\"}}",
            .{hex_sha},
        );
        defer gpa.free(legacy_manifest);

        try MockKeyring.set(gpa, service, "chunk-0", b64_str);
        try MockKeyring.set(gpa, service, "manifest", legacy_manifest);

        const loaded_legacy = try loadProfileCookies(gpa, MockKeyring.store, profile);
        defer loaded_legacy.deinit(gpa);
        try std.testing.expect(loaded_legacy.manifest.gen == null);
        try std.testing.expectEqual(@as(usize, 1), loaded_legacy.cookies.len);
        try std.testing.expectEqualStrings("legacy_v1", loaded_legacy.cookies[0].value);

        const upgraded_cookies = [_]Cookie{
            .{
                .name = "legacy_sid",
                .value = "upgraded_v2",
                .domain = ".example.com",
                .path = "/",
                .expires = 1910000000,
                .http_only = true,
                .secure = true,
            },
        };
        const m_up = try saveProfileCookies(gpa, MockKeyring.store, profile, &upgraded_cookies);
        defer m_up.deinit(gpa);
        try std.testing.expect(m_up.gen != null);
        // Legacy `chunk-0` must be deleted after committing the new generation.
        try std.testing.expectError(error.EntryNotFound, MockKeyring.get(gpa, service, "chunk-0"));
    }

    // 2. Simulate a storage failure on the 2nd chunk write of a multi-chunk overwrite:
    //    the previously committed generation MUST remain 100% intact and readable,
    //    and partially written new-gen chunk-0 must be cleaned up.
    const FailOnSecondSet = struct {
        var set_calls: usize = 0;

        fn setFn(alloc: Allocator, svc: []const u8, acct: []const u8, val: []const u8) SecretError!void {
            set_calls += 1;
            if (set_calls == 2) return error.StorageFailure;
            return MockKeyring.set(alloc, svc, acct, val);
        }

        const failing_store: SecretStore = .{
            .get = MockKeyring.get,
            .set = setFn,
            .delete = MockKeyring.delete,
        };
    };

    var big_cookies: std.ArrayList(Cookie) = .empty;
    defer {
        for (big_cookies.items) |*c| freeCookie(gpa, c);
        big_cookies.deinit(gpa);
    }
    var idx: usize = 0;
    while (idx < 20) : (idx += 1) {
        const name = try std.fmt.allocPrint(gpa, "tok_{d}", .{idx});
        errdefer gpa.free(name);
        const domain = try gpa.dupe(u8, ".example.com");
        errdefer gpa.free(domain);
        const path = try gpa.dupe(u8, "/");
        errdefer gpa.free(path);
        var raw_secret: [192]u8 = undefined;
        var b_i: usize = 0;
        while (b_i < 6) : (b_i += 1) {
            var seed_buf: [64]u8 = undefined;
            const seed = try std.fmt.bufPrint(&seed_buf, "fail-mid-save-{d}-{d}", .{ idx, b_i });
            var h: [32]u8 = undefined;
            Sha256.hash(seed, &h, .{});
            @memcpy(raw_secret[b_i * 32 ..][0..32], &h);
        }
        const enc_len = std.base64.url_safe_no_pad.Encoder.calcSize(raw_secret.len);
        const value = try gpa.alloc(u8, enc_len);
        _ = std.base64.url_safe_no_pad.Encoder.encode(value, &raw_secret);
        try big_cookies.append(gpa, .{
            .name = name,
            .value = value,
            .domain = domain,
            .path = path,
            .expires = 1920000000,
            .http_only = true,
            .secure = true,
        });
    }

    const count_before = MockKeyring.entries.count();
    FailOnSecondSet.set_calls = 0;
    try std.testing.expectError(
        error.StorageFailure,
        saveProfileCookies(gpa, FailOnSecondSet.failing_store, profile, big_cookies.items),
    );
    // Partial chunk-<new_gen>-0 was rolled back, leaving exact entry count!
    try std.testing.expectEqual(count_before, MockKeyring.entries.count());

    const still_intact = try loadProfileCookies(gpa, MockKeyring.store, profile);
    defer still_intact.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 1), still_intact.cookies.len);
    try std.testing.expectEqualStrings("upgraded_v2", still_intact.cookies[0].value);
}

test "host-only vs domain identity, manifest domain scope preservation, and expired cookie pruning on update" {
    if (comptime !isPosix()) return error.SkipZigTest;

    const gpa = std.testing.allocator;
    var threaded = Io.Threaded.init(gpa, .{ .environ = ado.currentProcessEnviron() });
    defer threaded.deinit();
    const io = threaded.io();
    MockKeyring.init(gpa);
    defer MockKeyring.deinit();
    setTestOverrides(MockKeyring.store, null);
    defer setTestOverrides(null, null);

    // Import with `--domain example.com` containing BOTH host-only `example.com`
    // and domain `.example.com` cookies with the same name (`sid`), plus a cookie
    // (`to_delete`) that the server will expire via `expires: 1` during `exec --update`.
    const import_json =
        \\[
        \\  {"name":"sid","value":"host_only_v1","domain":"example.com","path":"/","expires":4102444800,"httpOnly":true,"secure":true},
        \\  {"name":"sid","value":"domain_wide_v1","domain":".example.com","path":"/","expires":4102444800,"httpOnly":true,"secure":true},
        \\  {"name":"to_delete","value":"bye","domain":"app.example.com","path":"/","expires":4102444800,"httpOnly":true,"secure":true}
        \\]
    ;
    const imp_cmd = parseArgs(&.{ "import", "scoped", "-", "--domain", "example.com" }).?;
    {
        var stdin_r: Io.Reader = .fixed(import_json);
        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var err_out: Io.Writer.Allocating = .init(gpa);
        defer err_out.deinit();
        const rc = try run(gpa, io, imp_cmd, &stdin_r, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), rc);
    }

    // Verify both host-only `example.com` and `.example.com` coexist and manifest stored `domains`.
    {
        const initial_loaded = try loadProfileCookies(gpa, MockKeyring.store, "scoped");
        defer initial_loaded.deinit(gpa);
        try std.testing.expectEqual(@as(usize, 3), initial_loaded.cookies.len);
        try std.testing.expectEqual(@as(usize, 1), initial_loaded.manifest.domains.len);
        try std.testing.expectEqualStrings("example.com", initial_loaded.manifest.domains[0]);
    }

    // During `exec --update`, browser writes:
    // - rotated `.example.com` `sid` (must NOT clobber host-only `example.com` `sid`),
    // - `to_delete` with `expires: 1` (must be pruned!),
    // - third-party `tracker.other.invalid` cookie (must be rejected by stored `--domain example.com` scope!).
    const update_script =
        \\set -eu
        \\cat > "$KEYRING_COOKIE_JAR_FILE" <<'EOF'
        \\[
        \\  {"name":"sid","value":"domain_wide_v2","domain":".example.com","path":"/","expires":4102444900,"httpOnly":true,"secure":true},
        \\  {"name":"to_delete","value":"","domain":"app.example.com","path":"/","expires":1,"httpOnly":true,"secure":true},
        \\  {"name":"ad_id","value":"noise","domain":"tracker.other.invalid","path":"/","expires":4102444800,"httpOnly":false,"secure":true}
        \\]
        \\EOF
    ;
    const exec_subcmd = parseArgs(&.{ "exec", "scoped", "--update", "--", "/bin/sh", "-c", update_script }).?;
    {
        var empty_in: Io.Reader = .fixed("");
        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var err_out: Io.Writer.Allocating = .init(gpa);
        defer err_out.deinit();
        const rc = try run(gpa, io, exec_subcmd, &empty_in, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), rc);
    }

    const after = try loadProfileCookies(gpa, MockKeyring.store, "scoped");
    defer after.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 1), after.manifest.domains.len);
    try std.testing.expectEqualStrings("example.com", after.manifest.domains[0]);
    try std.testing.expectEqual(@as(usize, 2), after.cookies.len);

    // Host-only `example.com` comes first, `.example.com` second; `to_delete` and `tracker.other.invalid` are absent!
    try std.testing.expectEqualStrings("example.com", after.cookies[0].domain);
    try std.testing.expectEqualStrings("host_only_v1", after.cookies[0].value);
    try std.testing.expectEqualStrings(".example.com", after.cookies[1].domain);
    try std.testing.expectEqualStrings("domain_wide_v2", after.cookies[1].value);
}

test "Netscape export rejects cookies containing tab characters with clear IncompatibleNetscapeCookie message" {
    const gpa = std.testing.allocator;
    MockKeyring.init(gpa);
    defer MockKeyring.deinit();
    setTestOverrides(MockKeyring.store, null);
    defer setTestOverrides(null, null);

    const io = Io.Threaded.global_single_threaded.io();
    const json_with_tab =
        \\[{"name":"tab_cookie","value":"part1\tpart2","domain":"example.com","path":"/","expires":1950000000,"httpOnly":true,"secure":true}]
    ;
    const imp_cmd = parseArgs(&.{ "import", "tabprof", "-" }).?;
    {
        var stdin_r: Io.Reader = .fixed(json_with_tab);
        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var err_out: Io.Writer.Allocating = .init(gpa);
        defer err_out.deinit();
        try std.testing.expectEqual(@as(u8, 0), try run(gpa, io, imp_cmd, &stdin_r, &out.writer, &err_out.writer));
    }

    // CDP JSON export succeeds and preserves the tab character.
    {
        var empty_in: Io.Reader = .fixed("");
        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var err_out: Io.Writer.Allocating = .init(gpa);
        defer err_out.deinit();
        const rc = try run(gpa, io, .{ .export_cmd = .{ .profile = "tabprof", .format = .cdp } }, &empty_in, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), rc);
        try std.testing.expect(std.mem.indexOf(u8, out.written(), "part1\\tpart2") != null);
    }

    // Netscape export fails with IncompatibleNetscapeCookie and actionable message suggesting --format cdp.
    {
        var empty_in: Io.Reader = .fixed("");
        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var err_out: Io.Writer.Allocating = .init(gpa);
        defer err_out.deinit();
        const rc = try run(gpa, io, .{ .export_cmd = .{ .profile = "tabprof", .format = .netscape } }, &empty_in, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 1), rc);
        try std.testing.expect(std.mem.indexOf(u8, err_out.written(), "incompatible with Netscape cookies.txt (use --format cdp)") != null);
    }
}

fn currentPosixPid() std.posix.pid_t {
    if (builtin.os.tag == .linux) return std.os.linux.getpid();
    return std.c.getpid();
}

test "POSIX SIGTERM during cookie exec forwards signal, exits 143, and wipes /dev/shm ephemeral dir" {
    if (comptime !isPosix()) return error.SkipZigTest;

    const gpa = std.testing.allocator;
    var threaded = Io.Threaded.init(gpa, .{ .environ = ado.currentProcessEnviron() });
    defer threaded.deinit();
    const io = threaded.io();
    MockKeyring.init(gpa);
    defer MockKeyring.deinit();
    setTestOverrides(MockKeyring.store, null);
    defer setTestOverrides(null, null);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [4096]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const ready_path = try std.fmt.allocPrint(gpa, "{s}/sigterm-ready.txt", .{root_buf[0..root_len]});
    defer gpa.free(ready_path);

    const seed_cookies = [_]Cookie{
        .{
            .name = "__Secure-session",
            .value = "sigterm_wipe_secret",
            .domain = ".example.com",
            .path = "/",
            .expires = 1950000000,
            .http_only = true,
            .secure = true,
        },
    };
    const m = try saveProfileCookies(gpa, MockKeyring.store, "alice", &seed_cookies);
    m.deinit(gpa);

    const SenderCtx = struct {
        io: Io,
        ready_file: []const u8,
        target_pid: std.posix.pid_t,

        fn runSender(ctx: @This()) void {
            var attempt: usize = 0;
            while (attempt < 500) : (attempt += 1) {
                if (Io.Dir.cwd().statFile(ctx.io, ctx.ready_file, .{})) |st| {
                    if (st.size > 0) break;
                } else |_| {}
                ctx.io.sleep(.fromMilliseconds(10), .awake) catch {};
            }
            // Give `/bin/sh` a brief moment after atomic rename to `exec sleep 10`.
            ctx.io.sleep(.fromMilliseconds(25), .awake) catch {};
            std.posix.kill(ctx.target_pid, .TERM) catch {};
        }
    };

    const sender = try std.Thread.spawn(.{}, SenderCtx.runSender, .{SenderCtx{
        .io = io,
        .ready_file = ready_path,
        .target_pid = currentPosixPid(),
    }});
    defer sender.join();

    const child_script =
        \\dirname "$1" > "$2.tmp"
        \\mv "$2.tmp" "$2"
        \\exec sleep 10
    ;
    const exec_argv = [_][]const u8{
        "/bin/sh",
        "-c",
        child_script,
        "sh",
        "{cookie}",
        ready_path,
    };

    var empty_in: Io.Reader = .fixed("");
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err_out: Io.Writer.Allocating = .init(gpa);
    defer err_out.deinit();

    const rc = try run(
        gpa,
        io,
        .{
            .exec = .{
                .profile = "alice",
                .update = false,
                .format = .cdp,
                .argv = &exec_argv,
            },
        },
        &empty_in,
        &out.writer,
        &err_out.writer,
    );

    const expected_sigterm_rc: u8 = 128 +| @as(u8, @intCast(@min(@as(u32, @intCast(@backingInt(std.posix.SIG.TERM))), 127)));
    try std.testing.expectEqual(expected_sigterm_rc, rc);

    const recorded_raw = try Io.Dir.cwd().readFileAlloc(io, ready_path, gpa, .limited(4096));
    defer gpa.free(recorded_raw);
    const eph_dir_used = std.mem.trim(u8, recorded_raw, " \t\r\n");
    try std.testing.expect(eph_dir_used.len > 0);
    if (builtin.os.tag == .linux and isWritableDirectory(io, "/dev/shm")) {
        try std.testing.expect(std.mem.startsWith(u8, eph_dir_used, "/dev/shm/keyring-cookie-"));
    }

    // Ephemeral directory and cookie files MUST be completely wiped & removed despite SIGTERM!
    try std.testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().statFile(io, eph_dir_used, .{}),
    );
}
