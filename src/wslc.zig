//! `keyring wslc` — Container registry authentication for Microsoft's WSL
//! Container CLI (`wslc`).
//!
//! How `wslc` (`3.0.4.0+`) stores and resolves registry credentials:
//! - Settings file: `%LOCALAPPDATA%\wslc\settings.yaml`
//!   - `credentialStore: wincred` (default) or `credentialStore: file`
//! - `WinCredStorage` (`wincred`):
//!   - Stores `CRED_TYPE_GENERIC` (`CRED_PERSIST_LOCAL_MACHINE`) entries in
//!     Windows Credential Manager with `TargetName = "wslc-credential/<server>"`,
//!     `UserName = <username>`, and `CredentialBlob = <secret UTF-8 bytes>`.
//!   - If `UserName` is `"<token>"`, `wslc`'s `RegistryService` serializes
//!     `{"identitytoken": "<secret>"}` in `X-Registry-Auth`; otherwise it
//!     serializes `{"username": "<user>", "password": "<secret>"}`.
//! - `FileCredStorage` (`file`):
//!   - Stores `%LOCALAPPDATA%\wslc\registry-credentials.json` with structure:
//!     `{"Credentials": {"<server>": {"UserName": "...", "Secret": "<base64(DPAPI(secret))>"}}}`
//! - `NormalizeServer`:
//!   - Strips `<scheme>://` and `/<path>`, mapping `docker.io` and
//!     `index.docker.io` to `https://index.docker.io/v1/` and preserving
//!     `<host>[:<port>]` for all other registries.
//!
//! Subcommands:
//! - `keyring wslc login [<server>...] [-u|--username <user>] [--password-stdin] [-f|--force]`
//! - `keyring wslc logout <server>...`
//! - `keyring wslc status`
//! - `keyring wslc credential <get|store|erase>`
const std = @import("std");
const builtin = @import("builtin");
const keyring_zig = @import("keyring_zig");
const ado = @import("ado.zig");
const dpapi = @import("dpapi.zig");
const gh = @import("gh.zig");
const msal_cache = @import("msal_cache.zig");
const wincred = @import("wincred.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const wslc_cred_prefix = "wslc-credential/";
pub const wslc_cred_filter = "wslc-credential/*";
pub const settings_filename = "settings.yaml";
pub const credentials_filename = "registry-credentials.json";
pub const lock_filename = ".lock";
pub const docker_hub_legacy_url = "https://index.docker.io/v1/";
pub const acr_token_username = "00000000-0000-0000-0000-000000000000";
pub const identity_token_username = "<token>";

pub const CredentialStoreKind = enum {
    wincred,
    file,

    pub fn name(self: CredentialStoreKind) []const u8 {
        return switch (self) {
            .wincred => "wincred",
            .file => "file",
        };
    }
};

pub const Operation = enum {
    get,
    store,
    erase,

    pub fn fromString(s: []const u8) ?Operation {
        if (std.mem.eql(u8, s, "get")) return .get;
        if (std.mem.eql(u8, s, "store")) return .store;
        if (std.mem.eql(u8, s, "erase")) return .erase;
        return null;
    }
};

pub const LoginOptions = struct {
    servers: []const []const u8 = &.{},
    username: ?[]const u8 = null,
    password_stdin: bool = false,
    force: bool = false,
};

pub const LogoutOptions = struct {
    servers: []const []const u8 = &.{},
};

pub const Subcommand = union(enum) {
    login: LoginOptions,
    logout: LogoutOptions,
    status,
    credential: Operation,
};

pub const Error = error{
    InvalidServer,
    InvalidSettings,
    InvalidInput,
    EntryNotFound,
    NoStorageAccess,
    Locked,
    StorageFailure,
    AuthenticationFailed,
    NetworkFailure,
    OutOfMemory,
};

pub const StoredCredential = struct {
    server: []u8,
    username: []u8,
    secret: []u8,

    pub fn deinit(self: *const StoredCredential, gpa: Allocator) void {
        gpa.free(self.server);
        gpa.free(self.username);
        std.crypto.secureZero(u8, self.secret);
        gpa.free(self.secret);
    }
};

pub const WinCredOps = struct {
    getEntry: *const fn (gpa: Allocator, target: []const u8) wincred.Error!wincred.Entry,
    set: *const fn (gpa: Allocator, target: []const u8, user: []const u8, value: []const u8) wincred.Error!void,
    delete: *const fn (gpa: Allocator, target: []const u8) wincred.Error!void,
    listEntries: *const fn (gpa: Allocator, filter: []const u8) wincred.Error![]wincred.Entry,
};

const live_wincred_ops: WinCredOps = .{
    .getEntry = liveWinCredGetEntry,
    .set = liveWinCredSet,
    .delete = liveWinCredDelete,
    .listEntries = liveWinCredListEntries,
};

pub const DpapiOps = struct {
    protect: *const fn (gpa: Allocator, data: []const u8) dpapi.Error![]u8,
    unprotect: *const fn (gpa: Allocator, data: []const u8) dpapi.Error![]u8,
};

const live_dpapi_ops: DpapiOps = .{
    .protect = liveDpapiProtect,
    .unprotect = liveDpapiUnprotect,
};

pub const ProviderHooks = struct {
    acquireGhCredential: *const fn (
        gpa: Allocator,
        gh_host: []const u8,
        requested_username: ?[]const u8,
        allow_interactive: bool,
        stderr: *Io.Writer,
    ) gh.AuthError!?gh.GitCredential,
    acquireArmToken: *const fn (
        gpa: Allocator,
        stderr: *Io.Writer,
        allow_interactive: bool,
    ) ado.Error![]u8,
    exchangeAcrToken: *const fn (
        gpa: Allocator,
        server: []const u8,
        arm_access_token: []const u8,
        tenant_id: ?[]const u8,
    ) Error![]u8,
    genericGet: *const fn (gpa: Allocator, service: []const u8, account: []const u8) keyring_zig.Error![]u8,
    genericSet: *const fn (gpa: Allocator, service: []const u8, account: []const u8, password: []const u8) keyring_zig.Error!void,
    nowSeconds: *const fn () i64,
};

const live_provider_hooks: ProviderHooks = .{
    .acquireGhCredential = gh.getOrLoginGitCredential,
    .acquireArmToken = ado.acquireArmAccessToken,
    .exchangeAcrToken = liveExchangeAcrToken,
    .genericGet = keyring_zig.getAlloc,
    .genericSet = keyring_zig.setAlloc,
    .nowSeconds = liveNowSeconds,
};

var wslc_dir_override: ?[]const u8 = null;
var wincred_ops_override: ?WinCredOps = null;
var dpapi_ops_override: ?DpapiOps = null;
var provider_hooks_override: ?ProviderHooks = null;

fn activeWinCredOps() WinCredOps {
    return wincred_ops_override orelse live_wincred_ops;
}

fn activeDpapiOps() DpapiOps {
    return dpapi_ops_override orelse live_dpapi_ops;
}

fn activeProviderHooks() ProviderHooks {
    return provider_hooks_override orelse live_provider_hooks;
}

fn liveWinCredGetEntry(gpa: Allocator, target: []const u8) wincred.Error!wincred.Entry {
    if (builtin.os.tag != .windows) return error.StorageFailure;
    return wincred.getEntry(gpa, target);
}

fn liveWinCredSet(gpa: Allocator, target: []const u8, user: []const u8, value: []const u8) wincred.Error!void {
    if (builtin.os.tag != .windows) return error.StorageFailure;
    return wincred.set(gpa, target, user, value);
}

fn liveWinCredDelete(gpa: Allocator, target: []const u8) wincred.Error!void {
    if (builtin.os.tag != .windows) return error.StorageFailure;
    return wincred.delete(gpa, target);
}

fn liveWinCredListEntries(gpa: Allocator, filter: []const u8) wincred.Error![]wincred.Entry {
    if (builtin.os.tag != .windows) return error.StorageFailure;
    return wincred.listEntries(gpa, filter);
}

fn liveDpapiProtect(gpa: Allocator, data: []const u8) dpapi.Error![]u8 {
    if (builtin.os.tag == .windows) return dpapi.protect(gpa, data);
    return gpa.dupe(u8, data) catch error.OutOfMemory;
}

fn liveDpapiUnprotect(gpa: Allocator, data: []const u8) dpapi.Error![]u8 {
    if (builtin.os.tag == .windows) return dpapi.unprotect(gpa, data);
    return gpa.dupe(u8, data) catch error.OutOfMemory;
}

fn liveNowSeconds() i64 {
    const io = Io.Threaded.global_single_threaded.io();
    return Io.Clock.real.now(io).toSeconds();
}

/// Parse CLI arguments following `keyring wslc`.
pub fn parseArgs(rest: []const []const u8) ?Subcommand {
    if (rest.len == 0) return null;
    const sub = rest[0];
    const tail = rest[1..];

    if (std.mem.eql(u8, sub, "login")) {
        return parseLoginArgs(tail);
    }
    if (std.mem.eql(u8, sub, "logout")) {
        if (tail.len == 0) return null;
        for (tail) |arg| {
            if (arg.len == 0 or std.mem.startsWith(u8, arg, "-")) return null;
        }
        return .{ .logout = .{ .servers = tail } };
    }
    if (std.mem.eql(u8, sub, "status")) {
        if (tail.len != 0) return null;
        return .status;
    }
    if (std.mem.eql(u8, sub, "credential")) {
        if (tail.len != 1) return null;
        const op = Operation.fromString(tail[0]) orelse return null;
        return .{ .credential = op };
    }
    return null;
}

fn parseLoginArgs(args: []const []const u8) ?Subcommand {
    var opts: LoginOptions = .{};
    var positional_start: ?usize = null;
    var positional_count: usize = 0;

    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--force")) {
            opts.force = true;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--password-stdin")) {
            opts.password_stdin = true;
            i += 1;
        } else if (std.mem.eql(u8, arg, "-u") or std.mem.eql(u8, arg, "--username")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return null;
            opts.username = args[i + 1];
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--username=")) {
            const val = arg["--username=".len..];
            if (val.len == 0) return null;
            opts.username = val;
            i += 1;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return null;
        } else {
            if (arg.len == 0) return null;
            if (positional_start == null) {
                positional_start = i;
            } else if (positional_start.? + positional_count != i) {
                // Require flags before or after a contiguous server list so
                // `opts.servers` can slice `args` without allocating.
                return null;
            }
            positional_count += 1;
            i += 1;
        }
    }

    if (positional_start) |start| {
        opts.servers = args[start .. start + positional_count];
    }

    if (opts.password_stdin) {
        if (opts.servers.len != 1 or opts.username == null) return null;
    }

    return .{ .login = opts };
}

/// Normalize a container registry server address matching `wslc`'s
/// `RegistryService::NormalizeServer`:
/// - Strips `<scheme>://` and `/<path>`
/// - Rejects empty input, whitespace/control chars, backslashes, userinfo (`@`),
///   query (`?`), and fragment (`#`)
/// - Maps `docker.io`, `index.docker.io`, and `registry-1.docker.io` to
///   `https://index.docker.io/v1/`
/// - Lowercases the authority while preserving any `:port`
pub fn normalizeServerAlloc(gpa: Allocator, raw_server: []const u8) Error![]u8 {
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

    // Reject query or fragment before stripping path.
    if (std.mem.indexOfAny(u8, s, "?#") != null) return error.InvalidServer;

    if (std.mem.indexOfScalar(u8, s, '/')) |slash_idx| {
        s = s[0..slash_idx];
    }

    if (s.len == 0) return error.InvalidServer;
    if (std.mem.indexOfAny(u8, s, " \t\r\n\\@") != null) return error.InvalidServer;
    for (s) |c| {
        if (std.ascii.isControl(c)) return error.InvalidServer;
    }

    // Validate optional `:port` (handling IPv6 `[::1]:5000` or `host:5000`).
    const host_only = try extractHostWithoutPort(s);
    if (host_only.len == 0) return error.InvalidServer;

    const lowered = try gpa.dupe(u8, s);
    errdefer gpa.free(lowered);
    _ = std.ascii.lowerString(lowered, lowered);

    if (std.mem.eql(u8, lowered, "docker.io") or
        std.mem.eql(u8, lowered, "index.docker.io") or
        std.mem.eql(u8, lowered, "registry-1.docker.io"))
    {
        gpa.free(lowered);
        return gpa.dupe(u8, docker_hub_legacy_url);
    }

    return lowered;
}

fn extractHostWithoutPort(authority: []const u8) Error![]const u8 {
    if (authority.len == 0) return error.InvalidServer;
    if (authority[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidServer;
        if (close <= 1) return error.InvalidServer;
        if (close + 1 < authority.len) {
            if (authority[close + 1] != ':') return error.InvalidServer;
            const port_str = authority[close + 2 ..];
            _ = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidServer;
        }
        return authority[0 .. close + 1];
    }
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon_idx| {
        if (std.mem.indexOfScalar(u8, authority[0..colon_idx], ':') != null) {
            // Unbracketed IPv6 literal.
            return error.InvalidServer;
        }
        const port_str = authority[colon_idx + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidServer;
        if (port == 0) return error.InvalidServer;
        return authority[0..colon_idx];
    }
    return authority;
}

/// If `normalized_server` is a GitHub Container Registry endpoint (`ghcr.io`,
/// `containers.<tenant>.ghe.com`, or `docker.<github-host>`), return the
/// corresponding GitHub host (`github.com`, `<tenant>.ghe.com`, or GHES host)
/// owned by `gpa`.
pub fn resolveGhcrGitHubHostAlloc(gpa: Allocator, normalized_server: []const u8) Error!?[]u8 {
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

const JwtClaims = struct {
    exp: ?i64 = null,
    tid: ?[]const u8 = null,
};

/// Extract the `exp` UNIX timestamp from a JWT string (`header.payload.sig`),
/// or return `null` if the string is not a JWT with a numeric `exp` claim.
pub fn extractJwtExpiration(gpa: Allocator, token: []const u8) ?i64 {
    const payload = decodeJwtPayloadAlloc(gpa, token) orelse return null;
    defer gpa.free(payload);
    const parsed = std.json.parseFromSlice(JwtClaims, gpa, payload, .{
        .ignore_unknown_fields = true,
    }) catch return null;
    defer parsed.deinit();
    return parsed.value.exp;
}

/// Extract the `tid` (Microsoft Entra tenant ID) claim from a JWT string,
/// returning an owned slice when present.
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

/// Resolve the `wslc` configuration directory (`%LOCALAPPDATA%\wslc` on Windows).
pub fn resolveWslcDir(gpa: Allocator) ?[]u8 {
    if (wslc_dir_override) |override| {
        return gpa.dupe(u8, override) catch null;
    }
    if (getEnvVarOwned(gpa, "WSLC_CONFIG_DIR")) |dir| {
        if (dir.len > 0) return dir;
        gpa.free(dir);
    }
    if (builtin.os.tag == .windows) {
        if (getEnvVarOwned(gpa, "LOCALAPPDATA")) |lad| {
            defer gpa.free(lad);
            if (lad.len > 0) return std.fs.path.join(gpa, &.{ lad, "wslc" }) catch null;
        }
        if (getEnvVarOwned(gpa, "USERPROFILE")) |profile| {
            defer gpa.free(profile);
            if (profile.len > 0) return std.fs.path.join(gpa, &.{ profile, "AppData", "Local", "wslc" }) catch null;
        }
    }
    if (getEnvVarOwned(gpa, "XDG_CONFIG_HOME")) |xdg| {
        defer gpa.free(xdg);
        if (xdg.len > 0) return std.fs.path.join(gpa, &.{ xdg, "wslc" }) catch null;
    }
    const home = msal_cache.getHome(gpa) orelse return null;
    defer gpa.free(home);
    return std.fs.path.join(gpa, &.{ home, ".config", "wslc" }) catch null;
}

/// Parse `credentialStore` from `settings.yaml` content, matching `wslc`'s
/// `WSLCUserSettings.cpp` (`wincred` or `default` -> `.wincred`, `file` -> `.file`).
pub fn parseSettingsCredentialStore(content: []const u8) Error!CredentialStoreKind {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        const no_cr = std.mem.trimEnd(u8, raw_line, "\r");
        if (no_cr.len == 0) continue;
        // Top-level setting only (no leading indentation).
        if (no_cr[0] == ' ' or no_cr[0] == '\t' or no_cr[0] == '#') continue;

        const colon = std.mem.indexOfScalar(u8, no_cr, ':') orelse continue;
        const key = std.mem.trim(u8, no_cr[0..colon], " \t");
        if (!std.mem.eql(u8, key, "credentialStore")) continue;

        var raw_val = std.mem.trim(u8, no_cr[colon + 1 ..], " \t");
        if (raw_val.len >= 2 and (raw_val[0] == '"' or raw_val[0] == '\'')) {
            const quote = raw_val[0];
            if (std.mem.indexOfScalar(u8, raw_val[1..], quote)) |close_rel| {
                const after_quote = std.mem.trim(u8, raw_val[1 + close_rel + 1 ..], " \t");
                if (after_quote.len == 0 or after_quote[0] == '#') {
                    raw_val = raw_val[1 .. 1 + close_rel];
                } else {
                    return error.InvalidSettings;
                }
            } else {
                return error.InvalidSettings;
            }
        } else {
            for (raw_val, 0..) |c, idx| {
                if (c == '#' and (idx == 0 or raw_val[idx - 1] == ' ' or raw_val[idx - 1] == '\t')) {
                    raw_val = std.mem.trimEnd(u8, raw_val[0..idx], " \t");
                    break;
                }
            }
        }

        if (raw_val.len == 0 or
            std.ascii.eqlIgnoreCase(raw_val, "default") or
            std.ascii.eqlIgnoreCase(raw_val, "wincred"))
        {
            return .wincred;
        }
        if (std.ascii.eqlIgnoreCase(raw_val, "file")) {
            return .file;
        }
        return error.InvalidSettings;
    }
    return .wincred;
}

/// Detect the active `wslc` `credentialStore` backend from `<wslc_dir>/settings.yaml`.
pub fn detectCredentialStore(gpa: Allocator) Error!CredentialStoreKind {
    const wslc_dir = resolveWslcDir(gpa) orelse return .wincred;
    defer gpa.free(wslc_dir);
    const settings_path = try std.fs.path.join(gpa, &.{ wslc_dir, settings_filename });
    defer gpa.free(settings_path);
    const content = readFileIfExists(gpa, settings_path) orelse return .wincred;
    defer gpa.free(content);
    return parseSettingsCredentialStore(content);
}

// ---------------------------------------------------------------------------
// wslc ICredentialStorage read / write / erase / list (wincred & file)
// ---------------------------------------------------------------------------

const FileCredentialEntry = struct {
    UserName: []const u8,
    Secret: []const u8,
};

const FileCredentialDocument = struct {
    Credentials: std.json.ArrayHashMap(FileCredentialEntry) = .{},
};

pub fn storeWslcCredential(
    gpa: Allocator,
    store_kind: CredentialStoreKind,
    normalized_server: []const u8,
    username: []const u8,
    secret: []const u8,
) Error!void {
    return switch (store_kind) {
        .wincred => storeWinCred(gpa, normalized_server, username, secret),
        .file => storeFileCred(gpa, normalized_server, username, secret),
    };
}

pub fn getWslcCredential(
    gpa: Allocator,
    store_kind: CredentialStoreKind,
    normalized_server: []const u8,
) Error!StoredCredential {
    return switch (store_kind) {
        .wincred => getWinCred(gpa, normalized_server),
        .file => getFileCred(gpa, normalized_server),
    };
}

pub fn eraseWslcCredential(
    gpa: Allocator,
    store_kind: CredentialStoreKind,
    normalized_server: []const u8,
) Error!void {
    return switch (store_kind) {
        .wincred => eraseWinCred(gpa, normalized_server),
        .file => eraseFileCred(gpa, normalized_server),
    };
}

pub fn listWslcCredentials(
    gpa: Allocator,
    store_kind: CredentialStoreKind,
) Error![]StoredCredential {
    return switch (store_kind) {
        .wincred => listWinCred(gpa),
        .file => listFileCred(gpa),
    };
}

fn storeWinCred(gpa: Allocator, normalized_server: []const u8, username: []const u8, secret: []const u8) Error!void {
    const target = try std.fmt.allocPrint(gpa, "{s}{s}", .{ wslc_cred_prefix, normalized_server });
    defer gpa.free(target);
    activeWinCredOps().set(gpa, target, username, secret) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => if (builtin.os.tag != .windows and wincred_ops_override == null)
            error.NoStorageAccess
        else
            error.StorageFailure,
    };
}

fn getWinCred(gpa: Allocator, normalized_server: []const u8) Error!StoredCredential {
    const target = try std.fmt.allocPrint(gpa, "{s}{s}", .{ wslc_cred_prefix, normalized_server });
    defer gpa.free(target);
    const entry = activeWinCredOps().getEntry(gpa, target) catch |err| return switch (err) {
        error.EntryNotFound => error.EntryNotFound,
        error.OutOfMemory => error.OutOfMemory,
        else => if (builtin.os.tag != .windows and wincred_ops_override == null)
            error.NoStorageAccess
        else
            error.StorageFailure,
    };
    errdefer entry.deinit(gpa);

    const server = try gpa.dupe(u8, normalized_server);
    gpa.free(entry.target);
    return .{
        .server = server,
        .username = entry.username,
        .secret = entry.secret,
    };
}

fn eraseWinCred(gpa: Allocator, normalized_server: []const u8) Error!void {
    const target = try std.fmt.allocPrint(gpa, "{s}{s}", .{ wslc_cred_prefix, normalized_server });
    defer gpa.free(target);
    activeWinCredOps().delete(gpa, target) catch |err| return switch (err) {
        error.EntryNotFound => error.EntryNotFound,
        error.OutOfMemory => error.OutOfMemory,
        else => if (builtin.os.tag != .windows and wincred_ops_override == null)
            error.NoStorageAccess
        else
            error.StorageFailure,
    };
}

fn listWinCred(gpa: Allocator) Error![]StoredCredential {
    const entries = activeWinCredOps().listEntries(gpa, wslc_cred_filter) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => if (builtin.os.tag != .windows and wincred_ops_override == null)
            error.NoStorageAccess
        else
            error.StorageFailure,
    };
    defer {
        for (entries) |*e| e.deinit(gpa);
        gpa.free(entries);
    }

    var out = try std.ArrayList(StoredCredential).initCapacity(gpa, entries.len);
    errdefer {
        for (out.items) |*item| item.deinit(gpa);
        out.deinit(gpa);
    }

    for (entries) |e| {
        if (!std.mem.startsWith(u8, e.target, wslc_cred_prefix)) continue;
        const server_part = e.target[wslc_cred_prefix.len..];
        if (server_part.len == 0) continue;

        const server = try gpa.dupe(u8, server_part);
        errdefer gpa.free(server);
        const username = try gpa.dupe(u8, e.username);
        errdefer gpa.free(username);
        const secret = try gpa.dupe(u8, e.secret);

        try out.append(gpa, .{
            .server = server,
            .username = username,
            .secret = secret,
        });
    }
    return out.toOwnedSlice(gpa);
}

fn encodeFileSecretAlloc(gpa: Allocator, plaintext: []const u8) Error![]u8 {
    const protected = activeDpapiOps().protect(gpa, plaintext) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.StorageFailure,
    };
    defer gpa.free(protected);

    const enc_len = std.base64.standard.Encoder.calcSize(protected.len);
    const out = try gpa.alloc(u8, enc_len);
    _ = std.base64.standard.Encoder.encode(out, protected);
    return out;
}

fn decodeFileSecretAlloc(gpa: Allocator, encoded: []const u8) Error![]u8 {
    const trimmed = std.mem.trim(u8, encoded, " \t\r\n");
    const dec_len = std.base64.standard.Decoder.calcSizeForSlice(trimmed) catch return error.StorageFailure;
    const raw_dpapi = try gpa.alloc(u8, dec_len);
    defer gpa.free(raw_dpapi);
    std.base64.standard.Decoder.decode(raw_dpapi, trimmed) catch return error.StorageFailure;

    return activeDpapiOps().unprotect(gpa, raw_dpapi) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.StorageFailure,
    };
}

const FileLock = struct {
    file: Io.File = undefined,
    held: bool = false,

    fn release(self: *FileLock) void {
        if (!self.held) return;
        const io = Io.Threaded.global_single_threaded.io();
        self.file.unlock(io);
        self.file.close(io);
        self.held = false;
    }
};

fn acquireWslcLock(gpa: Allocator, wslc_dir: []const u8) FileLock {
    const io = Io.Threaded.global_single_threaded.io();
    _ = Io.Dir.cwd().createDirPathStatus(io, wslc_dir, dirPermissions()) catch return .{};
    const lock_path = std.fs.path.join(gpa, &.{ wslc_dir, lock_filename }) catch return .{};
    defer gpa.free(lock_path);
    const file = Io.Dir.cwd().createFile(io, lock_path, .{
        .truncate = false,
        .read = true,
        .permissions = filePermissions(),
    }) catch return .{};
    file.lock(io, .exclusive) catch {
        file.close(io);
        return .{};
    };
    return .{ .file = file, .held = true };
}

fn storeFileCred(gpa: Allocator, normalized_server: []const u8, username: []const u8, secret: []const u8) Error!void {
    const wslc_dir = resolveWslcDir(gpa) orelse return error.NoStorageAccess;
    defer gpa.free(wslc_dir);

    var lock = acquireWslcLock(gpa, wslc_dir);
    defer lock.release();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const creds_path = try std.fs.path.join(a, &.{ wslc_dir, credentials_filename });
    var doc: FileCredentialDocument = .{};
    if (readFileIfExists(a, creds_path)) |bytes| {
        if (bytes.len > 0) {
            doc = std.json.parseFromSliceLeaky(FileCredentialDocument, a, bytes, .{
                .ignore_unknown_fields = true,
                .allocate = .alloc_always,
            }) catch return error.StorageFailure;
        }
    }

    const encoded_secret = try encodeFileSecretAlloc(a, secret);
    try doc.Credentials.map.put(a, normalized_server, .{
        .UserName = username,
        .Secret = encoded_secret,
    });

    const serialized = try serializeFileCredentialDocument(a, &doc);
    try writeFileAtomic(a, creds_path, serialized);
}

fn getFileCred(gpa: Allocator, normalized_server: []const u8) Error!StoredCredential {
    const wslc_dir = resolveWslcDir(gpa) orelse return error.NoStorageAccess;
    defer gpa.free(wslc_dir);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const creds_path = try std.fs.path.join(a, &.{ wslc_dir, credentials_filename });
    const bytes = readFileIfExists(a, creds_path) orelse return error.EntryNotFound;
    if (bytes.len == 0) return error.EntryNotFound;

    const doc = std.json.parseFromSliceLeaky(FileCredentialDocument, a, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.StorageFailure;

    const entry = doc.Credentials.map.get(normalized_server) orelse return error.EntryNotFound;
    const secret = try decodeFileSecretAlloc(gpa, entry.Secret);
    errdefer {
        std.crypto.secureZero(u8, secret);
        gpa.free(secret);
    }
    const server = try gpa.dupe(u8, normalized_server);
    errdefer gpa.free(server);
    const username = try gpa.dupe(u8, entry.UserName);

    return .{
        .server = server,
        .username = username,
        .secret = secret,
    };
}

fn eraseFileCred(gpa: Allocator, normalized_server: []const u8) Error!void {
    const wslc_dir = resolveWslcDir(gpa) orelse return error.NoStorageAccess;
    defer gpa.free(wslc_dir);

    var lock = acquireWslcLock(gpa, wslc_dir);
    defer lock.release();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const creds_path = try std.fs.path.join(a, &.{ wslc_dir, credentials_filename });
    const bytes = readFileIfExists(a, creds_path) orelse return error.EntryNotFound;
    if (bytes.len == 0) return error.EntryNotFound;

    var doc = std.json.parseFromSliceLeaky(FileCredentialDocument, a, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.StorageFailure;

    if (!doc.Credentials.map.orderedRemove(normalized_server)) {
        return error.EntryNotFound;
    }

    const serialized = try serializeFileCredentialDocument(a, &doc);
    try writeFileAtomic(a, creds_path, serialized);
}

fn listFileCred(gpa: Allocator) Error![]StoredCredential {
    const wslc_dir = resolveWslcDir(gpa) orelse return error.NoStorageAccess;
    defer gpa.free(wslc_dir);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const creds_path = try std.fs.path.join(a, &.{ wslc_dir, credentials_filename });
    const bytes = readFileIfExists(a, creds_path) orelse return gpa.alloc(StoredCredential, 0);
    if (bytes.len == 0) return gpa.alloc(StoredCredential, 0);

    const doc = std.json.parseFromSliceLeaky(FileCredentialDocument, a, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.StorageFailure;

    var out = try std.ArrayList(StoredCredential).initCapacity(gpa, doc.Credentials.map.count());
    errdefer {
        for (out.items) |*item| item.deinit(gpa);
        out.deinit(gpa);
    }

    var it = doc.Credentials.map.iterator();
    while (it.next()) |kv| {
        const secret = try decodeFileSecretAlloc(gpa, kv.value_ptr.Secret);
        errdefer {
            std.crypto.secureZero(u8, secret);
            gpa.free(secret);
        }
        const server = try gpa.dupe(u8, kv.key_ptr.*);
        errdefer gpa.free(server);
        const username = try gpa.dupe(u8, kv.value_ptr.UserName);

        try out.append(gpa, .{
            .server = server,
            .username = username,
            .secret = secret,
        });
    }
    return out.toOwnedSlice(gpa);
}

fn serializeFileCredentialDocument(gpa: Allocator, doc: *const FileCredentialDocument) Error![]u8 {
    var out = Io.Writer.Allocating.init(gpa);
    defer out.deinit();

    out.writer.writeAll("{\n  \"Credentials\": {") catch return error.OutOfMemory;
    var first = true;
    var it = doc.Credentials.map.iterator();
    while (it.next()) |kv| {
        if (!first) out.writer.writeAll(",") catch return error.OutOfMemory;
        first = false;
        out.writer.writeAll("\n    ") catch return error.OutOfMemory;
        try writeJsonString(&out.writer, kv.key_ptr.*);
        out.writer.writeAll(": {\n      \"Secret\": ") catch return error.OutOfMemory;
        try writeJsonString(&out.writer, kv.value_ptr.Secret);
        out.writer.writeAll(",\n      \"UserName\": ") catch return error.OutOfMemory;
        try writeJsonString(&out.writer, kv.value_ptr.UserName);
        out.writer.writeAll("\n    }") catch return error.OutOfMemory;
    }
    out.writer.writeAll("\n  }\n}\n") catch return error.OutOfMemory;
    return out.toOwnedSlice() catch error.OutOfMemory;
}

// ---------------------------------------------------------------------------
// Provider Resolution (GHCR, ACR OAuth2 exchange, and Generic keyring)
// ---------------------------------------------------------------------------

const AcrExchangeResponse = struct {
    refresh_token: ?[]const u8 = null,
};

fn liveExchangeAcrToken(
    gpa: Allocator,
    server: []const u8,
    arm_access_token: []const u8,
    tenant_id: ?[]const u8,
) Error![]u8 {
    const url = try std.fmt.allocPrint(gpa, "https://{s}/oauth2/exchange", .{server});
    defer gpa.free(url);

    var body = Io.Writer.Allocating.init(gpa);
    defer body.deinit();
    try writeFormField(&body.writer, "grant_type", "access_token", true);
    try writeFormField(&body.writer, "service", server, false);
    if (tenant_id) |tid| {
        if (tid.len > 0) {
            try writeFormField(&body.writer, "tenant", tid, false);
        }
    }
    try writeFormField(&body.writer, "access_token", arm_access_token, false);

    var response = Io.Writer.Allocating.init(gpa);
    defer response.deinit();

    var client: std.http.Client = .{
        .allocator = gpa,
        .io = Io.Threaded.global_single_threaded.io(),
    };
    defer client.deinit();

    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .payload = body.written(),
        .headers = .{ .content_type = .{ .override = "application/x-www-form-urlencoded" } },
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

/// Resolve a credential for `normalized_server` from GHCR (`src/gh.zig`),
/// ACR (`src/msal_cache.zig` + `src/ado.zig` + `POST /oauth2/exchange`), or
/// the generic `keyring` store.
pub fn resolveRegistryCredential(
    gpa: Allocator,
    store_kind: CredentialStoreKind,
    normalized_server: []const u8,
    requested_username: ?[]const u8,
    force: bool,
    allow_interactive: bool,
    stderr: *Io.Writer,
) Error!StoredCredential {
    const hooks = activeProviderHooks();

    // 1. GitHub Container Registry (`ghcr.io`, `containers.<tenant>.ghe.com`, `docker.<ghe-host>`).
    if (try resolveGhcrGitHubHostAlloc(gpa, normalized_server)) |gh_host| {
        defer gpa.free(gh_host);
        const maybe_cred = hooks.acquireGhCredential(
            gpa,
            gh_host,
            requested_username,
            allow_interactive and !ado.isNonInteractive(),
            stderr,
        ) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.Locked => error.Locked,
            error.NoStorageAccess => error.NoStorageAccess,
            error.NetworkFailure => error.NetworkFailure,
            else => error.AuthenticationFailed,
        };
        const cred = maybe_cred orelse return error.EntryNotFound;
        defer cred.deinit(gpa);

        const effective_user = if (requested_username) |req_u|
            req_u
        else
            cred.username;

        return .{
            .server = try gpa.dupe(u8, normalized_server),
            .username = try gpa.dupe(u8, effective_user),
            .secret = try gpa.dupe(u8, cred.token),
        };
    }

    // 2. Azure Container Registry (`*.azurecr.io`, `*.azurecr.cn`, `*.azurecr.de`, `*.azurecr.us`).
    if (isAcrServer(normalized_server)) {
        if (!force) {
            if (getWslcCredential(gpa, store_kind, normalized_server)) |existing| {
                const now = hooks.nowSeconds();
                if (extractJwtExpiration(gpa, existing.secret)) |exp| {
                    if (exp > now + 300) {
                        return existing;
                    }
                }
                existing.deinit(gpa);
            } else |_| {}
        }

        const arm_token = hooks.acquireArmToken(
            gpa,
            stderr,
            allow_interactive and !ado.isNonInteractive(),
        ) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.NoStorageAccess => error.EntryNotFound,
            error.NetworkFailure => error.NetworkFailure,
            else => error.AuthenticationFailed,
        };
        defer {
            std.crypto.secureZero(u8, arm_token);
            gpa.free(arm_token);
        }

        const maybe_tid = extractJwtTenantIdAlloc(gpa, arm_token);
        defer if (maybe_tid) |tid| gpa.free(tid);

        const acr_token = try hooks.exchangeAcrToken(gpa, normalized_server, arm_token, maybe_tid);
        errdefer {
            std.crypto.secureZero(u8, acr_token);
            gpa.free(acr_token);
        }

        const user = requested_username orelse acr_token_username;
        return .{
            .server = try gpa.dupe(u8, normalized_server),
            .username = try gpa.dupe(u8, user),
            .secret = acr_token,
        };
    }

    // 3. Generic registry: check existing wslc credential if username not forced, or generic keyring.
    if (requested_username) |user| {
        const service = try genericServiceNameAlloc(gpa, normalized_server);
        defer gpa.free(service);
        if (hooks.genericGet(gpa, service, user)) |secret| {
            errdefer {
                std.crypto.secureZero(u8, secret);
                gpa.free(secret);
            }
            return .{
                .server = try gpa.dupe(u8, normalized_server),
                .username = try gpa.dupe(u8, user),
                .secret = secret,
            };
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Locked => return error.Locked,
            else => {},
        }
    }

    if (getWslcCredential(gpa, store_kind, normalized_server)) |existing| {
        if (requested_username == null or std.mem.eql(u8, existing.username, requested_username.?)) {
            if (extractJwtExpiration(gpa, existing.secret)) |exp| {
                if (exp <= hooks.nowSeconds()) {
                    existing.deinit(gpa);
                    return error.EntryNotFound;
                }
            }
            return existing;
        }
        existing.deinit(gpa);
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {},
    }

    return error.EntryNotFound;
}

fn genericServiceNameAlloc(gpa: Allocator, normalized_server: []const u8) ![]u8 {
    if (std.mem.indexOf(u8, normalized_server, "://") != null) {
        return gpa.dupe(u8, normalized_server);
    }
    return std.fmt.allocPrint(gpa, "https://{s}", .{normalized_server});
}

// ---------------------------------------------------------------------------
// Command execution: login, logout, status, credential, diagnose
// ---------------------------------------------------------------------------

pub fn run(
    gpa: Allocator,
    subcommand: Subcommand,
    stdin: *Io.Reader,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    return switch (subcommand) {
        .login => |opts| runLogin(gpa, opts, stdin, stdout, stderr),
        .logout => |opts| runLogout(gpa, opts, stdout, stderr),
        .status => runStatus(gpa, stdout, stderr),
        .credential => |op| runCredentialHelper(gpa, op, stdin, stdout, stderr),
    };
}

fn runLogin(
    gpa: Allocator,
    opts: LoginOptions,
    stdin: *Io.Reader,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const store_kind = detectCredentialStore(a) catch |err| {
        try stderr.print("keyring: wslc login: invalid wslc settings.yaml: {s}\n", .{@errorName(err)});
        try stderr.flush();
        return 1;
    };

    if (opts.password_stdin) {
        const normalized = normalizeServerAlloc(a, opts.servers[0]) catch {
            try stderr.print("keyring: wslc login: invalid registry server '{s}'\n", .{opts.servers[0]});
            try stderr.flush();
            return 2;
        };
        const user = opts.username.?;
        const secret = readBoundedStdinSecret(a, stdin) catch |err| {
            try stderr.print("keyring: wslc login: invalid password on stdin: {s}\n", .{@errorName(err)});
            try stderr.flush();
            return 2;
        };
        defer std.crypto.secureZero(u8, secret);

        // Also store in generic keyring when not an identity-token placeholder.
        if (!std.mem.eql(u8, user, identity_token_username) and
            !std.mem.eql(u8, user, acr_token_username))
        {
            if (genericServiceNameAlloc(a, normalized)) |svc| {
                activeProviderHooks().genericSet(a, svc, user, secret) catch {};
            } else |_| {}
        }

        storeWslcCredential(a, store_kind, normalized, user, secret) catch |err| {
            return reportError(stderr, "wslc login", normalized, err);
        };
        try stdout.print("Logged in to {s} as {s} (wslc {s} store)\n", .{
            normalized,
            user,
            store_kind.name(),
        });
        try stdout.flush();
        return 0;
    }

    var target_servers = std.ArrayList([]const u8).empty;
    for (opts.servers) |srv| {
        const norm = normalizeServerAlloc(a, srv) catch {
            try stderr.print("keyring: wslc login: invalid registry server '{s}'\n", .{srv});
            try stderr.flush();
            return 2;
        };
        if (!containsString(target_servers.items, norm)) {
            try target_servers.append(a, norm);
        }
    }

    // When no servers were explicitly passed, refresh all registries currently
    // present in wslc's credential store plus ghcr.io if a GitHub login exists.
    if (target_servers.items.len == 0) {
        if (listWslcCredentials(a, store_kind)) |existing_list| {
            for (existing_list) |item| {
                if (!containsString(target_servers.items, item.server)) {
                    try target_servers.append(a, item.server);
                }
            }
        } else |_| {}

        if (!containsString(target_servers.items, "ghcr.io")) {
            if (activeProviderHooks().acquireGhCredential(a, "github.com", opts.username, false, stderr)) |maybe_gh| {
                if (maybe_gh) |cred| {
                    cred.deinit(a);
                    try target_servers.append(a, "ghcr.io");
                }
            } else |_| {}
        }

        if (target_servers.items.len == 0) {
            try stderr.writeAll("keyring: wslc login: specify at least one <server> (e.g. 'keyring wslc login ghcr.io myregistry.azurecr.io')\n");
            try stderr.flush();
            return 2;
        }
    }

    for (target_servers.items) |normalized| {
        const cred = resolveRegistryCredential(
            a,
            store_kind,
            normalized,
            opts.username,
            opts.force,
            true,
            stderr,
        ) catch |err| {
            return reportError(stderr, "wslc login", normalized, err);
        };
        defer cred.deinit(a);

        storeWslcCredential(a, store_kind, normalized, cred.username, cred.secret) catch |err| {
            return reportError(stderr, "wslc login", normalized, err);
        };

        try stdout.print("Logged in to {s} as {s} (wslc {s} store)\n", .{
            normalized,
            cred.username,
            store_kind.name(),
        });
    }
    try stdout.flush();
    return 0;
}

fn runLogout(
    gpa: Allocator,
    opts: LogoutOptions,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const store_kind = detectCredentialStore(a) catch |err| {
        try stderr.print("keyring: wslc logout: invalid wslc settings.yaml: {s}\n", .{@errorName(err)});
        try stderr.flush();
        return 1;
    };

    var any_missing = false;
    for (opts.servers) |raw_server| {
        const normalized = normalizeServerAlloc(a, raw_server) catch {
            try stderr.print("keyring: wslc logout: invalid registry server '{s}'\n", .{raw_server});
            try stderr.flush();
            return 2;
        };
        eraseWslcCredential(a, store_kind, normalized) catch |err| switch (err) {
            error.EntryNotFound => {
                try stderr.print("keyring: wslc logout: not logged in to {s}\n", .{normalized});
                any_missing = true;
                continue;
            },
            else => return reportError(stderr, "wslc logout", normalized, err),
        };
        try stdout.print("Removed wslc login credentials for {s}\n", .{normalized});
    }
    try stdout.flush();
    try stderr.flush();
    return if (any_missing) 3 else 0;
}

fn runStatus(
    gpa: Allocator,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const store_kind = detectCredentialStore(a) catch |err| {
        try stderr.print("keyring: wslc status: invalid wslc settings.yaml: {s}\n", .{@errorName(err)});
        try stderr.flush();
        return 1;
    };

    try writeStatusReport(a, store_kind, stdout);
    try stdout.flush();
    return 0;
}

/// Print a summary of `wslc` credential storage for `keyring diagnose` and `keyring wslc status`.
pub fn diagnose(gpa: Allocator, stdout: *Io.Writer) !void {
    if (builtin.os.tag != .windows and wslc_dir_override == null and wincred_ops_override == null) {
        return;
    }
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const store_kind = detectCredentialStore(a) catch {
        try stdout.writeAll("wslc credential store: invalid settings.yaml\n");
        return;
    };
    try writeStatusReport(a, store_kind, stdout);
}

fn writeStatusReport(a: Allocator, store_kind: CredentialStoreKind, stdout: *Io.Writer) !void {
    const wslc_dir = resolveWslcDir(a) orelse "<unavailable>";
    const settings_path = if (std.mem.eql(u8, wslc_dir, "<unavailable>"))
        "<unavailable>"
    else
        try std.fs.path.join(a, &.{ wslc_dir, settings_filename });

    try stdout.print("wslc settings file: {s}\n", .{settings_path});
    try stdout.print("wslc credentialStore: {s}\n", .{store_kind.name()});

    const entries = listWslcCredentials(a, store_kind) catch |err| {
        try stdout.print("wslc registries: unavailable ({s})\n", .{@errorName(err)});
        return;
    };

    if (entries.len == 0) {
        try stdout.writeAll("wslc registries: none configured\n");
        return;
    }

    const now = activeProviderHooks().nowSeconds();
    try stdout.print("wslc registries ({d}):\n", .{entries.len});
    for (entries) |entry| {
        if (extractJwtExpiration(a, entry.secret)) |exp| {
            if (exp > now) {
                const remaining_mins = @divFloor(exp - now, 60);
                try stdout.print("  {s}: user={s}, status=valid (expires in {d}m)\n", .{
                    entry.server,
                    entry.username,
                    remaining_mins,
                });
            } else {
                try stdout.print("  {s}: user={s}, status=expired\n", .{
                    entry.server,
                    entry.username,
                });
            }
        } else {
            try stdout.print("  {s}: user={s}, status=present\n", .{
                entry.server,
                entry.username,
            });
        }
    }
}

const HelperStoreInput = struct {
    ServerURL: ?[]const u8 = null,
    Username: ?[]const u8 = null,
    Secret: ?[]const u8 = null,
};

fn runCredentialHelper(
    gpa: Allocator,
    op: Operation,
    stdin: *Io.Reader,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const store_kind = detectCredentialStore(a) catch {
        try stdout.writeAll("invalid wslc settings.yaml\n");
        try stdout.flush();
        return 1;
    };

    switch (op) {
        .get => {
            const raw_server = readBoundedStdinLine(a, stdin, 4096) catch {
                try stdout.writeAll("invalid registry server input\n");
                try stdout.flush();
                return 1;
            };
            const normalized = normalizeServerAlloc(a, raw_server) catch {
                try stdout.writeAll("invalid registry server URL\n");
                try stdout.flush();
                return 1;
            };
            // Helper `get` is strictly noninteractive: never launch browser or device login.
            const cred = resolveRegistryCredential(
                a,
                store_kind,
                normalized,
                null,
                false,
                false,
                stderr,
            ) catch |err| {
                const msg = switch (err) {
                    error.EntryNotFound => "credentials not found in native keychain\n",
                    error.Locked => "credential store is locked\n",
                    else => "failed to retrieve credentials\n",
                };
                try stdout.writeAll(msg);
                try stdout.flush();
                return 1;
            };
            defer cred.deinit(a);

            try stdout.writeAll("{\"ServerURL\":");
            try writeJsonString(stdout, cred.server);
            try stdout.writeAll(",\"Username\":");
            try writeJsonString(stdout, cred.username);
            try stdout.writeAll(",\"Secret\":");
            try writeJsonString(stdout, cred.secret);
            try stdout.writeAll("}\n");
            try stdout.flush();
            return 0;
        },
        .store => {
            const raw_json = readBoundedStdinAll(a, stdin, 64 * 1024) catch {
                try stderr.writeAll("keyring: wslc credential store: invalid or oversized input\n");
                try stderr.flush();
                return 1;
            };
            defer std.crypto.secureZero(u8, raw_json);

            const parsed = std.json.parseFromSlice(HelperStoreInput, a, raw_json, .{
                .ignore_unknown_fields = true,
            }) catch {
                try stderr.writeAll("keyring: wslc credential store: malformed JSON input\n");
                try stderr.flush();
                return 1;
            };
            defer parsed.deinit();

            const srv = parsed.value.ServerURL orelse return 1;
            const user = parsed.value.Username orelse return 1;
            const sec = parsed.value.Secret orelse return 1;
            if (user.len == 0 or sec.len == 0 or
                std.mem.indexOfScalar(u8, user, 0) != null or
                std.mem.indexOfScalar(u8, sec, 0) != null)
            {
                return 1;
            }
            const normalized = normalizeServerAlloc(a, srv) catch return 1;
            storeWslcCredential(a, store_kind, normalized, user, sec) catch return 1;
            return 0;
        },
        .erase => {
            const raw_server = readBoundedStdinLine(a, stdin, 4096) catch return 1;
            const normalized = normalizeServerAlloc(a, raw_server) catch return 1;
            eraseWslcCredential(a, store_kind, normalized) catch |err| switch (err) {
                error.EntryNotFound => return 0,
                else => return 1,
            };
            return 0;
        },
    }
}

fn readBoundedStdinSecret(gpa: Allocator, stdin: *Io.Reader) Error![]u8 {
    return readBoundedStdinLine(gpa, stdin, 64 * 1024);
}

fn readBoundedStdinLine(gpa: Allocator, stdin: *Io.Reader, max_bytes: usize) Error![]u8 {
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

fn readBoundedStdinAll(gpa: Allocator, stdin: *Io.Reader, max_bytes: usize) Error![]u8 {
    var writer = Io.Writer.Allocating.init(gpa);
    errdefer writer.deinit();
    _ = stdin.streamRemaining(&writer.writer) catch return error.InvalidInput;
    const written = writer.written();
    if (written.len == 0 or written.len > max_bytes) {
        return error.InvalidInput;
    }
    return writer.toOwnedSlice() catch error.OutOfMemory;
}

fn reportError(stderr: *Io.Writer, cmd_label: []const u8, server: []const u8, err: Error) !u8 {
    switch (err) {
        error.EntryNotFound => {
            try stderr.print("keyring: {s}: no credentials found for {s}\n", .{ cmd_label, server });
            try stderr.flush();
            return 3;
        },
        error.Locked => {
            try stderr.print("keyring: {s}: credential store is locked (run 'keyring unlock' first)\n", .{cmd_label});
            try stderr.flush();
            return 1;
        },
        error.NoStorageAccess, error.StorageFailure => {
            try stderr.print("keyring: {s}: storage unavailable for {s}: {s}\n", .{ cmd_label, server, @errorName(err) });
            try stderr.flush();
            return 4;
        },
        error.InvalidServer, error.InvalidInput => {
            try stderr.print("keyring: {s}: invalid input for {s}\n", .{ cmd_label, server });
            try stderr.flush();
            return 2;
        },
        else => {
            try stderr.print("keyring: {s}: failed to authenticate {s}: {s}\n", .{ cmd_label, server, @errorName(err) });
            try stderr.flush();
            return 1;
        },
    }
}

fn containsString(list: []const []const u8, needle: []const u8) bool {
    for (list) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

fn writeJsonString(writer: *Io.Writer, value: []const u8) Error!void {
    writer.writeByte('"') catch return error.StorageFailure;
    for (value) |c| switch (c) {
        '\\' => writer.writeAll("\\\\") catch return error.StorageFailure,
        '"' => writer.writeAll("\\\"") catch return error.StorageFailure,
        '\n' => writer.writeAll("\\n") catch return error.StorageFailure,
        '\r' => writer.writeAll("\\r") catch return error.StorageFailure,
        '\t' => writer.writeAll("\\t") catch return error.StorageFailure,
        else => writer.writeByte(c) catch return error.StorageFailure,
    };
    writer.writeByte('"') catch return error.StorageFailure;
}

fn readFileIfExists(gpa: Allocator, path: []const u8) ?[]u8 {
    const io = Io.Threaded.global_single_threaded.io();
    return Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(4 * 1024 * 1024)) catch null;
}

fn writeFileAtomic(gpa: Allocator, path: []const u8, contents: []const u8) Error!void {
    const io = Io.Threaded.global_single_threaded.io();
    const parent = std.fs.path.dirname(path) orelse return error.StorageFailure;
    _ = Io.Dir.cwd().createDirPathStatus(io, parent, dirPermissions()) catch return error.StorageFailure;

    var suffix_bytes: [8]u8 = undefined;
    io.random(&suffix_bytes);
    const suffix_hex = std.fmt.bytesToHex(suffix_bytes, .lower);
    const tmp = try std.fmt.allocPrint(gpa, "{s}.{s}.tmp", .{ path, suffix_hex });
    defer gpa.free(tmp);
    {
        var file = Io.Dir.cwd().createFile(io, tmp, .{
            .truncate = true,
            .permissions = filePermissions(),
        }) catch return error.StorageFailure;
        defer file.close(io);
        file.writeStreamingAll(io, contents) catch return error.StorageFailure;
    }
    Io.Dir.renameAbsolute(tmp, path, io) catch return error.StorageFailure;
}

fn dirPermissions() Io.File.Permissions {
    return if (builtin.os.tag == .windows or builtin.os.tag == .wasi) .default_dir else .fromMode(0o700);
}

fn filePermissions() Io.File.Permissions {
    return if (builtin.os.tag == .windows or builtin.os.tag == .wasi) .default_file else .fromMode(0o600);
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
// Unit tests
// ---------------------------------------------------------------------------

const FakeWinCred = struct {
    var targets: [8][128]u8 = undefined;
    var target_lens: [8]usize = @splat(0);
    var users: [8][128]u8 = undefined;
    var user_lens: [8]usize = @splat(0);
    var secrets: [8][512]u8 = undefined;
    var secret_lens: [8]usize = @splat(0);
    var used: [8]bool = @splat(false);

    fn reset() void {
        used = @splat(false);
    }

    fn getEntry(gpa: Allocator, target: []const u8) wincred.Error!wincred.Entry {
        for (0..8) |idx| {
            if (!used[idx]) continue;
            if (std.mem.eql(u8, targets[idx][0..target_lens[idx]], target)) {
                return .{
                    .target = try gpa.dupe(u8, targets[idx][0..target_lens[idx]]),
                    .username = try gpa.dupe(u8, users[idx][0..user_lens[idx]]),
                    .secret = try gpa.dupe(u8, secrets[idx][0..secret_lens[idx]]),
                };
            }
        }
        return error.EntryNotFound;
    }

    fn set(_: Allocator, target: []const u8, user: []const u8, value: []const u8) wincred.Error!void {
        for (0..8) |idx| {
            if (used[idx] and std.mem.eql(u8, targets[idx][0..target_lens[idx]], target)) {
                @memcpy(users[idx][0..user.len], user);
                user_lens[idx] = user.len;
                @memcpy(secrets[idx][0..value.len], value);
                secret_lens[idx] = value.len;
                return;
            }
        }
        for (0..8) |idx| {
            if (!used[idx]) {
                used[idx] = true;
                @memcpy(targets[idx][0..target.len], target);
                target_lens[idx] = target.len;
                @memcpy(users[idx][0..user.len], user);
                user_lens[idx] = user.len;
                @memcpy(secrets[idx][0..value.len], value);
                secret_lens[idx] = value.len;
                return;
            }
        }
        return error.StorageFailure;
    }

    fn delete(_: Allocator, target: []const u8) wincred.Error!void {
        for (0..8) |idx| {
            if (used[idx] and std.mem.eql(u8, targets[idx][0..target_lens[idx]], target)) {
                used[idx] = false;
                return;
            }
        }
        return error.EntryNotFound;
    }

    fn listEntries(gpa: Allocator, _: []const u8) wincred.Error![]wincred.Entry {
        var list = std.ArrayList(wincred.Entry).empty;
        errdefer {
            for (list.items) |*e| e.deinit(gpa);
            list.deinit(gpa);
        }
        for (0..8) |idx| {
            if (!used[idx]) continue;
            try list.append(gpa, .{
                .target = try gpa.dupe(u8, targets[idx][0..target_lens[idx]]),
                .username = try gpa.dupe(u8, users[idx][0..user_lens[idx]]),
                .secret = try gpa.dupe(u8, secrets[idx][0..secret_lens[idx]]),
            });
        }
        return list.toOwnedSlice(gpa);
    }

    const ops: WinCredOps = .{
        .getEntry = getEntry,
        .set = set,
        .delete = delete,
        .listEntries = listEntries,
    };
};

test "normalizeServerAlloc matches wslc RegistryService::NormalizeServer and rejects unsafe input" {
    const gpa = std.testing.allocator;

    {
        const s = try normalizeServerAlloc(gpa, "https://GHCR.IO/cataggar/keyring:latest");
        defer gpa.free(s);
        try std.testing.expectEqualStrings("ghcr.io", s);
    }
    {
        const s = try normalizeServerAlloc(gpa, "docker.io");
        defer gpa.free(s);
        try std.testing.expectEqualStrings("https://index.docker.io/v1/", s);
    }
    {
        const s = try normalizeServerAlloc(gpa, "https://index.docker.io/v1/");
        defer gpa.free(s);
        try std.testing.expectEqualStrings("https://index.docker.io/v1/", s);
    }
    {
        const s = try normalizeServerAlloc(gpa, "localhost:5000/repo/image");
        defer gpa.free(s);
        try std.testing.expectEqualStrings("localhost:5000", s);
    }
    {
        const s = try normalizeServerAlloc(gpa, "[::1]:5000/repo");
        defer gpa.free(s);
        try std.testing.expectEqualStrings("[::1]:5000", s);
    }

    try std.testing.expectError(error.InvalidServer, normalizeServerAlloc(gpa, ""));
    try std.testing.expectError(error.InvalidServer, normalizeServerAlloc(gpa, "https://alice:secret@ghcr.io"));
    try std.testing.expectError(error.InvalidServer, normalizeServerAlloc(gpa, "ghcr.io?token=1"));
    try std.testing.expectError(error.InvalidServer, normalizeServerAlloc(gpa, "ghcr.io#frag"));
    try std.testing.expectError(error.InvalidServer, normalizeServerAlloc(gpa, "ftp://ghcr.io"));
    try std.testing.expectError(error.InvalidServer, normalizeServerAlloc(gpa, "ghcr.io:99999"));
}

test "parseSettingsCredentialStore handles wincred, file, default, comments, and invalid values" {
    try std.testing.expectEqual(CredentialStoreKind.wincred, try parseSettingsCredentialStore(
        \\# wslc user settings
        \\# credentialStore: wincred
        \\session:
        \\  cpuCount: default
    ));
    try std.testing.expectEqual(CredentialStoreKind.wincred, try parseSettingsCredentialStore("credentialStore: default\n"));
    try std.testing.expectEqual(CredentialStoreKind.wincred, try parseSettingsCredentialStore("credentialStore: \"wincred\" # inline comment\n"));
    try std.testing.expectEqual(CredentialStoreKind.file, try parseSettingsCredentialStore("credentialStore: file\n"));
    try std.testing.expectError(error.InvalidSettings, parseSettingsCredentialStore("credentialStore: bogus\n"));
}

test "resolveGhcrGitHubHostAlloc and isAcrServer classify registries accurately" {
    const gpa = std.testing.allocator;

    const gh1 = (try resolveGhcrGitHubHostAlloc(gpa, "ghcr.io")).?;
    defer gpa.free(gh1);
    try std.testing.expectEqualStrings("github.com", gh1);

    const gh2 = (try resolveGhcrGitHubHostAlloc(gpa, "containers.octocorp.ghe.com")).?;
    defer gpa.free(gh2);
    try std.testing.expectEqualStrings("octocorp.ghe.com", gh2);

    try std.testing.expect((try resolveGhcrGitHubHostAlloc(gpa, "myregistry.azurecr.io")) == null);

    try std.testing.expect(isAcrServer("myregistry.azurecr.io"));
    try std.testing.expect(isAcrServer("myregistry.azurecr.io:443"));
    try std.testing.expect(isAcrServer("govreg.azurecr.us"));
    try std.testing.expect(!isAcrServer("azurecr.io"));
    try std.testing.expect(!isAcrServer("ghcr.io"));
}

test "extractJwtExpiration and extractJwtTenantIdAlloc decode JWT claims" {
    const gpa = std.testing.allocator;
    // Header: {"alg":"none"} -> eyJhbGciOiJub25lIn0
    // Payload: {"exp":1893456000,"tid":"11111111-2222-3333-4444-555555555555"}
    //   base64url -> eyJleHAiOjE4OTM0NTYwMDAsInRpZCI6IjExMTExMTExLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NSJ9
    const jwt = "eyJhbGciOiJub25lIn0.eyJleHAiOjE4OTM0NTYwMDAsInRpZCI6IjExMTExMTExLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NSJ9.sig";

    try std.testing.expectEqual(@as(?i64, 1893456000), extractJwtExpiration(gpa, jwt));
    const tid = extractJwtTenantIdAlloc(gpa, jwt).?;
    defer gpa.free(tid);
    try std.testing.expectEqualStrings("11111111-2222-3333-4444-555555555555", tid);
}

test "FileCredStorage and WinCredStorage round-trip store, get, list, and erase" {
    const gpa = std.testing.allocator;
    const io = Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = try gpa.dupe(u8, path_buf[0..path_len]);
    defer gpa.free(dir_path);

    wslc_dir_override = dir_path;
    defer wslc_dir_override = null;

    FakeWinCred.reset();
    wincred_ops_override = FakeWinCred.ops;
    defer wincred_ops_override = null;

    for ([_]CredentialStoreKind{ .wincred, .file }) |kind| {
        try storeWslcCredential(gpa, kind, "ghcr.io", "cataggar", "gho_secret_123");
        try storeWslcCredential(gpa, kind, "myacr.azurecr.io", acr_token_username, "acr_rt_456");

        const got = try getWslcCredential(gpa, kind, "ghcr.io");
        defer got.deinit(gpa);
        try std.testing.expectEqualStrings("ghcr.io", got.server);
        try std.testing.expectEqualStrings("cataggar", got.username);
        try std.testing.expectEqualStrings("gho_secret_123", got.secret);

        const all = try listWslcCredentials(gpa, kind);
        defer {
            for (all) |*item| item.deinit(gpa);
            gpa.free(all);
        }
        try std.testing.expectEqual(@as(usize, 2), all.len);

        try eraseWslcCredential(gpa, kind, "ghcr.io");
        try std.testing.expectError(error.EntryNotFound, getWslcCredential(gpa, kind, "ghcr.io"));
        try eraseWslcCredential(gpa, kind, "myacr.azurecr.io");
    }
}

test "wslc login, credential get/store/erase, and logout work end-to-end with mocked providers" {
    const gpa = std.testing.allocator;
    const io = Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = try gpa.dupe(u8, path_buf[0..path_len]);
    defer gpa.free(dir_path);

    try tmp.dir.writeFile(io, .{ .sub_path = "settings.yaml", .data = "credentialStore: file\n" });

    wslc_dir_override = dir_path;
    defer wslc_dir_override = null;

    const MockProviders = struct {
        var saw_interactive_on_get: bool = false;
        var acr_exchange_calls: usize = 0;

        fn acquireGh(
            alloc: Allocator,
            gh_host: []const u8,
            requested_username: ?[]const u8,
            allow_interactive: bool,
            _: *Io.Writer,
        ) gh.AuthError!?gh.GitCredential {
            if (!allow_interactive) {
                saw_interactive_on_get = false;
            }
            if (std.mem.eql(u8, gh_host, "github.com")) {
                return .{
                    .username = try alloc.dupe(u8, requested_username orelse "cataggar"),
                    .token = try alloc.dupe(u8, "gho_test_token_abc"),
                };
            }
            return null;
        }

        fn acquireArm(alloc: Allocator, _: *Io.Writer, allow_interactive: bool) ado.Error![]u8 {
            _ = allow_interactive;
            // JWT with tid=11111111-2222-3333-4444-555555555555 and exp=1893456000
            return alloc.dupe(
                u8,
                "eyJhbGciOiJub25lIn0.eyJleHAiOjE4OTM0NTYwMDAsInRpZCI6IjExMTExMTExLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NSJ9.sig",
            );
        }

        fn exchangeAcr(
            alloc: Allocator,
            server: []const u8,
            _: []const u8,
            tenant_id: ?[]const u8,
        ) Error![]u8 {
            acr_exchange_calls += 1;
            if (!std.mem.eql(u8, server, "myacr.azurecr.io")) return error.AuthenticationFailed;
            if (tenant_id == null or !std.mem.eql(u8, tenant_id.?, "11111111-2222-3333-4444-555555555555")) {
                return error.AuthenticationFailed;
            }
            // Return an ACR refresh token JWT with exp=1893456000
            return alloc.dupe(
                u8,
                "eyJhbGciOiJub25lIn0.eyJleHAiOjE4OTM0NTYwMDB9.acr_rt_sig",
            );
        }

        fn genericGet(_: Allocator, _: []const u8, _: []const u8) keyring_zig.Error![]u8 {
            return error.EntryNotFound;
        }

        fn genericSet(_: Allocator, _: []const u8, _: []const u8, _: []const u8) keyring_zig.Error!void {}

        fn nowSeconds() i64 {
            return 1700000000;
        }
    };

    MockProviders.acr_exchange_calls = 0;
    provider_hooks_override = .{
        .acquireGhCredential = MockProviders.acquireGh,
        .acquireArmToken = MockProviders.acquireArm,
        .exchangeAcrToken = MockProviders.exchangeAcr,
        .genericGet = MockProviders.genericGet,
        .genericSet = MockProviders.genericSet,
        .nowSeconds = MockProviders.nowSeconds,
    };
    defer provider_hooks_override = null;

    // 1. `keyring wslc login ghcr.io myacr.azurecr.io`
    {
        var out = Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        var err_out = Io.Writer.Allocating.init(gpa);
        defer err_out.deinit();
        var empty_in = Io.Reader.fixed("");

        const cmd = parseArgs(&.{ "login", "ghcr.io", "myacr.azurecr.io" }).?;
        const code = try run(gpa, cmd, &empty_in, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        try std.testing.expectEqual(@as(usize, 1), MockProviders.acr_exchange_calls);
    }

    // 2. Second `login myacr.azurecr.io` without `--force` reuses the non-expired ACR token.
    {
        var out = Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        var err_out = Io.Writer.Allocating.init(gpa);
        defer err_out.deinit();
        var empty_in = Io.Reader.fixed("");

        const cmd = parseArgs(&.{ "login", "myacr.azurecr.io" }).?;
        const code = try run(gpa, cmd, &empty_in, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        try std.testing.expectEqual(@as(usize, 1), MockProviders.acr_exchange_calls);
    }

    // 3. `keyring wslc credential get` returns the Docker/wslc helper JSON without interactive prompts.
    {
        var out = Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        var err_out = Io.Writer.Allocating.init(gpa);
        defer err_out.deinit();
        var in_reader = Io.Reader.fixed("https://ghcr.io/v2/\n");

        const cmd = parseArgs(&.{ "credential", "get" }).?;
        const code = try run(gpa, cmd, &in_reader, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        try std.testing.expectEqualStrings(
            "{\"ServerURL\":\"ghcr.io\",\"Username\":\"cataggar\",\"Secret\":\"gho_test_token_abc\"}\n",
            out.written(),
        );
    }

    // 4. `keyring wslc logout ghcr.io myacr.azurecr.io` removes both entries.
    {
        var out = Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        var err_out = Io.Writer.Allocating.init(gpa);
        defer err_out.deinit();
        var empty_in = Io.Reader.fixed("");

        const cmd = parseArgs(&.{ "logout", "ghcr.io", "myacr.azurecr.io" }).?;
        const code = try run(gpa, cmd, &empty_in, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        try std.testing.expectError(error.EntryNotFound, getWslcCredential(gpa, .file, "ghcr.io"));
        try std.testing.expectError(error.EntryNotFound, getWslcCredential(gpa, .file, "myacr.azurecr.io"));
    }
}
