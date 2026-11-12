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
const registry_auth = @import("registry_auth.zig");
const wincred = @import("wincred.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const wslc_cred_prefix = "wslc-credential/";
pub const wslc_cred_filter = "wslc-credential/*";
pub const settings_filename = "settings.yaml";
pub const credentials_filename = "registry-credentials.json";
pub const lock_filename = "wslc.lock";
pub const docker_hub_legacy_url = registry_auth.docker_hub_legacy_url;
pub const acr_token_username = registry_auth.acr_token_username;
pub const identity_token_username = registry_auth.identity_token_username;
pub const wincred_max_blob_bytes: usize = 2560;

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

pub const ServerIterator = struct {
    args: []const []const u8,
    index: usize = 0,

    pub fn next(self: *ServerIterator) ?[]const u8 {
        while (self.index < self.args.len) {
            const arg = self.args[self.index];
            if (std.mem.eql(u8, arg, "-f") or
                std.mem.eql(u8, arg, "--force") or
                std.mem.eql(u8, arg, "--password-stdin") or
                std.mem.startsWith(u8, arg, "--username="))
            {
                self.index += 1;
            } else if (std.mem.eql(u8, arg, "-u") or std.mem.eql(u8, arg, "--username")) {
                self.index += 2;
            } else {
                self.index += 1;
                return arg;
            }
        }
        return null;
    }
};

pub const LoginOptions = struct {
    raw_args: []const []const u8 = &.{},
    server_count: usize = 0,
    first_server: ?[]const u8 = null,
    username: ?[]const u8 = null,
    password_stdin: bool = false,
    force: bool = false,

    pub fn serverIterator(self: LoginOptions) ServerIterator {
        return .{ .args = self.raw_args };
    }
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
        force_login: bool,
        stderr: *Io.Writer,
    ) gh.AuthError!?gh.GitCredential,
    acquireArmToken: *const fn (
        gpa: Allocator,
        stderr: *Io.Writer,
        allow_interactive: bool,
        force_refresh: bool,
    ) ado.Error![]u8,
    discoverAcrTenant: ?*const fn (
        gpa: Allocator,
        server: []const u8,
    ) ?[]u8 = null,
    acquireArmTokenForTenant: ?*const fn (
        gpa: Allocator,
        stderr: *Io.Writer,
        allow_interactive: bool,
        force_refresh: bool,
        tenant_id: ?[]const u8,
    ) ado.Error![]u8 = null,
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
    .acquireGhCredential = gh.getOrLoginRegistryCredential,
    .acquireArmToken = ado.acquireArmAccessTokenWithOptions,
    .discoverAcrTenant = liveDiscoverAcrTenant,
    .acquireArmTokenForTenant = ado.acquireArmAccessTokenForTenant,
    .exchangeAcrToken = liveExchangeAcrToken,
    .genericGet = keyring_zig.getAlloc,
    .genericSet = keyring_zig.setAlloc,
    .nowSeconds = liveNowSeconds,
};

var wslc_dir_override: ?[]const u8 = null;
var wslc_lock_path_override: ?[]const u8 = null;
var wincred_ops_override: ?WinCredOps = null;
var dpapi_ops_override: ?DpapiOps = null;
var provider_hooks_override: ?ProviderHooks = null;
var env_override_fn: ?*const fn (name: []const u8) ?[]const u8 = null;
var fs_read_override_fn: ?*const fn (gpa: Allocator, path: []const u8) anyerror![]u8 = null;
var fs_rename_override_fn: ?*const fn (old_path: []const u8, new_path: []const u8) anyerror!void = null;
var fs_retry_sleep_override: ?*const fn (ms: u32) void = null;

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
    if (builtin.os.tag != .windows) return error.ProtectFailed;
    return dpapi.protect(gpa, data);
}

fn liveDpapiUnprotect(gpa: Allocator, data: []const u8) dpapi.Error![]u8 {
    if (builtin.os.tag != .windows) return error.UnprotectFailed;
    return dpapi.unprotect(gpa, data);
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
    var opts: LoginOptions = .{ .raw_args = args };

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
            if (opts.first_server == null) {
                opts.first_server = arg;
            }
            opts.server_count += 1;
            i += 1;
        }
    }

    if (opts.password_stdin) {
        if (opts.server_count != 1 or opts.username == null) return null;
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
    return registry_auth.normalizeServerAlloc(gpa, raw_server, .legacy_v1_url) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidServer,
    };
}

fn extractHostWithoutPort(authority: []const u8) Error![]const u8 {
    return registry_auth.extractHostWithoutPort(authority) catch error.InvalidServer;
}

/// If `normalized_server` is a GitHub Container Registry endpoint (`ghcr.io`,
/// `containers.<tenant>.ghe.com`, or `docker.<github-host>`), return the
/// corresponding GitHub host (`github.com`, `<tenant>.ghe.com`, or GHES host)
/// owned by `gpa`.
pub fn resolveGhcrGitHubHostAlloc(gpa: Allocator, normalized_server: []const u8) Error!?[]u8 {
    return registry_auth.resolveGhcrGitHubHostAlloc(gpa, normalized_server) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidServer,
    };
}

/// Return true if `normalized_server` is an Azure Container Registry host
/// (`<name>.azurecr.io`, `<name>.azurecr.cn`, `<name>.azurecr.de`, `<name>.azurecr.us`).
pub fn isAcrServer(normalized_server: []const u8) bool {
    return registry_auth.isAcrServer(normalized_server);
}

/// Extract the `exp` UNIX timestamp from a JWT string (`header.payload.sig`),
/// or return `null` if the string is not a JWT with a numeric `exp` claim.
pub fn extractJwtExpiration(gpa: Allocator, token: []const u8) ?i64 {
    return registry_auth.extractJwtExpiration(gpa, token);
}

/// Extract the `tid` (Microsoft Entra tenant ID) claim from a JWT string,
/// returning an owned slice when present.
pub fn extractJwtTenantIdAlloc(gpa: Allocator, token: []const u8) ?[]u8 {
    return registry_auth.extractJwtTenantIdAlloc(gpa, token);
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
    const home = getHomeDir(gpa) orelse return null;
    defer gpa.free(home);
    return std.fs.path.join(gpa, &.{ home, ".config", "wslc" }) catch null;
}

fn getHomeDir(gpa: Allocator) ?[]u8 {
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

fn resolveKeyringStateDir(gpa: Allocator) ?[]u8 {
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

fn resolveWslcLockPath(gpa: Allocator, wslc_dir: []const u8) Error![]u8 {
    if (wslc_lock_path_override) |override| {
        return gpa.dupe(u8, override);
    }
    if (wslc_dir_override != null) {
        return std.fs.path.join(gpa, &.{ wslc_dir, lock_filename });
    }
    if (resolveKeyringStateDir(gpa)) |state_dir| {
        defer gpa.free(state_dir);
        return std.fs.path.join(gpa, &.{ state_dir, lock_filename });
    }
    return std.fs.path.join(gpa, &.{ wslc_dir, lock_filename });
}

/// Parse `credentialStore` from `settings.yaml` content, matching `wslc`'s
/// `WSLCUserSettings.cpp` (`wincred` or `default` -> `.wincred`, `file` -> `.file`).
pub fn parseSettingsCredentialStore(content: []const u8) Error!CredentialStoreKind {
    const stripped = if (std.mem.startsWith(u8, content, "\xEF\xBB\xBF"))
        content[3..]
    else
        content;
    var lines = std.mem.splitScalar(u8, stripped, '\n');
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
    const content = (try readFileIfExists(gpa, settings_path)) orelse return .wincred;
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

pub fn setWslcCredential(
    gpa: Allocator,
    store_kind: CredentialStoreKind,
    normalized_server: []const u8,
    username: []const u8,
    secret: []const u8,
    stderr: ?*Io.Writer,
) Error!void {
    return switch (store_kind) {
        .wincred => {
            storeWinCred(gpa, normalized_server, username, secret) catch |err| {
                if (err == error.StorageFailure and secret.len > wincred_max_blob_bytes) {
                    if (stderr) |err_w| {
                        err_w.print(
                            "keyring: wslc: credential for {s} ({d} bytes) exceeds Windows Credential Manager's 2,560-byte blob limit; set 'credentialStore: file' in %LOCALAPPDATA%\\wslc\\settings.yaml\n",
                            .{ normalized_server, secret.len },
                        ) catch {};
                        err_w.flush() catch {};
                    }
                }
                return err;
            };
        },
        .file => storeFileCred(gpa, normalized_server, username, secret),
    };
}

pub fn storeWslcCredential(
    gpa: Allocator,
    store_kind: CredentialStoreKind,
    normalized_server: []const u8,
    username: []const u8,
    secret: []const u8,
) Error!void {
    return setWslcCredential(gpa, store_kind, normalized_server, username, secret, null);
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
        errdefer {
            std.crypto.secureZero(u8, secret);
            gpa.free(secret);
        }

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
        else => if (builtin.os.tag != .windows and dpapi_ops_override == null)
            error.NoStorageAccess
        else
            error.StorageFailure,
    };
    defer {
        std.crypto.secureZero(u8, protected);
        gpa.free(protected);
    }

    const enc_len = std.base64.standard.Encoder.calcSize(protected.len);
    const out = try gpa.alloc(u8, enc_len);
    _ = std.base64.standard.Encoder.encode(out, protected);
    return out;
}

fn decodeFileSecretAlloc(gpa: Allocator, encoded: []const u8) Error![]u8 {
    const trimmed = std.mem.trim(u8, encoded, " \t\r\n");
    const dec_len = std.base64.standard.Decoder.calcSizeForSlice(trimmed) catch return error.StorageFailure;
    const raw_dpapi = try gpa.alloc(u8, dec_len);
    defer {
        std.crypto.secureZero(u8, raw_dpapi);
        gpa.free(raw_dpapi);
    }
    std.base64.standard.Decoder.decode(raw_dpapi, trimmed) catch return error.StorageFailure;

    return activeDpapiOps().unprotect(gpa, raw_dpapi) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => if (builtin.os.tag != .windows and dpapi_ops_override == null)
            error.NoStorageAccess
        else
            error.StorageFailure,
    };
}

const FileLock = struct {
    file: Io.File,

    fn release(self: *FileLock) void {
        const io = Io.Threaded.global_single_threaded.io();
        self.file.unlock(io);
        self.file.close(io);
    }
};

fn acquireWslcLock(gpa: Allocator, wslc_dir: []const u8) Error!FileLock {
    const io = Io.Threaded.global_single_threaded.io();
    const lock_path = try resolveWslcLockPath(gpa, wslc_dir);
    defer gpa.free(lock_path);

    if (std.fs.path.dirname(lock_path)) |lock_parent| {
        if (lock_parent.len > 0) {
            _ = Io.Dir.cwd().createDirPathStatus(io, lock_parent, dirPermissions()) catch return error.StorageFailure;
        }
    }

    const file = openLockFileWithRetry(io, lock_path) catch return error.StorageFailure;
    file.lock(io, .exclusive) catch {
        file.close(io);
        return error.StorageFailure;
    };
    return .{ .file = file };
}

fn zeroFileCredDocSecrets(doc: *const FileCredentialDocument) void {
    for (doc.Credentials.map.values()) |entry| {
        std.crypto.secureZero(u8, @constCast(entry.Secret));
    }
}

fn storeFileCred(gpa: Allocator, normalized_server: []const u8, username: []const u8, secret: []const u8) Error!void {
    const wslc_dir = resolveWslcDir(gpa) orelse return error.NoStorageAccess;
    defer gpa.free(wslc_dir);

    var lock = try acquireWslcLock(gpa, wslc_dir);
    defer lock.release();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const creds_path = try std.fs.path.join(a, &.{ wslc_dir, credentials_filename });
    var doc: FileCredentialDocument = .{};
    defer zeroFileCredDocSecrets(&doc);
    if (try readFileIfExists(a, creds_path)) |bytes| {
        defer std.crypto.secureZero(u8, bytes);
        if (bytes.len > 0) {
            doc = std.json.parseFromSliceLeaky(FileCredentialDocument, a, bytes, .{
                .ignore_unknown_fields = true,
                .allocate = .alloc_always,
            }) catch return error.StorageFailure;
        }
    }

    const encoded_secret = try encodeFileSecretAlloc(a, secret);
    if (doc.Credentials.map.get(normalized_server)) |prev_entry| {
        std.crypto.secureZero(u8, @constCast(prev_entry.Secret));
    }
    try doc.Credentials.map.put(a, normalized_server, .{
        .UserName = username,
        .Secret = encoded_secret,
    });

    const serialized = std.json.Stringify.valueAlloc(a, doc, .{
        .whitespace = .indent_2,
    }) catch return error.OutOfMemory;
    defer std.crypto.secureZero(u8, serialized);
    try writeFileAtomic(a, creds_path, serialized);
}

fn getFileCred(gpa: Allocator, normalized_server: []const u8) Error!StoredCredential {
    const wslc_dir = resolveWslcDir(gpa) orelse return error.NoStorageAccess;
    defer gpa.free(wslc_dir);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const creds_path = try std.fs.path.join(a, &.{ wslc_dir, credentials_filename });
    const bytes = (try readFileIfExists(a, creds_path)) orelse return error.EntryNotFound;
    defer std.crypto.secureZero(u8, bytes);
    if (bytes.len == 0) return error.EntryNotFound;

    const doc = std.json.parseFromSliceLeaky(FileCredentialDocument, a, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.StorageFailure;
    defer zeroFileCredDocSecrets(&doc);

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

    var lock = try acquireWslcLock(gpa, wslc_dir);
    defer lock.release();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const creds_path = try std.fs.path.join(a, &.{ wslc_dir, credentials_filename });
    const bytes = (try readFileIfExists(a, creds_path)) orelse return error.EntryNotFound;
    defer std.crypto.secureZero(u8, bytes);
    if (bytes.len == 0) return error.EntryNotFound;

    var doc = std.json.parseFromSliceLeaky(FileCredentialDocument, a, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.StorageFailure;
    defer zeroFileCredDocSecrets(&doc);

    if (doc.Credentials.map.get(normalized_server)) |old_entry| {
        std.crypto.secureZero(u8, @constCast(old_entry.Secret));
    }
    if (!doc.Credentials.map.orderedRemove(normalized_server)) {
        return error.EntryNotFound;
    }

    const serialized = std.json.Stringify.valueAlloc(a, doc, .{
        .whitespace = .indent_2,
    }) catch return error.OutOfMemory;
    defer std.crypto.secureZero(u8, serialized);
    try writeFileAtomic(a, creds_path, serialized);
}

fn listFileCred(gpa: Allocator) Error![]StoredCredential {
    const wslc_dir = resolveWslcDir(gpa) orelse return error.NoStorageAccess;
    defer gpa.free(wslc_dir);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const creds_path = try std.fs.path.join(a, &.{ wslc_dir, credentials_filename });
    const bytes = (try readFileIfExists(a, creds_path)) orelse return gpa.alloc(StoredCredential, 0);
    defer std.crypto.secureZero(u8, bytes);
    if (bytes.len == 0) return gpa.alloc(StoredCredential, 0);

    const doc = std.json.parseFromSliceLeaky(FileCredentialDocument, a, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.StorageFailure;
    defer zeroFileCredDocSecrets(&doc);

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
        errdefer gpa.free(username);

        try out.append(gpa, .{
            .server = server,
            .username = username,
            .secret = secret,
        });
    }
    return out.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// Provider Resolution (GHCR, ACR OAuth2 exchange, and Generic keyring)
// ---------------------------------------------------------------------------

pub const AcrExchangeRequest = registry_auth.AcrExchangeRequest;

pub fn parseWwwAuthenticateTenantIdAlloc(gpa: Allocator, header_value: []const u8) ?[]u8 {
    return registry_auth.parseWwwAuthenticateTenantIdAlloc(gpa, header_value);
}

fn liveDiscoverAcrTenant(gpa: Allocator, server: []const u8) ?[]u8 {
    return registry_auth.liveDiscoverAcrTenant(gpa, server);
}

pub fn buildAcrExchangeRequest(
    gpa: Allocator,
    server: []const u8,
    arm_access_token: []const u8,
    tenant_id: ?[]const u8,
) Error!AcrExchangeRequest {
    return registry_auth.buildAcrExchangeRequest(gpa, server, arm_access_token, tenant_id) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidServer,
    };
}

fn liveExchangeAcrToken(
    gpa: Allocator,
    server: []const u8,
    arm_access_token: []const u8,
    tenant_id: ?[]const u8,
) Error![]u8 {
    return registry_auth.liveExchangeAcrToken(gpa, server, arm_access_token, tenant_id) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.NetworkFailure => error.NetworkFailure,
        error.InvalidServer => error.InvalidServer,
        else => error.AuthenticationFailed,
    };
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
    return resolveRegistryCredentialLazy(
        gpa,
        store_kind,
        normalized_server,
        requested_username,
        force,
        allow_interactive,
        stderr,
    );
}

fn resolveCredentialStoreLazy(gpa: Allocator, cached_kind: *?CredentialStoreKind) Error!CredentialStoreKind {
    if (cached_kind.*) |kind| return kind;
    const kind = try detectCredentialStore(gpa);
    cached_kind.* = kind;
    return kind;
}

fn mapArmTokenError(err: ado.Error) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.NoStorageAccess => error.EntryNotFound,
        error.NetworkFailure => error.NetworkFailure,
        else => error.AuthenticationFailed,
    };
}

fn isAcrSentinelUsername(username: []const u8) bool {
    return std.mem.eql(u8, username, acr_token_username) or
        std.mem.eql(u8, username, identity_token_username);
}

fn isRealGenericUsername(username: []const u8) bool {
    return username.len > 0 and !isAcrSentinelUsername(username);
}

fn acquireArmTokenWithHooks(
    hooks: ProviderHooks,
    gpa: Allocator,
    stderr: *Io.Writer,
    allow_interactive: bool,
    force_refresh: bool,
    tenant_id: ?[]const u8,
) ado.Error![]u8 {
    if (hooks.acquireArmTokenForTenant) |for_tenant_fn| {
        return for_tenant_fn(gpa, stderr, allow_interactive, force_refresh, tenant_id);
    }
    return hooks.acquireArmToken(gpa, stderr, allow_interactive, force_refresh);
}

fn lookupFallbackCredential(
    gpa: Allocator,
    cached_kind: *?CredentialStoreKind,
    normalized_server: []const u8,
    requested_username: ?[]const u8,
    force: bool,
) Error!?StoredCredential {
    const hooks = activeProviderHooks();

    if (requested_username) |user| {
        const service = try genericServiceNameAlloc(gpa, normalized_server);
        defer gpa.free(service);
        if (hooks.genericGet(gpa, service, user)) |secret| {
            errdefer {
                std.crypto.secureZero(u8, secret);
                gpa.free(secret);
            }
            const server_copy = try gpa.dupe(u8, normalized_server);
            errdefer gpa.free(server_copy);
            const user_copy = try gpa.dupe(u8, user);
            errdefer gpa.free(user_copy);
            return .{
                .server = server_copy,
                .username = user_copy,
                .secret = secret,
            };
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Locked => return error.Locked,
            else => {},
        }
    }

    const store_kind = try resolveCredentialStoreLazy(gpa, cached_kind);
    if (getWslcCredential(gpa, store_kind, normalized_server)) |existing| {
        var existing_owned = true;
        defer if (existing_owned) existing.deinit(gpa);

        if (requested_username == null or std.mem.eql(u8, existing.username, requested_username.?)) {
            const now = hooks.nowSeconds();
            const is_expired_jwt = if (extractJwtExpiration(gpa, existing.secret)) |exp|
                exp <= now
            else
                false;

            if (requested_username == null and isRealGenericUsername(existing.username) and (force or is_expired_jwt)) {
                const service = try genericServiceNameAlloc(gpa, normalized_server);
                defer gpa.free(service);

                if (hooks.genericGet(gpa, service, existing.username)) |fresh_secret| {
                    const fresh_expired = if (extractJwtExpiration(gpa, fresh_secret)) |fresh_exp|
                        fresh_exp <= now
                    else
                        false;
                    if (!fresh_expired) {
                        errdefer {
                            std.crypto.secureZero(u8, fresh_secret);
                            gpa.free(fresh_secret);
                        }
                        const server_copy = try gpa.dupe(u8, normalized_server);
                        errdefer gpa.free(server_copy);
                        const user_copy = try gpa.dupe(u8, existing.username);
                        return .{
                            .server = server_copy,
                            .username = user_copy,
                            .secret = fresh_secret,
                        };
                    }
                    std.crypto.secureZero(u8, fresh_secret);
                    gpa.free(fresh_secret);
                } else |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.Locked => return error.Locked,
                    else => {},
                }
            }

            if (is_expired_jwt) {
                return null;
            }
            existing_owned = false;
            return existing;
        }
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Locked => return error.Locked,
        else => {},
    }

    return null;
}

fn resolveRegistryCredentialLazy(
    gpa: Allocator,
    maybe_store_kind: ?CredentialStoreKind,
    normalized_server: []const u8,
    requested_username: ?[]const u8,
    force: bool,
    allow_interactive: bool,
    stderr: *Io.Writer,
) Error!StoredCredential {
    const hooks = activeProviderHooks();
    var cached_kind = maybe_store_kind;
    const can_interact = allow_interactive and !isNonInteractive(gpa);

    // 1. GitHub Container Registry (`ghcr.io`, `containers.<tenant>.ghe.com`, `docker.<ghe-host>`).
    if (try resolveGhcrGitHubHostAlloc(gpa, normalized_server)) |gh_host| {
        defer gpa.free(gh_host);

        if (!force) {
            // If wslc/generic storage already holds a manually stored credential
            // (e.g. from `credential store` or `wslc login -u <user> --password-stdin`)
            // and `gh` has no matching stored login, return the stored credential
            // instead of launching an interactive OAuth prompt on no-arg `wslc login`.
            if (can_interact) {
                if (try lookupFallbackCredential(gpa, &cached_kind, normalized_server, requested_username, false)) |existing| {
                    var existing_owned = true;
                    defer if (existing_owned) existing.deinit(gpa);

                    const probe = hooks.acquireGhCredential(
                        gpa,
                        gh_host,
                        requested_username,
                        false,
                        false,
                        stderr,
                    ) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.Locked => return error.Locked,
                        else => null,
                    };
                    if (probe) |gh_cred| {
                        gh_cred.deinit(gpa);
                    } else {
                        existing_owned = false;
                        return existing;
                    }
                }
            }

            const maybe_cred = hooks.acquireGhCredential(
                gpa,
                gh_host,
                requested_username,
                allow_interactive,
                false,
                stderr,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Locked => return error.Locked,
                error.NoStorageAccess => return error.NoStorageAccess,
                error.NetworkFailure => return error.NetworkFailure,
                else => {
                    if (try lookupFallbackCredential(gpa, &cached_kind, normalized_server, requested_username, false)) |fallback| {
                        return fallback;
                    }
                    return error.AuthenticationFailed;
                },
            };

            if (maybe_cred) |cred| {
                defer cred.deinit(gpa);
                const effective_user = requested_username orelse cred.username;
                const server_copy = try gpa.dupe(u8, normalized_server);
                errdefer gpa.free(server_copy);
                const user_copy = try gpa.dupe(u8, effective_user);
                errdefer gpa.free(user_copy);
                const secret_copy = try gpa.dupe(u8, cred.token);
                return .{
                    .server = server_copy,
                    .username = user_copy,
                    .secret = secret_copy,
                };
            }

            if (try lookupFallbackCredential(gpa, &cached_kind, normalized_server, requested_username, false)) |fallback| {
                return fallback;
            }
            return error.EntryNotFound;
        }

        const maybe_cred = hooks.acquireGhCredential(
            gpa,
            gh_host,
            requested_username,
            allow_interactive,
            true,
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

        const effective_user = requested_username orelse cred.username;
        const server_copy = try gpa.dupe(u8, normalized_server);
        errdefer gpa.free(server_copy);
        const user_copy = try gpa.dupe(u8, effective_user);
        errdefer gpa.free(user_copy);
        const secret_copy = try gpa.dupe(u8, cred.token);
        return .{
            .server = server_copy,
            .username = user_copy,
            .secret = secret_copy,
        };
    }

    // 2. Azure Container Registry (`*.azurecr.io`, `*.azurecr.cn`, `*.azurecr.de`, `*.azurecr.us`).
    if (isAcrServer(normalized_server)) {
        if (requested_username) |user| {
            if (!isAcrSentinelUsername(user)) {
                if (user.len > 0) {
                    const service = try genericServiceNameAlloc(gpa, normalized_server);
                    defer gpa.free(service);
                    if (hooks.genericGet(gpa, service, user)) |secret| {
                        errdefer {
                            std.crypto.secureZero(u8, secret);
                            gpa.free(secret);
                        }
                        const server_copy = try gpa.dupe(u8, normalized_server);
                        errdefer gpa.free(server_copy);
                        const user_copy = try gpa.dupe(u8, user);
                        return .{
                            .server = server_copy,
                            .username = user_copy,
                            .secret = secret,
                        };
                    } else |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.Locked => return error.Locked,
                        else => {},
                    }
                }

                if (!force) {
                    const store_kind = try resolveCredentialStoreLazy(gpa, &cached_kind);
                    if (getWslcCredential(gpa, store_kind, normalized_server)) |existing| {
                        if (std.mem.eql(u8, existing.username, user)) {
                            if (extractJwtExpiration(gpa, existing.secret)) |exp| {
                                if (@as(i128, exp) > @as(i128, hooks.nowSeconds()) + 300) {
                                    return existing;
                                }
                            } else {
                                return existing;
                            }
                        }
                        existing.deinit(gpa);
                    } else |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.Locked => return error.Locked,
                        else => {},
                    }
                }

                return error.EntryNotFound;
            }
        }

        if (!force) {
            const store_kind = try resolveCredentialStoreLazy(gpa, &cached_kind);
            if (getWslcCredential(gpa, store_kind, normalized_server)) |existing| {
                if (requested_username == null or std.mem.eql(u8, existing.username, requested_username.?)) {
                    if (extractJwtExpiration(gpa, existing.secret)) |exp| {
                        if (@as(i128, exp) > @as(i128, hooks.nowSeconds()) + 300) {
                            return existing;
                        }
                    } else {
                        return existing;
                    }
                }
                existing.deinit(gpa);
            } else |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Locked => return error.Locked,
                else => {},
            }
        }

        const discovered_tid = if (hooks.discoverAcrTenant) |discover_fn|
            discover_fn(gpa, normalized_server)
        else
            null;
        defer if (discovered_tid) |tid| gpa.free(tid);

        const arm_token = acquireArmTokenWithHooks(
            hooks,
            gpa,
            stderr,
            can_interact,
            force,
            discovered_tid,
        ) catch |err| return mapArmTokenError(err);
        defer {
            std.crypto.secureZero(u8, arm_token);
            gpa.free(arm_token);
        }

        const maybe_tid = if (discovered_tid) |tid|
            try gpa.dupe(u8, tid)
        else
            extractJwtTenantIdAlloc(gpa, arm_token);
        defer if (maybe_tid) |tid| gpa.free(tid);

        const acr_token = hooks.exchangeAcrToken(gpa, normalized_server, arm_token, maybe_tid) catch |err| retry: {
            if (err != error.AuthenticationFailed or force) return err;

            const refreshed_arm = acquireArmTokenWithHooks(
                hooks,
                gpa,
                stderr,
                can_interact,
                true,
                discovered_tid,
            ) catch |arm_err| return mapArmTokenError(arm_err);
            defer {
                std.crypto.secureZero(u8, refreshed_arm);
                gpa.free(refreshed_arm);
            }

            const refreshed_tid = if (discovered_tid) |tid|
                try gpa.dupe(u8, tid)
            else
                extractJwtTenantIdAlloc(gpa, refreshed_arm);
            defer if (refreshed_tid) |tid| gpa.free(tid);

            break :retry try hooks.exchangeAcrToken(gpa, normalized_server, refreshed_arm, refreshed_tid);
        };
        errdefer {
            std.crypto.secureZero(u8, acr_token);
            gpa.free(acr_token);
        }

        const user = if (requested_username != null and std.mem.eql(u8, requested_username.?, identity_token_username))
            identity_token_username
        else
            acr_token_username;
        const server_copy = try gpa.dupe(u8, normalized_server);
        errdefer gpa.free(server_copy);
        const user_copy = try gpa.dupe(u8, user);
        return .{
            .server = server_copy,
            .username = user_copy,
            .secret = acr_token,
        };
    }

    // 3. Generic registry: check generic keyring first when username is provided, then wslc storage.
    if (try lookupFallbackCredential(gpa, &cached_kind, normalized_server, requested_username, force)) |cred| {
        return cred;
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
        const raw_srv = opts.first_server.?;
        const normalized = normalizeServerAlloc(a, raw_srv) catch {
            try stderr.print("keyring: wslc login: invalid registry server '{s}'\n", .{raw_srv});
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

        setWslcCredential(a, store_kind, normalized, user, secret, stderr) catch |err| {
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
    var srv_it = opts.serverIterator();
    while (srv_it.next()) |srv| {
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
        if (listWslcCredentials(a, store_kind)) |entries| {
            defer for (entries) |item| std.crypto.secureZero(u8, item.secret);
            for (entries) |item| {
                if (!containsString(target_servers.items, item.server)) {
                    try target_servers.append(a, item.server);
                }
            }
        } else |_| {}

        if (!containsString(target_servers.items, "ghcr.io")) {
            const has_gh = if (provider_hooks_override == null) blk: {
                if (gh.lookupStoredCredential(a, "github.com", opts.username) catch null) |cred| {
                    cred.deinit(a);
                    break :blk true;
                }
                break :blk false;
            } else blk: {
                var sink = Io.Writer.Allocating.init(a);
                defer sink.deinit();
                if (activeProviderHooks().acquireGhCredential(a, "github.com", opts.username, false, false, &sink.writer)) |maybe_gh| {
                    if (maybe_gh) |cred| {
                        cred.deinit(a);
                        break :blk true;
                    }
                } else |_| {}
                break :blk false;
            };
            if (has_gh) {
                try target_servers.append(a, "ghcr.io");
            }
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

        setWslcCredential(a, store_kind, normalized, cred.username, cred.secret, stderr) catch |err| {
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
    defer for (entries) |item| std.crypto.secureZero(u8, item.secret);

    if (entries.len == 0) {
        try stdout.writeAll("wslc registries: none configured\n");
        return;
    }

    const now = activeProviderHooks().nowSeconds();
    try stdout.print("wslc registries ({d}):\n", .{entries.len});
    for (entries) |entry| {
        if (extractJwtExpiration(a, entry.secret)) |exp| {
            if (exp > now) {
                const remaining_mins: i128 = @divFloor(@as(i128, exp) - @as(i128, now), 60);
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

const HelperOutput = struct {
    ServerURL: []const u8,
    Username: []const u8,
    Secret: []const u8,
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
            // Helper `get` is strictly noninteractive and only inspects wslc
            // settings.yaml lazily when reading wslc storage.
            const cred = resolveRegistryCredentialLazy(
                a,
                null,
                normalized,
                null,
                false,
                false,
                stderr,
            ) catch |err| {
                const msg = switch (err) {
                    error.InvalidSettings => "invalid wslc settings.yaml\n",
                    error.EntryNotFound => "credentials not found in native keychain\n",
                    error.Locked => "credential store is locked\n",
                    else => "failed to retrieve credentials\n",
                };
                try stdout.writeAll(msg);
                try stdout.flush();
                return 1;
            };
            defer cred.deinit(a);

            const json_out = std.json.Stringify.valueAlloc(gpa, HelperOutput{
                .ServerURL = cred.server,
                .Username = cred.username,
                .Secret = cred.secret,
            }, .{}) catch return error.OutOfMemory;
            defer {
                std.crypto.secureZero(u8, json_out);
                gpa.free(json_out);
            }

            try stdout.writeAll(json_out);
            try stdout.writeByte('\n');
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
            defer {
                if (parsed.value.Secret) |sec_buf| {
                    std.crypto.secureZero(u8, @constCast(sec_buf));
                }
                parsed.deinit();
            }

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
            const store_kind = detectCredentialStore(a) catch {
                try stderr.writeAll("keyring: wslc credential store: invalid wslc settings.yaml\n");
                try stderr.flush();
                return 1;
            };
            setWslcCredential(a, store_kind, normalized, user, sec, stderr) catch return 1;
            return 0;
        },
        .erase => {
            const raw_server = readBoundedStdinLine(a, stdin, 4096) catch return 1;
            const normalized = normalizeServerAlloc(a, raw_server) catch return 1;
            const store_kind = detectCredentialStore(a) catch {
                try stderr.writeAll("keyring: wslc credential erase: invalid wslc settings.yaml\n");
                try stderr.flush();
                return 1;
            };
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
    return registry_auth.readBoundedStdinLine(gpa, stdin, max_bytes) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidInput,
    };
}

fn readBoundedStdinAll(gpa: Allocator, stdin: *Io.Reader, max_bytes: usize) Error![]u8 {
    return registry_auth.readBoundedStdinAll(gpa, stdin, max_bytes) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidInput,
    };
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

const fs_max_attempts: usize = 5;

fn isTransientFsError(err: anyerror) bool {
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

fn sleepRetryMs(ms: u32) void {
    if (fs_retry_sleep_override) |override_fn| {
        override_fn(ms);
        return;
    }
    const io = Io.Threaded.global_single_threaded.io();
    Io.Clock.Duration.sleep(.{ .clock = .awake, .raw = .fromMilliseconds(ms) }, io) catch {};
}

fn openLockFileWithRetry(io: Io, lock_path: []const u8) Error!Io.File {
    var delay_ms: u32 = 10;
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        if (Io.Dir.cwd().createFile(io, lock_path, .{
            .truncate = false,
            .read = true,
            .permissions = filePermissions(),
        })) |file| {
            return file;
        } else |err| {
            if (attempt + 1 < fs_max_attempts and isTransientFsError(err)) {
                sleepRetryMs(delay_ms);
                delay_ms *= 2;
                continue;
            }
            return error.StorageFailure;
        }
    }
}

fn readFileRawOnce(io: Io, gpa: Allocator, path: []const u8) anyerror![]u8 {
    if (fs_read_override_fn) |override_fn| {
        return override_fn(gpa, path);
    }
    return Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(4 * 1024 * 1024));
}

/// Read `path` if it exists, treating ONLY `error.FileNotFound` as `null`.
/// Retries briefly on transient Windows sharing/locking errors (`AccessDenied`,
/// `LockViolation`, `FileBusy`, etc.) matching `wslc`'s `RetryOpenFileOnSharingViolation`,
/// and propagates all other errors so existing `registry-credentials.json`
/// entries can never be overwritten on a read failure.
fn readFileIfExists(gpa: Allocator, path: []const u8) Error!?[]u8 {
    const io = Io.Threaded.global_single_threaded.io();
    var delay_ms: u32 = 10;
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        if (readFileRawOnce(io, gpa, path)) |bytes| {
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

fn renameAbsoluteOnce(io: Io, old_path: []const u8, new_path: []const u8) anyerror!void {
    if (fs_rename_override_fn) |override_fn| {
        return override_fn(old_path, new_path);
    }
    return Io.Dir.cwd().rename(old_path, Io.Dir.cwd(), new_path, io);
}

fn renameAbsoluteWithRetry(io: Io, old_path: []const u8, new_path: []const u8) Error!void {
    var delay_ms: u32 = 10;
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        if (renameAbsoluteOnce(io, old_path, new_path)) |_| {
            return;
        } else |err| {
            if (attempt + 1 < fs_max_attempts and isTransientFsError(err)) {
                sleepRetryMs(delay_ms);
                delay_ms *= 2;
                continue;
            }
            return error.StorageFailure;
        }
    }
}

fn writeFileAtomic(gpa: Allocator, path: []const u8, contents: []const u8) Error!void {
    if (fs_rename_override_fn == null and fs_retry_sleep_override == null) {
        return registry_auth.writeProtectedFileAtomic(gpa, path, contents) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.StorageFailure,
        };
    }

    const io = Io.Threaded.global_single_threaded.io();
    if (std.fs.path.dirname(path)) |parent| {
        if (parent.len > 0) {
            _ = Io.Dir.cwd().createDirPathStatus(io, parent, dirPermissions()) catch return error.StorageFailure;
        }
    }

    var tmp_owned: ?[]u8 = null;
    defer if (tmp_owned) |t| gpa.free(t);

    if (builtin.os.tag != .windows) {
        var file: Io.File = undefined;
        var open_attempt: usize = 0;
        while (true) : (open_attempt += 1) {
            var suffix_bytes: [16]u8 = undefined;
            io.randomSecure(&suffix_bytes) catch io.random(&suffix_bytes);
            const suffix_hex = std.fmt.bytesToHex(suffix_bytes, .lower);
            const candidate = try std.fmt.allocPrint(gpa, "{s}.{s}.tmp", .{ path, suffix_hex });
            if (Io.Dir.cwd().createFile(io, candidate, .{
                .truncate = true,
                .exclusive = true,
                .permissions = filePermissions(),
            })) |f| {
                tmp_owned = candidate;
                file = f;
                break;
            } else |err| {
                gpa.free(candidate);
                if (err == error.PathAlreadyExists and open_attempt + 1 < fs_max_attempts) {
                    continue;
                }
                return error.StorageFailure;
            }
        }
        const tmp = tmp_owned.?;
        {
            defer file.close(io);
            if (builtin.os.tag != .wasi) {
                file.setPermissions(io, filePermissions()) catch {
                    Io.Dir.cwd().deleteFile(io, tmp) catch {};
                    return error.StorageFailure;
                };
            }
            file.writeStreamingAll(io, contents) catch {
                Io.Dir.cwd().deleteFile(io, tmp) catch {};
                return error.StorageFailure;
            };
        }
        renameAbsoluteWithRetry(io, tmp, path) catch {
            Io.Dir.cwd().deleteFile(io, tmp) catch {};
            return error.StorageFailure;
        };
        return;
    }

    var open_attempt: usize = 0;
    while (true) : (open_attempt += 1) {
        var suffix_bytes: [16]u8 = undefined;
        io.randomSecure(&suffix_bytes) catch io.random(&suffix_bytes);
        const suffix_hex = std.fmt.bytesToHex(suffix_bytes, .lower);
        const candidate = try std.fmt.allocPrint(gpa, "{s}.{s}.tmp", .{ path, suffix_hex });
        if (Io.Dir.cwd().createFile(io, candidate, .{
            .truncate = true,
            .exclusive = true,
            .permissions = filePermissions(),
        })) |empty_file| {
            empty_file.close(io);
            tmp_owned = candidate;
            break;
        } else |err| {
            gpa.free(candidate);
            if (err == error.PathAlreadyExists and open_attempt + 1 < fs_max_attempts) {
                continue;
            }
            return error.StorageFailure;
        }
    }
    const tmp = tmp_owned.?;
    registry_auth.restrictFileToCurrentUserWindows(gpa, tmp) catch {
        Io.Dir.cwd().deleteFile(io, tmp) catch {};
        return error.StorageFailure;
    };
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
    renameAbsoluteWithRetry(io, tmp, path) catch {
        Io.Dir.cwd().deleteFile(io, tmp) catch {};
        return error.StorageFailure;
    };
    registry_auth.restrictFileToCurrentUserWindows(gpa, path) catch {};
}

fn dirPermissions() Io.File.Permissions {
    return if (builtin.os.tag == .windows or builtin.os.tag == .wasi) .default_dir else .fromMode(0o700);
}

fn filePermissions() Io.File.Permissions {
    return if (builtin.os.tag == .windows or builtin.os.tag == .wasi) .default_file else .fromMode(0o600);
}

fn isNonInteractive(gpa: Allocator) bool {
    if (env_override_fn == null) return ado.isNonInteractive();
    if (getEnvVarOwned(gpa, "ADO_KEYRING_NONINTERACTIVE")) |value| {
        defer gpa.free(value);
        if (std.ascii.eqlIgnoreCase(value, "true") or std.mem.eql(u8, value, "1")) return true;
    }
    if (getEnvVarOwned(gpa, "KEYRING_NONINTERACTIVE")) |value| {
        defer gpa.free(value);
        if (std.ascii.eqlIgnoreCase(value, "true") or std.mem.eql(u8, value, "1")) return true;
    }
    if (getEnvVarOwned(gpa, "GIT_TERMINAL_PROMPT")) |value| {
        defer gpa.free(value);
        if (std.ascii.eqlIgnoreCase(value, "false") or std.mem.eql(u8, value, "0")) return true;
    }
    if (getEnvVarOwned(gpa, "GCM_INTERACTIVE")) |value| {
        defer gpa.free(value);
        if (std.ascii.eqlIgnoreCase(value, "never") or
            std.ascii.eqlIgnoreCase(value, "false") or
            std.ascii.eqlIgnoreCase(value, "0"))
        {
            return true;
        }
    }
    return false;
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
// Unit tests
// ---------------------------------------------------------------------------

const FakeDpapi = struct {
    const prefix = "dpapi-v1:";

    fn protect(gpa: Allocator, data: []const u8) dpapi.Error![]u8 {
        const out = gpa.alloc(u8, prefix.len + data.len) catch return error.OutOfMemory;
        @memcpy(out[0..prefix.len], prefix);
        @memcpy(out[prefix.len..], data);
        return out;
    }

    fn unprotect(gpa: Allocator, data: []const u8) dpapi.Error![]u8 {
        if (!std.mem.startsWith(u8, data, prefix)) return error.UnprotectFailed;
        return gpa.dupe(u8, data[prefix.len..]) catch error.OutOfMemory;
    }

    const ops: DpapiOps = .{
        .protect = protect,
        .unprotect = unprotect,
    };
};

const FakeWinCred = struct {
    var targets: [8][128]u8 = undefined;
    var target_lens: [8]usize = @splat(0);
    var users: [8][128]u8 = undefined;
    var user_lens: [8]usize = @splat(0);
    var secrets: [8][wincred_max_blob_bytes]u8 = undefined;
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
        if (target.len > 128 or user.len > 128 or value.len > wincred_max_blob_bytes) {
            return error.StorageFailure;
        }
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
    try std.testing.expectError(error.InvalidServer, normalizeServerAlloc(gpa, "localhost:0"));
    try std.testing.expectError(error.InvalidServer, normalizeServerAlloc(gpa, "[::1]:0"));
    try std.testing.expectError(error.InvalidServer, normalizeServerAlloc(gpa, "https://[2001:db8::1]:0/repo"));
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
    try std.testing.expectEqual(CredentialStoreKind.file, try parseSettingsCredentialStore("\xEF\xBB\xBFcredentialStore: file\r\n"));
    try std.testing.expectEqual(CredentialStoreKind.file, try parseSettingsCredentialStore("\xEF\xBB\xBF# BOM comment\ncredentialStore: file\n"));
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

    dpapi_ops_override = FakeDpapi.ops;
    defer dpapi_ops_override = null;

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

    dpapi_ops_override = FakeDpapi.ops;
    defer dpapi_ops_override = null;

    const MockProviders = struct {
        var saw_interactive_on_get: bool = false;
        var saw_force_on_gh: bool = false;
        var acr_exchange_calls: usize = 0;

        fn acquireGh(
            alloc: Allocator,
            gh_host: []const u8,
            requested_username: ?[]const u8,
            allow_interactive: bool,
            force_login: bool,
            _: *Io.Writer,
        ) gh.AuthError!?gh.GitCredential {
            if (!allow_interactive) {
                saw_interactive_on_get = false;
            }
            saw_force_on_gh = force_login;
            if (std.mem.eql(u8, gh_host, "github.com")) {
                return .{
                    .username = try alloc.dupe(u8, requested_username orelse "cataggar"),
                    .token = try alloc.dupe(u8, if (force_login) "gho_forced_pkg_token" else "gho_test_token_abc"),
                };
            }
            return null;
        }

        fn acquireArm(
            alloc: Allocator,
            _: *Io.Writer,
            allow_interactive: bool,
            force_refresh: bool,
        ) ado.Error![]u8 {
            _ = allow_interactive;
            _ = force_refresh;
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

    // 5. `keyring wslc login ghcr.io -f` forwards `force_login = true` to GHCR provider.
    {
        MockProviders.saw_force_on_gh = false;
        var out = Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        var err_out = Io.Writer.Allocating.init(gpa);
        defer err_out.deinit();
        var empty_in = Io.Reader.fixed("");

        const cmd = parseArgs(&.{ "login", "ghcr.io", "-f" }).?;
        const code = try run(gpa, cmd, &empty_in, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        try std.testing.expect(MockProviders.saw_force_on_gh);

        const stored = try getWslcCredential(gpa, .file, "ghcr.io");
        defer stored.deinit(gpa);
        try std.testing.expectEqualStrings("gho_forced_pkg_token", stored.secret);
    }
}

test "liveDpapiProtect fails closed on non-Windows and round-trips via DPAPI on Windows" {
    const gpa = std.testing.allocator;
    dpapi_ops_override = null;

    if (builtin.os.tag != .windows) {
        try std.testing.expectError(error.ProtectFailed, liveDpapiProtect(gpa, "secret-token"));
        try std.testing.expectError(error.UnprotectFailed, liveDpapiUnprotect(gpa, "secret-token"));

        const io = Io.Threaded.global_single_threaded.io();
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const path_len = try tmp.dir.realPath(io, &path_buf);
        const dir_path = try gpa.dupe(u8, path_buf[0..path_len]);
        defer gpa.free(dir_path);

        wslc_dir_override = dir_path;
        defer wslc_dir_override = null;

        try std.testing.expectError(
            error.NoStorageAccess,
            storeWslcCredential(gpa, .file, "ghcr.io", "cataggar", "gho_secret"),
        );
    } else {
        const encrypted = try liveDpapiProtect(gpa, "secret-token");
        defer gpa.free(encrypted);
        try std.testing.expect(!std.mem.eql(u8, "secret-token", encrypted));

        const decrypted = try liveDpapiUnprotect(gpa, encrypted);
        defer gpa.free(decrypted);
        try std.testing.expectEqualStrings("secret-token", decrypted);
    }
}

test "FileCredStorage fails closed on lock/read errors and retries transient sharing violations" {
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
    dpapi_ops_override = FakeDpapi.ops;
    defer dpapi_ops_override = null;
    fs_retry_sleep_override = struct {
        fn noSleep(_: u32) void {}
    }.noSleep;
    defer fs_retry_sleep_override = null;

    // Seed an existing credential in registry-credentials.json.
    try storeWslcCredential(gpa, .file, "ghcr.io", "cataggar", "gho_preserve_me");

    // 1. Lock failure MUST fail closed without touching registry-credentials.json.
    const bad_lock_dir = try std.fs.path.join(gpa, &.{ dir_path, "lock-is-a-dir" });
    defer gpa.free(bad_lock_dir);
    _ = try Io.Dir.cwd().createDirPathStatus(io, bad_lock_dir, dirPermissions());
    {
        wslc_lock_path_override = bad_lock_dir;
        defer wslc_lock_path_override = null;

        try std.testing.expectError(
            error.StorageFailure,
            storeWslcCredential(gpa, .file, "myacr.azurecr.io", acr_token_username, "acr_should_not_write"),
        );
    }

    // Existing ghcr.io entry is still intact.
    {
        const existing = try getWslcCredential(gpa, .file, "ghcr.io");
        defer existing.deinit(gpa);
        try std.testing.expectEqualStrings("gho_preserve_me", existing.secret);
    }

    // 2. Transient AccessDenied / LockViolation on read retries and preserves existing entries.
    const ReadFaultInjector = struct {
        var calls: usize = 0;
        var mode: enum { transient, persistent } = .transient;

        fn readFn(alloc: Allocator, path: []const u8) anyerror![]u8 {
            calls += 1;
            if (mode == .persistent) return error.AccessDenied;
            if (calls == 1) return error.LockViolation;
            if (calls == 2) return error.AccessDenied;
            return Io.Dir.cwd().readFileAlloc(Io.Threaded.global_single_threaded.io(), path, alloc, .limited(4 * 1024 * 1024));
        }
    };
    {
        ReadFaultInjector.calls = 0;
        ReadFaultInjector.mode = .transient;
        fs_read_override_fn = ReadFaultInjector.readFn;
        defer fs_read_override_fn = null;

        try storeWslcCredential(gpa, .file, "myacr.azurecr.io", acr_token_username, "acr_merged_ok");
        try std.testing.expectEqual(@as(usize, 3), ReadFaultInjector.calls);
    }

    // 3. Persistent AccessDenied on read propagates StorageFailure and NEVER overwrites existing entries!
    {
        ReadFaultInjector.calls = 0;
        ReadFaultInjector.mode = .persistent;
        fs_read_override_fn = ReadFaultInjector.readFn;
        defer fs_read_override_fn = null;

        try std.testing.expectError(
            error.StorageFailure,
            storeWslcCredential(gpa, .file, "other.example.com", "bob", "clobber_attempt"),
        );
        try std.testing.expectEqual(fs_max_attempts, ReadFaultInjector.calls);
    }

    // Both ghcr.io and myacr.azurecr.io must still be present on disk!
    {
        const gh_cred = try getWslcCredential(gpa, .file, "ghcr.io");
        defer gh_cred.deinit(gpa);
        try std.testing.expectEqualStrings("gho_preserve_me", gh_cred.secret);

        const acr_cred = try getWslcCredential(gpa, .file, "myacr.azurecr.io");
        defer acr_cred.deinit(gpa);
        try std.testing.expectEqualStrings("acr_merged_ok", acr_cred.secret);
    }

    // 4. Transient AccessDenied on rename in writeFileAtomic retries and succeeds.
    const RenameFaultInjector = struct {
        var calls: usize = 0;

        fn renameFn(old_path: []const u8, new_path: []const u8) anyerror!void {
            calls += 1;
            if (calls <= 2) return error.AccessDenied;
            return Io.Dir.cwd().rename(old_path, Io.Dir.cwd(), new_path, Io.Threaded.global_single_threaded.io());
        }
    };
    {
        RenameFaultInjector.calls = 0;
        fs_rename_override_fn = RenameFaultInjector.renameFn;
        defer fs_rename_override_fn = null;

        try storeWslcCredential(gpa, .file, "third.example.com", "alice", "third_secret");
        try std.testing.expectEqual(@as(usize, 3), RenameFaultInjector.calls);

        const third = try getWslcCredential(gpa, .file, "third.example.com");
        defer third.deinit(gpa);
        try std.testing.expectEqualStrings("third_secret", third.secret);
    }
}

test "std.json.Stringify escapes all control characters below 0x20 and round-trips HelperOutput" {
    const gpa = std.testing.allocator;

    const raw = "a\x00\x01\x08\x0c\x1b\x1f\n\r\t\"\\z";
    const json_out = try std.json.Stringify.valueAlloc(gpa, HelperOutput{
        .ServerURL = "ghcr.io",
        .Username = "alice",
        .Secret = raw,
    }, .{});
    defer gpa.free(json_out);

    for (json_out) |c| {
        try std.testing.expect(c >= 0x20);
    }

    const parsed = try std.json.parseFromSlice(HelperStoreInput, gpa, json_out, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("ghcr.io", parsed.value.ServerURL.?);
    try std.testing.expectEqualStrings("alice", parsed.value.Username.?);
    try std.testing.expectEqualStrings(raw, parsed.value.Secret.?);
}

test "parseArgs supports login flags in any position and env_override_fn isolates paths" {
    const gpa = std.testing.allocator;

    const interspersed = parseArgs(&.{ "login", "ghcr.io", "-f", "myacr.azurecr.io", "-u", "octocat", "containers.corp.ghe.com" }).?;
    try std.testing.expect(interspersed.login.force);
    try std.testing.expectEqualStrings("octocat", interspersed.login.username.?);
    try std.testing.expectEqual(@as(usize, 3), interspersed.login.server_count);

    var it = interspersed.login.serverIterator();
    try std.testing.expectEqualStrings("ghcr.io", it.next().?);
    try std.testing.expectEqualStrings("myacr.azurecr.io", it.next().?);
    try std.testing.expectEqualStrings("containers.corp.ghe.com", it.next().?);
    try std.testing.expect(it.next() == null);

    const stdin_after = parseArgs(&.{ "login", "registry.example.com", "-u", "alice", "--password-stdin" }).?;
    try std.testing.expect(stdin_after.login.password_stdin);
    try std.testing.expectEqualStrings("registry.example.com", stdin_after.login.first_server.?);
    try std.testing.expectEqualStrings("alice", stdin_after.login.username.?);

    env_override_fn = struct {
        fn get(name: []const u8) ?[]const u8 {
            if (std.mem.eql(u8, name, "WSLC_CONFIG_DIR")) return "/custom/wslc-dir";
            if (std.mem.eql(u8, name, "LOCALAPPDATA")) return "C:\\HermeticLocalAppData";
            if (std.mem.eql(u8, name, "XDG_DATA_HOME")) return "/custom/xdg-data";
            return null;
        }
    }.get;
    defer env_override_fn = null;

    const resolved_dir = resolveWslcDir(gpa).?;
    defer gpa.free(resolved_dir);
    try std.testing.expectEqualStrings("/custom/wslc-dir", resolved_dir);

    const lock_path = try resolveWslcLockPath(gpa, resolved_dir);
    defer gpa.free(lock_path);
    try std.testing.expect(std.mem.endsWith(u8, lock_path, lock_filename));
    try std.testing.expect(std.mem.indexOf(u8, lock_path, "keyring") != null);
}

test "ACR strips port from service param, retries once on AuthenticationFailed, lazy settings.yaml in credential get, and warns on WinCred >2560 bytes" {
    const gpa = std.testing.allocator;
    const io = Io.Threaded.global_single_threaded.io();

    // 1. `buildAcrExchangeRequest` strips `:443` from `service=` while keeping `:443` on the URL.
    {
        const req = try buildAcrExchangeRequest(gpa, "myregistry.azurecr.io:443", "arm_tok", "tid-123");
        defer req.deinit(gpa);
        try std.testing.expectEqualStrings("https://myregistry.azurecr.io:443/oauth2/exchange", req.url);
        try std.testing.expectEqualStrings(
            "grant_type=access_token&service=myregistry.azurecr.io&tenant=tid-123&access_token=arm_tok",
            req.form_body,
        );
    }

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = try gpa.dupe(u8, path_buf[0..path_len]);
    defer gpa.free(dir_path);

    wslc_dir_override = dir_path;
    defer wslc_dir_override = null;
    dpapi_ops_override = FakeDpapi.ops;
    defer dpapi_ops_override = null;
    FakeWinCred.reset();
    wincred_ops_override = FakeWinCred.ops;
    defer wincred_ops_override = null;

    // 2. Write an invalid settings.yaml (`credentialStore: bogus`) and verify
    //    `keyring wslc credential get` for `ghcr.io` still succeeds because
    //    `detectCredentialStore` is only called when reading/writing wslc storage.
    try tmp.dir.writeFile(io, .{ .sub_path = "settings.yaml", .data = "credentialStore: bogus\n" });

    const MockRetry = struct {
        var arm_calls: usize = 0;
        var saw_force_refresh: bool = false;
        var exchange_calls: usize = 0;

        fn acquireGh(
            alloc: Allocator,
            _: []const u8,
            _: ?[]const u8,
            _: bool,
            _: bool,
            _: *Io.Writer,
        ) gh.AuthError!?gh.GitCredential {
            return .{
                .username = try alloc.dupe(u8, "cataggar"),
                .token = try alloc.dupe(u8, "gho_lazy_ok"),
            };
        }

        fn acquireArm(
            alloc: Allocator,
            _: *Io.Writer,
            _: bool,
            force_refresh: bool,
        ) ado.Error![]u8 {
            arm_calls += 1;
            if (force_refresh) {
                saw_force_refresh = true;
                return alloc.dupe(u8, "fresh_arm_token");
            }
            return alloc.dupe(u8, "stale_arm_token");
        }

        fn exchangeAcr(
            alloc: Allocator,
            _: []const u8,
            arm_token: []const u8,
            _: ?[]const u8,
        ) Error![]u8 {
            exchange_calls += 1;
            if (std.mem.eql(u8, arm_token, "stale_arm_token")) {
                return error.AuthenticationFailed;
            }
            return alloc.dupe(u8, "valid_acr_refresh_token");
        }

        fn genericGet(_: Allocator, _: []const u8, _: []const u8) keyring_zig.Error![]u8 {
            return error.EntryNotFound;
        }
        fn genericSet(_: Allocator, _: []const u8, _: []const u8, _: []const u8) keyring_zig.Error!void {}
        fn nowSeconds() i64 {
            return 1700000000;
        }
    };

    MockRetry.arm_calls = 0;
    MockRetry.saw_force_refresh = false;
    MockRetry.exchange_calls = 0;
    provider_hooks_override = .{
        .acquireGhCredential = MockRetry.acquireGh,
        .acquireArmToken = MockRetry.acquireArm,
        .exchangeAcrToken = MockRetry.exchangeAcr,
        .genericGet = MockRetry.genericGet,
        .genericSet = MockRetry.genericSet,
        .nowSeconds = MockRetry.nowSeconds,
    };
    defer provider_hooks_override = null;

    {
        var out = Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        var err_out = Io.Writer.Allocating.init(gpa);
        defer err_out.deinit();
        var in_reader = Io.Reader.fixed("https://ghcr.io/v2/\n");

        const code = try run(gpa, .{ .credential = .get }, &in_reader, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        try std.testing.expectEqualStrings(
            "{\"ServerURL\":\"ghcr.io\",\"Username\":\"cataggar\",\"Secret\":\"gho_lazy_ok\"}\n",
            out.written(),
        );
    }

    // 3. Fix settings.yaml to wincred and verify ACR 401/AuthenticationFailed triggers a single `force_refresh = true` retry.
    try tmp.dir.writeFile(io, .{ .sub_path = "settings.yaml", .data = "credentialStore: wincred\n" });
    {
        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        const cred = try resolveRegistryCredential(
            gpa,
            .wincred,
            "myacr.azurecr.io",
            null,
            false,
            false,
            &stderr.writer,
        );
        defer cred.deinit(gpa);
        try std.testing.expectEqualStrings("valid_acr_refresh_token", cred.secret);
        try std.testing.expectEqual(@as(usize, 2), MockRetry.arm_calls);
        try std.testing.expect(MockRetry.saw_force_refresh);
        try std.testing.expectEqual(@as(usize, 2), MockRetry.exchange_calls);
    }

    // 4. Storing > 2,560 bytes in WinCred fails with actionable stderr guidance pointing to `credentialStore: file`.
    {
        const oversized = try gpa.alloc(u8, 2600);
        defer gpa.free(oversized);
        @memset(oversized, 'x');

        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();

        try std.testing.expectError(
            error.StorageFailure,
            setWslcCredential(gpa, .wincred, "myacr.azurecr.io", acr_token_username, oversized, &stderr.writer),
        );
        try std.testing.expect(std.mem.indexOf(u8, stderr.written(), "2,560-byte blob limit") != null);
        try std.testing.expect(std.mem.indexOf(u8, stderr.written(), "credentialStore: file") != null);
    }
}

test "writeFileAtomic supports relative WSLC_CONFIG_DIR paths without panicking" {
    const gpa = std.testing.allocator;
    const io = Io.Threaded.global_single_threaded.io();

    var rand_bytes: [6]u8 = undefined;
    io.random(&rand_bytes);
    const hex = std.fmt.bytesToHex(rand_bytes, .lower);
    const rel_dir = try std.fmt.allocPrint(gpa, "./.zig-cache/wslc-rel-test-{s}", .{hex});
    defer gpa.free(rel_dir);
    try std.testing.expect(!std.fs.path.isAbsolute(rel_dir));
    defer Io.Dir.cwd().deleteTree(io, rel_dir) catch {};

    const EnvCtx = struct {
        var dir: []const u8 = "";
        fn get(name: []const u8) ?[]const u8 {
            if (std.mem.eql(u8, name, "WSLC_CONFIG_DIR")) return dir;
            return null;
        }
    };
    EnvCtx.dir = rel_dir;
    wslc_dir_override = null;
    wslc_lock_path_override = null;
    env_override_fn = EnvCtx.get;
    defer env_override_fn = null;
    dpapi_ops_override = FakeDpapi.ops;
    defer dpapi_ops_override = null;

    try storeWslcCredential(gpa, .file, "ghcr.io", "octocat", "ghp_rel_secret_1");
    try storeWslcCredential(gpa, .file, "myregistry.azurecr.io", "repotoken", "acr_rel_secret_2");

    const got = try getWslcCredential(gpa, .file, "ghcr.io");
    defer got.deinit(gpa);
    try std.testing.expectEqualStrings("octocat", got.username);
    try std.testing.expectEqualStrings("ghp_rel_secret_1", got.secret);

    try eraseWslcCredential(gpa, .file, "ghcr.io");
    try std.testing.expectError(error.EntryNotFound, getWslcCredential(gpa, .file, "ghcr.io"));

    const remaining = try getWslcCredential(gpa, .file, "myregistry.azurecr.io");
    defer remaining.deinit(gpa);
    try std.testing.expectEqualStrings("repotoken", remaining.username);
    try std.testing.expectEqualStrings("acr_rel_secret_2", remaining.secret);
}

test "credential store and --password-stdin round-trip for ghcr.io without gh login and for non-JWT ACR tokens, and OOM never leaks partial StoredCredential" {
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
    dpapi_ops_override = FakeDpapi.ops;
    defer dpapi_ops_override = null;

    const ManualRoundTripMocks = struct {
        var gh_calls: usize = 0;
        var arm_calls: usize = 0;
        var acr_exchange_calls: usize = 0;
        var generic_secret: ?[]const u8 = null;

        fn acquireGh(
            _: Allocator,
            _: []const u8,
            _: ?[]const u8,
            _: bool,
            _: bool,
            _: *Io.Writer,
        ) gh.AuthError!?gh.GitCredential {
            gh_calls += 1;
            // Simulate a machine with NO `gh` login configured.
            return null;
        }

        fn acquireArm(
            alloc: Allocator,
            _: *Io.Writer,
            _: bool,
            _: bool,
        ) ado.Error![]u8 {
            arm_calls += 1;
            return alloc.dupe(u8, "arm_token_should_not_be_used");
        }

        fn exchangeAcr(
            alloc: Allocator,
            _: []const u8,
            _: []const u8,
            _: ?[]const u8,
        ) Error![]u8 {
            acr_exchange_calls += 1;
            return alloc.dupe(u8, "entra_acr_jwt_should_not_clobber");
        }

        fn genericGet(alloc: Allocator, service: []const u8, account: []const u8) keyring_zig.Error![]u8 {
            if (generic_secret) |sec| {
                if (std.mem.eql(u8, service, "https://ghcr.io") and std.mem.eql(u8, account, "stdin-bot")) {
                    return alloc.dupe(u8, sec);
                }
            }
            return error.EntryNotFound;
        }

        fn genericSet(_: Allocator, service: []const u8, account: []const u8, password: []const u8) keyring_zig.Error!void {
            if (std.mem.eql(u8, service, "https://ghcr.io") and std.mem.eql(u8, account, "stdin-bot")) {
                _ = password;
                generic_secret = "ghp_stdin_bot_secret";
            }
        }

        fn nowSeconds() i64 {
            return 1700000000;
        }
    };

    ManualRoundTripMocks.gh_calls = 0;
    ManualRoundTripMocks.arm_calls = 0;
    ManualRoundTripMocks.acr_exchange_calls = 0;
    ManualRoundTripMocks.generic_secret = null;
    provider_hooks_override = .{
        .acquireGhCredential = ManualRoundTripMocks.acquireGh,
        .acquireArmToken = ManualRoundTripMocks.acquireArm,
        .exchangeAcrToken = ManualRoundTripMocks.exchangeAcr,
        .genericGet = ManualRoundTripMocks.genericGet,
        .genericSet = ManualRoundTripMocks.genericSet,
        .nowSeconds = ManualRoundTripMocks.nowSeconds,
    };
    defer provider_hooks_override = null;

    // 1. `credential store` -> `credential get` for `ghcr.io` when no `gh` login exists.
    {
        var out = Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        var err_out = Io.Writer.Allocating.init(gpa);
        defer err_out.deinit();
        var store_in = Io.Reader.fixed(
            "{\"ServerURL\":\"https://ghcr.io\",\"Username\":\"octocat\",\"Secret\":\"ghp_manual_store_token\"}\n",
        );
        const store_code = try run(gpa, .{ .credential = .store }, &store_in, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), store_code);

        var get_in = Io.Reader.fixed("ghcr.io\n");
        const get_code = try run(gpa, .{ .credential = .get }, &get_in, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), get_code);
        try std.testing.expectEqualStrings(
            "{\"ServerURL\":\"ghcr.io\",\"Username\":\"octocat\",\"Secret\":\"ghp_manual_store_token\"}\n",
            out.written(),
        );
    }

    // 2. `credential store` -> `credential get` for non-JWT `myregistry.azurecr.io` repository/admin token.
    {
        var out = Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        var err_out = Io.Writer.Allocating.init(gpa);
        defer err_out.deinit();
        var store_in = Io.Reader.fixed(
            "{\"ServerURL\":\"myregistry.azurecr.io\",\"Username\":\"repo-pull-token\",\"Secret\":\"acr_non_jwt_repo_password_999\"}\n",
        );
        const store_code = try run(gpa, .{ .credential = .store }, &store_in, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), store_code);

        var get_in = Io.Reader.fixed("https://myregistry.azurecr.io/v2/\n");
        const get_code = try run(gpa, .{ .credential = .get }, &get_in, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), get_code);
        try std.testing.expectEqualStrings(
            "{\"ServerURL\":\"myregistry.azurecr.io\",\"Username\":\"repo-pull-token\",\"Secret\":\"acr_non_jwt_repo_password_999\"}\n",
            out.written(),
        );
        // Must NOT call Entra ARM token or overwrite with 00000000-0000-0000-0000-000000000000!
        try std.testing.expectEqual(@as(usize, 0), ManualRoundTripMocks.arm_calls);
        try std.testing.expectEqual(@as(usize, 0), ManualRoundTripMocks.acr_exchange_calls);
    }

    // 3. No-arg `keyring wslc login` preserves both `ghcr.io` (without `gh` login) and non-JWT `myregistry.azurecr.io`!
    {
        var out = Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        var err_out = Io.Writer.Allocating.init(gpa);
        defer err_out.deinit();
        var empty_in = Io.Reader.fixed("");

        const cmd = parseArgs(&.{"login"}).?;
        const code = try run(gpa, cmd, &empty_in, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        try std.testing.expectEqual(@as(usize, 0), ManualRoundTripMocks.arm_calls);
        try std.testing.expectEqual(@as(usize, 0), ManualRoundTripMocks.acr_exchange_calls);

        const ghcr_after = try getWslcCredential(gpa, .file, "ghcr.io");
        defer ghcr_after.deinit(gpa);
        try std.testing.expectEqualStrings("octocat", ghcr_after.username);
        try std.testing.expectEqualStrings("ghp_manual_store_token", ghcr_after.secret);

        const acr_after = try getWslcCredential(gpa, .file, "myregistry.azurecr.io");
        defer acr_after.deinit(gpa);
        try std.testing.expectEqualStrings("repo-pull-token", acr_after.username);
        try std.testing.expectEqualStrings("acr_non_jwt_repo_password_999", acr_after.secret);
    }

    // 4. `wslc login ghcr.io -u stdin-bot --password-stdin` round-trips via genericGet even after wslc erase.
    {
        var out = Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        var err_out = Io.Writer.Allocating.init(gpa);
        defer err_out.deinit();
        var pw_in = Io.Reader.fixed("ghp_stdin_bot_secret\n");

        const cmd = parseArgs(&.{ "login", "ghcr.io", "-u", "stdin-bot", "--password-stdin" }).?;
        try std.testing.expectEqual(@as(u8, 0), try run(gpa, cmd, &pw_in, &out.writer, &err_out.writer));

        try eraseWslcCredential(gpa, .file, "ghcr.io");
        const resolved = try resolveRegistryCredential(gpa, .file, "ghcr.io", "stdin-bot", false, false, &err_out.writer);
        defer resolved.deinit(gpa);
        try std.testing.expectEqualStrings("stdin-bot", resolved.username);
        try std.testing.expectEqualStrings("ghp_stdin_bot_secret", resolved.secret);
    }

    // 5. Simulate OOM at every allocation index across GHCR, ACR, and generic resolution to verify zero leaks.
    const OomHooks = struct {
        fn acquireGh(
            alloc: Allocator,
            _: []const u8,
            _: ?[]const u8,
            _: bool,
            _: bool,
            _: *Io.Writer,
        ) gh.AuthError!?gh.GitCredential {
            const u = try alloc.dupe(u8, "cataggar");
            errdefer alloc.free(u);
            const t = try alloc.dupe(u8, "gho_oom_test");
            return .{ .username = u, .token = t };
        }
        fn acquireArm(alloc: Allocator, _: *Io.Writer, _: bool, _: bool) ado.Error![]u8 {
            return alloc.dupe(u8, "arm_oom_tok");
        }
        fn exchangeAcr(alloc: Allocator, _: []const u8, _: []const u8, _: ?[]const u8) Error![]u8 {
            return alloc.dupe(u8, "acr_oom_rt");
        }
        fn genericGet(alloc: Allocator, _: []const u8, _: []const u8) keyring_zig.Error![]u8 {
            return alloc.dupe(u8, "gen_oom_secret");
        }
        fn genericSet(_: Allocator, _: []const u8, _: []const u8, _: []const u8) keyring_zig.Error!void {}
        fn nowSeconds() i64 {
            return 1700000000;
        }
    };
    provider_hooks_override = .{
        .acquireGhCredential = OomHooks.acquireGh,
        .acquireArmToken = OomHooks.acquireArm,
        .exchangeAcrToken = OomHooks.exchangeAcr,
        .genericGet = OomHooks.genericGet,
        .genericSet = OomHooks.genericSet,
        .nowSeconds = OomHooks.nowSeconds,
    };

    const cases = [_]struct { srv: []const u8, user: ?[]const u8, force: bool }{
        .{ .srv = "ghcr.io", .user = null, .force = false },
        .{ .srv = "ghcr.io", .user = "cataggar", .force = true },
        .{ .srv = "freshacr.azurecr.io", .user = null, .force = true },
        .{ .srv = "myacr.azurecr.io", .user = "repo-token", .force = true },
        .{ .srv = "generic.example.com", .user = "alice", .force = false },
    };
    for (cases) |c| {
        var stderr_sink = Io.Writer.Allocating.init(gpa);
        defer stderr_sink.deinit();

        var fail_idx: usize = 0;
        while (fail_idx < 24) : (fail_idx += 1) {
            var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = fail_idx });
            if (resolveRegistryCredential(
                failing.allocator(),
                .file,
                c.srv,
                c.user,
                c.force,
                false,
                &stderr_sink.writer,
            )) |cred| {
                cred.deinit(failing.allocator());
                break;
            } else |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
            }
        }
    }
}

test "ACR explicit non-sentinel username refreshes from genericGet on -f and returns EntryNotFound without Entra exchange" {
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
    dpapi_ops_override = FakeDpapi.ops;
    defer dpapi_ops_override = null;

    const AcrUserMocks = struct {
        var arm_calls: usize = 0;
        var exchange_calls: usize = 0;
        var last_tid: [64]u8 = undefined;
        var last_tid_len: usize = 0;
        var repo_token_in_generic: ?[]const u8 = null;

        fn acquireGh(
            _: Allocator,
            _: []const u8,
            _: ?[]const u8,
            _: bool,
            _: bool,
            _: *Io.Writer,
        ) gh.AuthError!?gh.GitCredential {
            return null;
        }

        fn acquireArm(alloc: Allocator, _: *Io.Writer, _: bool, _: bool) ado.Error![]u8 {
            arm_calls += 1;
            return alloc.dupe(u8, "arm_fallback_tok");
        }

        fn discoverTenant(alloc: Allocator, server: []const u8) ?[]u8 {
            if (std.mem.eql(u8, server, "myacr.azurecr.io")) {
                return parseWwwAuthenticateTenantIdAlloc(
                    alloc,
                    "Bearer realm=\"https://myacr.azurecr.io/oauth2/token\",service=\"myacr.azurecr.io\",tenant=\"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE\"",
                );
            }
            return null;
        }

        fn acquireArmForTenant(
            alloc: Allocator,
            _: *Io.Writer,
            _: bool,
            _: bool,
            tid: ?[]const u8,
        ) ado.Error![]u8 {
            arm_calls += 1;
            if (tid) |t| {
                @memcpy(last_tid[0..t.len], t);
                last_tid_len = t.len;
            } else {
                last_tid_len = 0;
            }
            return alloc.dupe(u8, "arm_tenant_tok");
        }

        fn exchangeAcr(alloc: Allocator, _: []const u8, _: []const u8, tid: ?[]const u8) Error![]u8 {
            exchange_calls += 1;
            if (tid) |t| {
                @memcpy(last_tid[0..t.len], t);
                last_tid_len = t.len;
            }
            return alloc.dupe(u8, "eyJhbGciOiJub25lIn0.eyJleHAiOjE4OTM0NTYwMDB9.acr_rt");
        }

        fn genericGet(alloc: Allocator, service: []const u8, account: []const u8) keyring_zig.Error![]u8 {
            if (std.mem.eql(u8, service, "https://myacr.azurecr.io") and std.mem.eql(u8, account, "repo-token")) {
                if (repo_token_in_generic) |sec| return alloc.dupe(u8, sec);
            }
            if (std.mem.eql(u8, service, "https://generic.example.com") and std.mem.eql(u8, account, "deploy-bot")) {
                return alloc.dupe(u8, "rotated_generic_secret");
            }
            return error.EntryNotFound;
        }

        fn genericSet(_: Allocator, _: []const u8, _: []const u8, _: []const u8) keyring_zig.Error!void {}

        fn nowSeconds() i64 {
            return 1700000000;
        }
    };

    AcrUserMocks.arm_calls = 0;
    AcrUserMocks.exchange_calls = 0;
    AcrUserMocks.last_tid_len = 0;
    AcrUserMocks.repo_token_in_generic = "rotated_acr_repo_password";
    provider_hooks_override = .{
        .acquireGhCredential = AcrUserMocks.acquireGh,
        .acquireArmToken = AcrUserMocks.acquireArm,
        .discoverAcrTenant = AcrUserMocks.discoverTenant,
        .acquireArmTokenForTenant = AcrUserMocks.acquireArmForTenant,
        .exchangeAcrToken = AcrUserMocks.exchangeAcr,
        .genericGet = AcrUserMocks.genericGet,
        .genericSet = AcrUserMocks.genericSet,
        .nowSeconds = AcrUserMocks.nowSeconds,
    };
    defer provider_hooks_override = null;

    // 1. `wslc login -f myacr.azurecr.io -u repo-token` refreshes from `genericGet` without calling Entra!
    try storeWslcCredential(gpa, .file, "myacr.azurecr.io", "repo-token", "stale_acr_repo_password");
    {
        var out = Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        var err_out = Io.Writer.Allocating.init(gpa);
        defer err_out.deinit();
        var empty_in = Io.Reader.fixed("");

        const cmd = parseArgs(&.{ "login", "-f", "myacr.azurecr.io", "-u", "repo-token" }).?;
        const code = try run(gpa, cmd, &empty_in, &out.writer, &err_out.writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        try std.testing.expectEqual(@as(usize, 0), AcrUserMocks.arm_calls);
        try std.testing.expectEqual(@as(usize, 0), AcrUserMocks.exchange_calls);

        const stored = try getWslcCredential(gpa, .file, "myacr.azurecr.io");
        defer stored.deinit(gpa);
        try std.testing.expectEqualStrings("repo-token", stored.username);
        try std.testing.expectEqualStrings("rotated_acr_repo_password", stored.secret);
    }

    // 2. Missing non-sentinel `-u repo-token` returns EntryNotFound (exit 3) without minting an Entra JWT!
    AcrUserMocks.repo_token_in_generic = null;
    {
        var err_out = Io.Writer.Allocating.init(gpa);
        defer err_out.deinit();

        // Under `-f`, wslc storage is bypassed and genericGet misses -> EntryNotFound.
        try std.testing.expectError(
            error.EntryNotFound,
            resolveRegistryCredential(gpa, .file, "myacr.azurecr.io", "repo-token", true, true, &err_out.writer),
        );
        // Without `-f`, an unknown non-sentinel username also returns EntryNotFound without calling Entra.
        try std.testing.expectError(
            error.EntryNotFound,
            resolveRegistryCredential(gpa, .file, "myacr.azurecr.io", "unknown-repo-token", false, true, &err_out.writer),
        );
        try std.testing.expectEqual(@as(usize, 0), AcrUserMocks.arm_calls);
        try std.testing.expectEqual(@as(usize, 0), AcrUserMocks.exchange_calls);
    }

    // 3. Sentinel `<token>` and `null` DO run Entra `/oauth2/exchange` (with discovered tenant) and emit `<token>` / `00000000-...`.
    {
        var err_out = Io.Writer.Allocating.init(gpa);
        defer err_out.deinit();

        const tok_cred = try resolveRegistryCredential(
            gpa,
            .file,
            "myacr.azurecr.io",
            identity_token_username,
            true,
            true,
            &err_out.writer,
        );
        defer tok_cred.deinit(gpa);
        try std.testing.expectEqualStrings(identity_token_username, tok_cred.username);
        try std.testing.expectEqualStrings(
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            AcrUserMocks.last_tid[0..AcrUserMocks.last_tid_len],
        );

        const guid_cred = try resolveRegistryCredential(
            gpa,
            .file,
            "myacr.azurecr.io",
            null,
            true,
            true,
            &err_out.writer,
        );
        defer guid_cred.deinit(gpa);
        try std.testing.expectEqualStrings(acr_token_username, guid_cred.username);
        try std.testing.expectEqual(@as(usize, 2), AcrUserMocks.arm_calls);
        try std.testing.expectEqual(@as(usize, 2), AcrUserMocks.exchange_calls);
    }

    // 4. Generic registry `-f` without `-u` refreshes rotated password from `genericGet`.
    try storeWslcCredential(gpa, .file, "generic.example.com", "deploy-bot", "old_generic_secret");
    {
        var err_out = Io.Writer.Allocating.init(gpa);
        defer err_out.deinit();
        const refreshed = try resolveRegistryCredential(
            gpa,
            .file,
            "generic.example.com",
            null,
            true,
            true,
            &err_out.writer,
        );
        defer refreshed.deinit(gpa);
        try std.testing.expectEqualStrings("deploy-bot", refreshed.username);
        try std.testing.expectEqualStrings("rotated_generic_secret", refreshed.secret);
    }

    // 5. Extreme JWT `exp` / clock timestamps never overflow signed `i64` in status or ACR refresh checks.
    const ExtremeClock = struct {
        var now_val: i64 = std.math.maxInt(i64) - 10;
        var exchange_count: usize = 0;

        fn acquireGh(_: Allocator, _: []const u8, _: ?[]const u8, _: bool, _: bool, _: *Io.Writer) gh.AuthError!?gh.GitCredential {
            return null;
        }
        fn acquireArm(alloc: Allocator, _: *Io.Writer, _: bool, _: bool) ado.Error![]u8 {
            return alloc.dupe(u8, "arm_tok");
        }
        fn exchangeAcr(alloc: Allocator, _: []const u8, _: []const u8, _: ?[]const u8) Error![]u8 {
            exchange_count += 1;
            return alloc.dupe(u8, "fresh_acr_tok");
        }
        fn genericGet(_: Allocator, _: []const u8, _: []const u8) keyring_zig.Error![]u8 {
            return error.EntryNotFound;
        }
        fn genericSet(_: Allocator, _: []const u8, _: []const u8, _: []const u8) keyring_zig.Error!void {}
        fn nowSeconds() i64 {
            return now_val;
        }
    };
    provider_hooks_override = .{
        .acquireGhCredential = ExtremeClock.acquireGh,
        .acquireArmToken = ExtremeClock.acquireArm,
        .exchangeAcrToken = ExtremeClock.exchangeAcr,
        .genericGet = ExtremeClock.genericGet,
        .genericSet = ExtremeClock.genericSet,
        .nowSeconds = ExtremeClock.nowSeconds,
    };
    // Payload: {"exp":9223372036854775807}
    const max_exp_jwt = "eyJhbGciOiJub25lIn0.eyJleHAiOjkyMjMzNzIwMzY4NTQ3NzU4MDd9.sig";
    try storeWslcCredential(gpa, .file, "myacr.azurecr.io", acr_token_username, max_exp_jwt);
    {
        var err_out = Io.Writer.Allocating.init(gpa);
        defer err_out.deinit();
        // `now_val` is within 10s of maxInt(i64) (< 300s buffer), so it refreshes without overflowing `now + 300`!
        const c = try resolveRegistryCredential(gpa, .file, "myacr.azurecr.io", null, false, true, &err_out.writer);
        defer c.deinit(gpa);
        try std.testing.expectEqual(@as(usize, 1), ExtremeClock.exchange_count);
    }
    try storeWslcCredential(gpa, .file, "myacr.azurecr.io", acr_token_username, max_exp_jwt);
    ExtremeClock.now_val = -1_000_000;
    {
        var out = Io.Writer.Allocating.init(gpa);
        defer out.deinit();
        var err_out = Io.Writer.Allocating.init(gpa);
        defer err_out.deinit();
        var empty_in = Io.Reader.fixed("");
        // `exp - now > maxInt(i64)` must not overflow in `wslc status`!
        try std.testing.expectEqual(@as(u8, 0), try run(gpa, .status, &empty_in, &out.writer, &err_out.writer));
        try std.testing.expect(std.mem.indexOf(u8, out.written(), "status=valid") != null);
    }
}
