//! `keyring podman` and `docker-credential-keyring` — Container registry
//! authentication for **Podman Desktop** and **Podman CLI** (`#65`, superseding `#41`).
//!
//! Architecture:
//! - **Podman CLI** (`podman`, `podman.exe`, `buildah`, `skopeo`) reads
//!   `containers-auth.json(5)` and checks `"credHelpers"` *before* `"auths"`,
//!   invoking `docker-credential-keyring` (`docker-credential-keyring.exe` on
//!   Windows) dynamically on demand. Over `podman-remote` (Windows -> WSL 2),
//!   the server serializer drops `IdentityToken` (`<token>`), so ACR refresh
//!   tokens are always returned as `Username = "00000000-0000-0000-0000-000000000000"`.
//! - **Podman Desktop** (`extensions/podman` `RegistrySetup` + `ImageRegistry`)
//!   ignores `"credHelpers"` and `"credsStore"`, reading base64 `username:secret`
//!   entries exclusively from `"auths"` keyed by bare hostnames (`ghcr.io`,
//!   `containers.<tenant>.ghe.com`, `<name>.azurecr.io`, `docker.io`).
//! - **Dual-mode default (`keyring podman login`)**: writes both `"auths"` (for
//!   Podman Desktop GUI) and `"credHelpers": { "<host>": "keyring" }` + provisions
//!   `docker-credential-keyring[.exe]` on `PATH` (for dynamic Podman CLI refresh).
//! - **Helper-only CLI mode (`keyring podman config` / `--helper-only`)**: writes
//!   `"credHelpers"` only with zero secrets stored in `auth.json`.
const std = @import("std");
const builtin = @import("builtin");
const app_build_options = @import("app_build_options");
const ado = @import("ado.zig");
const gh = @import("gh.zig");
const registry_auth = @import("registry_auth.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const helper_value = "keyring";
pub const helper_basename_posix = "docker-credential-keyring";
pub const helper_basename_windows = "docker-credential-keyring.exe";
pub const podman_lock_filename = "podman-auth.lock";
const cas_max_attempts: usize = 3;

pub const LoginMode = enum {
    dual,
    helper_only,
    auths_only,
};

pub const LoginServerIterator = struct {
    args: []const []const u8,
    index: usize = 0,

    pub fn next(self: *LoginServerIterator) ?[]const u8 {
        while (self.index < self.args.len) {
            const arg = self.args[self.index];
            if (std.mem.eql(u8, arg, "-f") or
                std.mem.eql(u8, arg, "--force") or
                std.mem.eql(u8, arg, "--password-stdin") or
                std.mem.eql(u8, arg, "--helper-only") or
                std.mem.eql(u8, arg, "--auths-only") or
                std.mem.startsWith(u8, arg, "--username=") or
                std.mem.startsWith(u8, arg, "--authfile="))
            {
                self.index += 1;
            } else if (std.mem.eql(u8, arg, "-u") or
                std.mem.eql(u8, arg, "--username") or
                std.mem.eql(u8, arg, "--authfile"))
            {
                self.index += 2;
            } else {
                self.index += 1;
                return arg;
            }
        }
        return null;
    }
};

pub const PositionalIterator = struct {
    args: []const []const u8,
    index: usize = 0,

    pub fn next(self: *PositionalIterator) ?[]const u8 {
        while (self.index < self.args.len) {
            const arg = self.args[self.index];
            if (std.mem.eql(u8, arg, "--all") or
                std.mem.startsWith(u8, arg, "--authfile="))
            {
                self.index += 1;
            } else if (std.mem.eql(u8, arg, "--authfile")) {
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
    mode: LoginMode = .dual,
    authfile: ?[]const u8 = null,

    pub fn serverIterator(self: LoginOptions) LoginServerIterator {
        return .{ .args = self.raw_args };
    }
};

pub const ConfigOptions = struct {
    raw_args: []const []const u8 = &.{},
    server_count: usize = 0,
    authfile: ?[]const u8 = null,

    pub fn serverIterator(self: ConfigOptions) PositionalIterator {
        return .{ .args = self.raw_args };
    }
};

pub const LogoutOptions = struct {
    raw_args: []const []const u8 = &.{},
    server_count: usize = 0,
    all: bool = false,
    authfile: ?[]const u8 = null,

    pub fn serverIterator(self: LogoutOptions) PositionalIterator {
        return .{ .args = self.raw_args };
    }
};

pub const StatusOptions = struct {
    authfile: ?[]const u8 = null,
};

pub const Subcommand = union(enum) {
    login: LoginOptions,
    config: ConfigOptions,
    logout: LogoutOptions,
    status: StatusOptions,
    credential: registry_auth.HelperOperation,
};

pub const Error = error{
    InvalidServer,
    InvalidInput,
    ExternalHelperConflict,
    HelperNotOnPath,
    EntryNotFound,
    NoStorageAccess,
    Locked,
    StorageFailure,
    AuthenticationFailed,
    NetworkFailure,
    OutOfMemory,
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
    acquireArmTokenForTenant: *const fn (
        gpa: Allocator,
        stderr: *Io.Writer,
        allow_interactive: bool,
        force_refresh: bool,
        tenant_id: ?[]const u8,
    ) ado.Error![]u8,
    discoverAcrTenant: *const fn (gpa: Allocator, server: []const u8) ?[]u8,
    exchangeAcrToken: *const fn (
        gpa: Allocator,
        server: []const u8,
        arm_access_token: []const u8,
        tenant_id: ?[]const u8,
    ) registry_auth.Error![]u8,
    nowSeconds: *const fn () i64,
};

const live_provider_hooks: ProviderHooks = .{
    .acquireGhCredential = gh.getOrLoginRegistryCredential,
    .acquireArmTokenForTenant = ado.acquireArmAccessTokenForTenant,
    .discoverAcrTenant = registry_auth.liveDiscoverAcrTenant,
    .exchangeAcrToken = registry_auth.liveExchangeAcrToken,
    .nowSeconds = liveNowSeconds,
};

var provider_hooks_override: ?ProviderHooks = null;
var env_override_fn: ?*const fn (name: []const u8) ?[]const u8 = null;
var self_exe_override: ?[]const u8 = null;
var os_tag_override: ?std.Target.Os.Tag = null;
var dir_exists_override_fn: ?*const fn (path: []const u8) bool = null;
var cas_race_inject_fn: ?*const fn (path: []const u8, attempt: usize) void = null;

fn activeProviderHooks() ProviderHooks {
    return provider_hooks_override orelse live_provider_hooks;
}

fn effectiveOsTag() std.Target.Os.Tag {
    return os_tag_override orelse builtin.os.tag;
}

fn liveNowSeconds() i64 {
    const io = Io.Threaded.global_single_threaded.io();
    return Io.Clock.real.now(io).toSeconds();
}

/// Return true if `arg0` invokes the binary as `docker-credential-keyring`
/// (or `docker-credential-keyring.exe` on Windows).
pub fn isDockerCredentialArgv0(arg0: []const u8) bool {
    var base = arg0;
    if (std.mem.lastIndexOfAny(u8, base, "/\\")) |sep| {
        base = base[sep + 1 ..];
    }
    if (base.len > 4 and std.ascii.endsWithIgnoreCase(base, ".exe")) {
        base = base[0 .. base.len - 4];
    }
    return std.ascii.eqlIgnoreCase(base, "docker-credential-keyring");
}

// ---------------------------------------------------------------------------
// CLI Parsing
// ---------------------------------------------------------------------------

pub fn parseArgs(rest: []const []const u8) ?Subcommand {
    if (rest.len == 0) return null;
    const sub = rest[0];
    const tail = rest[1..];

    if (std.mem.eql(u8, sub, "login")) return parseLoginArgs(tail);
    if (std.mem.eql(u8, sub, "config")) return parseConfigArgs(tail);
    if (std.mem.eql(u8, sub, "logout")) return parseLogoutArgs(tail);
    if (std.mem.eql(u8, sub, "status")) return parseStatusArgs(tail);
    if (std.mem.eql(u8, sub, "credential")) {
        if (tail.len != 1) return null;
        const op = registry_auth.HelperOperation.fromString(tail[0]) orelse return null;
        return .{ .credential = op };
    }
    return null;
}

fn parseLoginArgs(args: []const []const u8) ?Subcommand {
    var opts: LoginOptions = .{ .raw_args = args };
    var saw_helper_only = false;
    var saw_auths_only = false;

    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--force")) {
            opts.force = true;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--password-stdin")) {
            opts.password_stdin = true;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--helper-only")) {
            saw_helper_only = true;
            opts.mode = .helper_only;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--auths-only")) {
            saw_auths_only = true;
            opts.mode = .auths_only;
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
        } else if (std.mem.eql(u8, arg, "--authfile")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return null;
            opts.authfile = args[i + 1];
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--authfile=")) {
            const val = arg["--authfile=".len..];
            if (val.len == 0) return null;
            opts.authfile = val;
            i += 1;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return null;
        } else {
            if (arg.len == 0) return null;
            if (opts.first_server == null) opts.first_server = arg;
            opts.server_count += 1;
            i += 1;
        }
    }

    if (saw_helper_only and saw_auths_only) return null;
    if (opts.password_stdin and (opts.server_count != 1 or opts.username == null)) return null;
    return .{ .login = opts };
}

fn parseConfigArgs(args: []const []const u8) ?Subcommand {
    var opts: ConfigOptions = .{ .raw_args = args };
    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--authfile")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return null;
            opts.authfile = args[i + 1];
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--authfile=")) {
            const val = arg["--authfile=".len..];
            if (val.len == 0) return null;
            opts.authfile = val;
            i += 1;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return null;
        } else {
            if (arg.len == 0) return null;
            opts.server_count += 1;
            i += 1;
        }
    }
    if (opts.server_count == 0) return null;
    return .{ .config = opts };
}

fn parseLogoutArgs(args: []const []const u8) ?Subcommand {
    var opts: LogoutOptions = .{ .raw_args = args };
    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--all")) {
            opts.all = true;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--authfile")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return null;
            opts.authfile = args[i + 1];
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--authfile=")) {
            const val = arg["--authfile=".len..];
            if (val.len == 0) return null;
            opts.authfile = val;
            i += 1;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return null;
        } else {
            if (arg.len == 0) return null;
            opts.server_count += 1;
            i += 1;
        }
    }
    if (opts.all and opts.server_count != 0) return null;
    if (!opts.all and opts.server_count == 0) return null;
    return .{ .logout = opts };
}

fn parseStatusArgs(args: []const []const u8) ?Subcommand {
    var opts: StatusOptions = .{};
    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--authfile")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return null;
            opts.authfile = args[i + 1];
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--authfile=")) {
            const val = arg["--authfile=".len..];
            if (val.len == 0) return null;
            opts.authfile = val;
            i += 1;
        } else {
            return null;
        }
    }
    return .{ .status = opts };
}

// ---------------------------------------------------------------------------
// Platform auth.json Path Resolution
// ---------------------------------------------------------------------------

pub const AuthFilePaths = struct {
    primary_path: []u8,
    persistent_helpers_path: ?[]u8 = null,
    desktop_path: ?[]u8 = null,
    explicit_override: bool = false,

    pub fn deinit(self: *const AuthFilePaths, gpa: Allocator) void {
        gpa.free(self.primary_path);
        if (self.persistent_helpers_path) |p| gpa.free(p);
        if (self.desktop_path) |p| gpa.free(p);
    }
};

pub fn resolveAuthFilePaths(gpa: Allocator, explicit_authfile: ?[]const u8) Error!AuthFilePaths {
    const os_tag = effectiveOsTag();
    const home = getHomeDir(gpa);
    defer if (home) |h| gpa.free(h);

    const desktop_path: ?[]u8 = switch (os_tag) {
        .windows, .macos => if (home) |h|
            try std.fs.path.join(gpa, &.{ h, ".config", "containers", "auth.json" })
        else
            null,
        .linux => blk: {
            if (getEnvVarOwned(gpa, "XDG_RUNTIME_DIR")) |xdg_rt| {
                defer gpa.free(xdg_rt);
                if (xdg_rt.len > 0) {
                    break :blk try std.fs.path.join(gpa, &.{ xdg_rt, "containers", "auth.json" });
                }
            }
            break :blk null;
        },
        else => null,
    };
    errdefer if (desktop_path) |dp| gpa.free(dp);

    if (explicit_authfile) |af| {
        return .{
            .primary_path = try gpa.dupe(u8, af),
            .desktop_path = desktop_path,
            .explicit_override = true,
        };
    }

    if (getEnvVarOwned(gpa, "REGISTRY_AUTH_FILE")) |env_af| {
        if (env_af.len > 0) {
            return .{
                .primary_path = env_af,
                .desktop_path = desktop_path,
                .explicit_override = true,
            };
        }
        gpa.free(env_af);
    }

    switch (os_tag) {
        .windows, .macos => {
            const h = home orelse return error.NoStorageAccess;
            const primary = try std.fs.path.join(gpa, &.{ h, ".config", "containers", "auth.json" });
            return .{
                .primary_path = primary,
                .desktop_path = desktop_path,
            };
        },
        .linux => {
            const persistent: ?[]u8 = blk: {
                if (getEnvVarOwned(gpa, "XDG_CONFIG_HOME")) |xdg_cfg| {
                    defer gpa.free(xdg_cfg);
                    if (xdg_cfg.len > 0) {
                        break :blk try std.fs.path.join(gpa, &.{ xdg_cfg, "containers", "auth.json" });
                    }
                }
                if (home) |h| {
                    break :blk try std.fs.path.join(gpa, &.{ h, ".config", "containers", "auth.json" });
                }
                break :blk null;
            };
            errdefer if (persistent) |p| gpa.free(p);

            if (getEnvVarOwned(gpa, "XDG_RUNTIME_DIR")) |xdg_rt| {
                defer gpa.free(xdg_rt);
                if (xdg_rt.len > 0 and directoryExists(xdg_rt)) {
                    const primary = try std.fs.path.join(gpa, &.{ xdg_rt, "containers", "auth.json" });
                    const distinct_persistent = if (persistent) |p|
                        if (std.mem.eql(u8, p, primary)) blk: {
                            gpa.free(p);
                            break :blk null;
                        } else p
                    else
                        null;
                    return .{
                        .primary_path = primary,
                        .persistent_helpers_path = distinct_persistent,
                        .desktop_path = desktop_path,
                    };
                }
            }

            if (builtin.os.tag == .linux and os_tag_override == null and env_override_fn == null) {
                const uid = std.os.linux.geteuid();
                const run_user_dir = try std.fmt.allocPrint(gpa, "/run/containers/{d}", .{uid});
                defer gpa.free(run_user_dir);
                if (directoryWritable(run_user_dir)) {
                    const primary = try std.fs.path.join(gpa, &.{ run_user_dir, "auth.json" });
                    return .{
                        .primary_path = primary,
                        .persistent_helpers_path = persistent,
                        .desktop_path = desktop_path,
                    };
                }
            }

            const primary = persistent orelse return error.NoStorageAccess;
            return .{
                .primary_path = primary,
                .persistent_helpers_path = null,
                .desktop_path = desktop_path,
            };
        },
        else => {
            const h = home orelse return error.NoStorageAccess;
            const primary = try std.fs.path.join(gpa, &.{ h, ".config", "containers", "auth.json" });
            return .{
                .primary_path = primary,
                .desktop_path = desktop_path,
            };
        },
    }
}

fn directoryExists(path: []const u8) bool {
    if (dir_exists_override_fn) |override_fn| return override_fn(path);
    const io = Io.Threaded.global_single_threaded.io();
    const st = Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return st.kind == .directory;
}

fn directoryWritable(path: []const u8) bool {
    const io = Io.Threaded.global_single_threaded.io();
    Io.Dir.cwd().access(io, path, .{ .write = true }) catch return false;
    return directoryExists(path);
}

fn fileExists(path: []const u8) bool {
    const io = Io.Threaded.global_single_threaded.io();
    Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn getEnvVarOwned(gpa: Allocator, name: []const u8) ?[]u8 {
    if (env_override_fn) |override_fn| {
        if (override_fn(name)) |val| return gpa.dupe(u8, val) catch null;
        return null;
    }
    return registry_auth.getEnvVarOwned(gpa, name);
}

fn getHomeDir(gpa: Allocator) ?[]u8 {
    if (effectiveOsTag() == .windows) {
        if (getEnvVarOwned(gpa, "USERPROFILE")) |p| {
            if (p.len > 0) return p;
            gpa.free(p);
        }
    }
    if (getEnvVarOwned(gpa, "HOME")) |h| {
        if (h.len > 0) return h;
        gpa.free(h);
    }
    if (env_override_fn != null) return null;
    return registry_auth.getHomeDir(gpa);
}

fn resolveLockPath(gpa: Allocator, auth_path: []const u8) Error![]u8 {
    if (registry_auth.state_dir_override != null or env_override_fn == null) {
        if (registry_auth.resolveKeyringStateDir(gpa)) |state_dir| {
            defer gpa.free(state_dir);
            return std.fs.path.join(gpa, &.{ state_dir, podman_lock_filename });
        }
    }
    if (getHomeDir(gpa)) |home| {
        defer gpa.free(home);
        return std.fs.path.join(gpa, &.{ home, ".cache", "keyring", podman_lock_filename });
    }
    const parent = std.fs.path.dirname(auth_path) orelse ".";
    return std.fs.path.join(gpa, &.{ parent, ".keyring-podman.lock" });
}

// ---------------------------------------------------------------------------
// auth.json DOM Manipulation, Base64 Auth Encoding, & Optimistic CAS Writer
// ---------------------------------------------------------------------------

pub const BasicPair = struct {
    username: []u8,
    secret: []u8,

    pub fn deinit(self: *const BasicPair, gpa: Allocator) void {
        gpa.free(self.username);
        std.crypto.secureZero(u8, self.secret);
        gpa.free(self.secret);
    }
};

pub fn encodeBasicAuthAlloc(gpa: Allocator, username: []const u8, secret: []const u8) Error![]u8 {
    if (username.len == 0 or secret.len == 0) return error.InvalidInput;
    if (std.mem.indexOfScalar(u8, username, ':') != null) return error.InvalidInput;

    const raw_len = username.len + 1 + secret.len;
    const raw = try gpa.alloc(u8, raw_len);
    defer {
        std.crypto.secureZero(u8, raw);
        gpa.free(raw);
    }
    @memcpy(raw[0..username.len], username);
    raw[username.len] = ':';
    @memcpy(raw[username.len + 1 ..], secret);

    const enc_len = std.base64.standard.Encoder.calcSize(raw.len);
    const out = try gpa.alloc(u8, enc_len);
    _ = std.base64.standard.Encoder.encode(out, raw);
    return out;
}

pub fn decodeBasicAuthAlloc(gpa: Allocator, encoded: []const u8) Error!BasicPair {
    const trimmed = std.mem.trim(u8, encoded, " \t\r\n");
    const dec_len = std.base64.standard.Decoder.calcSizeForSlice(trimmed) catch return error.InvalidInput;
    const raw = try gpa.alloc(u8, dec_len);
    defer {
        std.crypto.secureZero(u8, raw);
        gpa.free(raw);
    }
    std.base64.standard.Decoder.decode(raw, trimmed) catch return error.InvalidInput;

    const colon_idx = std.mem.indexOfScalar(u8, raw, ':') orelse return error.InvalidInput;
    const username = try gpa.dupe(u8, raw[0..colon_idx]);
    errdefer gpa.free(username);
    const secret = try gpa.dupe(u8, raw[colon_idx + 1 ..]);
    return .{ .username = username, .secret = secret };
}

fn sha256Bytes(data: ?[]const u8) ?[32]u8 {
    const slice = data orelse return null;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(slice, &digest, .{});
    return digest;
}

fn digestsMatch(a: ?[32]u8, b: ?[32]u8) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.mem.eql(u8, &a.?, &b.?);
}

fn parseAuthJsonRootLeaky(a: Allocator, maybe_bytes: ?[]const u8) Error!std.json.ObjectMap {
    if (maybe_bytes) |bytes| {
        const trimmed = std.mem.trim(u8, bytes, " \t\r\n");
        if (trimmed.len > 0) {
            const val = std.json.parseFromSliceLeaky(std.json.Value, a, trimmed, .{
                .allocate = .alloc_always,
            }) catch return error.StorageFailure;
            if (val != .object) return error.StorageFailure;
            var obj = val.object;
            try ensureAuthsObject(a, &obj);
            return obj;
        }
    }
    var fresh: std.json.ObjectMap = .empty;
    try ensureAuthsObject(a, &fresh);
    return fresh;
}

fn ensureAuthsObject(a: Allocator, root: *std.json.ObjectMap) Error!void {
    if (root.getPtr("auths")) |auths_val| {
        if (auths_val.* != .object) return error.StorageFailure;
    } else {
        root.put(a, "auths", .{ .object = .empty }) catch return error.OutOfMemory;
    }
}

fn ensureCredHelpersObject(a: Allocator, root: *std.json.ObjectMap) Error!*std.json.ObjectMap {
    if (root.getPtr("credHelpers")) |ch_val| {
        if (ch_val.* != .object) return error.StorageFailure;
        return &ch_val.object;
    }
    root.put(a, "credHelpers", .{ .object = .empty }) catch return error.OutOfMemory;
    return &root.getPtr("credHelpers").?.object;
}

fn mutateAuthFileWithCas(
    gpa: Allocator,
    auth_path: []const u8,
    ctx: anytype,
    comptime mutateFn: fn (a: Allocator, root: *std.json.ObjectMap, ctx: @TypeOf(ctx)) Error!bool,
) Error!bool {
    const lock_path = try resolveLockPath(gpa, auth_path);
    defer gpa.free(lock_path);
    var lock = try registry_auth.acquireLockFile(lock_path);
    defer lock.release();

    var attempt: usize = 0;
    while (attempt < cas_max_attempts) : (attempt += 1) {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();

        const initial_bytes = try registry_auth.readFileIfExists(a, auth_path);
        defer if (initial_bytes) |b| std.crypto.secureZero(u8, b);
        const initial_hash = sha256Bytes(initial_bytes);

        var root = try parseAuthJsonRootLeaky(a, initial_bytes);
        const changed = try mutateFn(a, &root, ctx);
        if (!changed and initial_bytes != null) {
            return false;
        }

        if (cas_race_inject_fn) |race_fn| {
            race_fn(auth_path, attempt);
        }

        const verify_bytes = try registry_auth.readFileIfExists(a, auth_path);
        defer if (verify_bytes) |b| std.crypto.secureZero(u8, b);
        if (!digestsMatch(initial_hash, sha256Bytes(verify_bytes))) {
            continue;
        }

        const root_val: std.json.Value = .{ .object = root };
        const serialized_raw = std.json.Stringify.valueAlloc(a, root_val, .{
            .whitespace = .indent_2,
        }) catch return error.OutOfMemory;
        defer std.crypto.secureZero(u8, serialized_raw);

        const serialized = try std.fmt.allocPrint(a, "{s}\n", .{serialized_raw});
        defer std.crypto.secureZero(u8, serialized);

        try registry_auth.writeProtectedFileAtomic(a, auth_path, serialized);
        return changed;
    }
    return error.StorageFailure;
}

const LoginRecord = struct {
    server: []const u8,
    username: []const u8,
    secret: []const u8,
};

const ApplyLoginCtx = struct {
    records: []const LoginRecord,
    mode: LoginMode,
    force: bool,
};

fn applyLoginMutation(a: Allocator, root: *std.json.ObjectMap, ctx: ApplyLoginCtx) Error!bool {
    const auths_obj = &root.getPtr("auths").?.object;

    for (ctx.records) |rec| {
        switch (ctx.mode) {
            .dual => {
                const encoded = try encodeBasicAuthAlloc(a, rec.username, rec.secret);
                try putAuthsEntryPreservingFields(a, auths_obj, rec.server, encoded);
                const ch_obj = try ensureCredHelpersObject(a, root);
                ch_obj.put(a, try a.dupe(u8, rec.server), .{ .string = try a.dupe(u8, helper_value) }) catch return error.OutOfMemory;
            },
            .helper_only => {
                _ = auths_obj.orderedRemove(rec.server);
                const ch_obj = try ensureCredHelpersObject(a, root);
                ch_obj.put(a, try a.dupe(u8, rec.server), .{ .string = try a.dupe(u8, helper_value) }) catch return error.OutOfMemory;
            },
            .auths_only => {
                if (root.getPtr("credHelpers")) |ch_val| {
                    if (ch_val.* != .object) return error.StorageFailure;
                    if (ch_val.object.get(rec.server)) |existing_helper| {
                        if (existing_helper == .string) {
                            if (std.mem.eql(u8, existing_helper.string, helper_value) or ctx.force) {
                                _ = ch_val.object.orderedRemove(rec.server);
                            } else {
                                return error.ExternalHelperConflict;
                            }
                        }
                    }
                }
                const encoded = try encodeBasicAuthAlloc(a, rec.username, rec.secret);
                try putAuthsEntryPreservingFields(a, auths_obj, rec.server, encoded);
            },
        }
    }
    return true;
}

fn putAuthsEntryPreservingFields(
    a: Allocator,
    auths_obj: *std.json.ObjectMap,
    server: []const u8,
    encoded_auth: []const u8,
) Error!void {
    if (auths_obj.getPtr(server)) |existing| {
        if (existing.* == .object) {
            existing.object.put(a, "auth", .{ .string = encoded_auth }) catch return error.OutOfMemory;
            _ = existing.object.orderedRemove("identitytoken");
            return;
        }
    }
    var entry_obj: std.json.ObjectMap = .empty;
    entry_obj.put(a, "auth", .{ .string = encoded_auth }) catch return error.OutOfMemory;
    auths_obj.put(a, try a.dupe(u8, server), .{ .object = entry_obj }) catch return error.OutOfMemory;
}

const RemoveHelpersForAuthsOnlyCtx = struct {
    servers: []const []const u8,
    force: bool,
};

fn removeHelpersForAuthsOnlyMutation(_: Allocator, root: *std.json.ObjectMap, ctx: RemoveHelpersForAuthsOnlyCtx) Error!bool {
    var any_changed = false;
    if (root.getPtr("credHelpers")) |ch_val| {
        if (ch_val.* != .object) return error.StorageFailure;
        for (ctx.servers) |srv| {
            if (ch_val.object.get(srv)) |existing_helper| {
                if (existing_helper == .string) {
                    if (std.mem.eql(u8, existing_helper.string, helper_value) or ctx.force) {
                        _ = ch_val.object.orderedRemove(srv);
                        any_changed = true;
                    } else {
                        return error.ExternalHelperConflict;
                    }
                }
            }
        }
    }
    return any_changed;
}

const ApplyConfigCtx = struct {
    servers: []const []const u8,
};

fn applyConfigMutation(a: Allocator, root: *std.json.ObjectMap, ctx: ApplyConfigCtx) Error!bool {
    const ch_obj = try ensureCredHelpersObject(a, root);
    for (ctx.servers) |srv| {
        ch_obj.put(a, try a.dupe(u8, srv), .{ .string = try a.dupe(u8, helper_value) }) catch return error.OutOfMemory;
    }
    return true;
}

const ApplyLogoutCtx = struct {
    servers: []const []const u8,
    all: bool,
    removed_servers: *std.ArrayList([]u8),
    gpa: Allocator,
};

fn applyLogoutMutation(_: Allocator, root: *std.json.ObjectMap, ctx: ApplyLogoutCtx) Error!bool {
    var any_removed = false;
    const auths_obj = &root.getPtr("auths").?.object;

    if (ctx.all) {
        var auth_keys = std.ArrayList([]const u8).empty;
        defer auth_keys.deinit(ctx.gpa);
        var it = auths_obj.iterator();
        while (it.next()) |kv| {
            if (std.mem.indexOfScalar(u8, kv.key_ptr.*, '/') == null) {
                auth_keys.append(ctx.gpa, kv.key_ptr.*) catch return error.OutOfMemory;
            }
        }
        for (auth_keys.items) |k| {
            try recordRemovedUnique(ctx.gpa, ctx.removed_servers, k);
            _ = auths_obj.orderedRemove(k);
            any_removed = true;
        }

        if (root.getPtr("credHelpers")) |ch_val| {
            if (ch_val.* == .object) {
                var ch_keys = std.ArrayList([]const u8).empty;
                defer ch_keys.deinit(ctx.gpa);
                var ch_it = ch_val.object.iterator();
                while (ch_it.next()) |kv| {
                    if (kv.value_ptr.* == .string and std.mem.eql(u8, kv.value_ptr.string, helper_value)) {
                        ch_keys.append(ctx.gpa, kv.key_ptr.*) catch return error.OutOfMemory;
                    }
                }
                for (ch_keys.items) |k| {
                    try recordRemovedUnique(ctx.gpa, ctx.removed_servers, k);
                    _ = ch_val.object.orderedRemove(k);
                    any_removed = true;
                }
            }
        }
        return any_removed;
    }

    for (ctx.servers) |srv| {
        var srv_removed = false;
        if (auths_obj.orderedRemove(srv)) {
            srv_removed = true;
        }
        if (root.getPtr("credHelpers")) |ch_val| {
            if (ch_val.* == .object) {
                if (ch_val.object.get(srv)) |v| {
                    if (v == .string and std.mem.eql(u8, v.string, helper_value)) {
                        _ = ch_val.object.orderedRemove(srv);
                        srv_removed = true;
                    }
                }
            }
        }
        if (srv_removed) {
            try recordRemovedUnique(ctx.gpa, ctx.removed_servers, srv);
            any_removed = true;
        }
    }
    return any_removed;
}

fn recordRemovedUnique(gpa: Allocator, list: *std.ArrayList([]u8), server: []const u8) Error!void {
    for (list.items) |existing| {
        if (std.mem.eql(u8, existing, server)) return;
    }
    const copy = try gpa.dupe(u8, server);
    errdefer gpa.free(copy);
    try list.append(gpa, copy);
}

// ---------------------------------------------------------------------------
// ghr-Aware docker-credential-keyring[.exe] PATH Provisioning
// ---------------------------------------------------------------------------

pub fn helperBinaryName() []const u8 {
    return if (effectiveOsTag() == .windows) helper_basename_windows else helper_basename_posix;
}

fn keyringBinaryName() []const u8 {
    return if (effectiveOsTag() == .windows) "keyring.exe" else "keyring";
}

fn pathListDelimiter() u8 {
    return if (builtin.os.tag == .windows) ';' else ':';
}

fn pathsEqualForOs(a: []const u8, b: []const u8) bool {
    const ta = std.mem.trimEnd(u8, a, "/\\");
    const tb = std.mem.trimEnd(u8, b, "/\\");
    if (builtin.os.tag == .windows or effectiveOsTag() == .windows) {
        if (ta.len != tb.len) return false;
        for (ta, tb) |ca, cb| {
            const na = if (ca == '/') '\\' else std.ascii.toLower(ca);
            const nb = if (cb == '/') '\\' else std.ascii.toLower(cb);
            if (na != nb) return false;
        }
        return true;
    }
    return std.mem.eql(u8, ta, tb);
}

fn isDirInPathEnv(path_env: []const u8, candidate_dir: []const u8) bool {
    var it = std.mem.splitScalar(u8, path_env, pathListDelimiter());
    while (it.next()) |raw_entry| {
        const entry = std.mem.trim(u8, raw_entry, " \t\"");
        if (entry.len == 0) continue;
        if (pathsEqualForOs(entry, candidate_dir)) return true;
    }
    return false;
}

pub fn findHelperOnPathAlloc(gpa: Allocator) ?[]u8 {
    const path_env = getEnvVarOwned(gpa, "PATH") orelse getEnvVarOwned(gpa, "Path") orelse return null;
    defer gpa.free(path_env);

    const helper_name = helperBinaryName();
    var it = std.mem.splitScalar(u8, path_env, pathListDelimiter());
    while (it.next()) |raw_entry| {
        const entry = std.mem.trim(u8, raw_entry, " \t\"");
        if (entry.len == 0) continue;
        const candidate = std.fs.path.join(gpa, &.{ entry, helper_name }) catch continue;
        if (fileExists(candidate)) return candidate;
        gpa.free(candidate);
    }
    return null;
}

fn resolveSelfExeAlloc(gpa: Allocator) Error![]u8 {
    if (self_exe_override) |override| {
        return gpa.dupe(u8, override);
    }
    const io = Io.Threaded.global_single_threaded.io();
    const exe_z = std.process.executablePathAlloc(io, gpa) catch return error.HelperNotOnPath;
    defer gpa.free(exe_z);
    return gpa.dupe(u8, exe_z);
}

fn appendCandidateDirUnique(gpa: Allocator, list: *std.ArrayList([]u8), dir: []const u8) Error!void {
    if (dir.len == 0) return;
    for (list.items) |existing| {
        if (pathsEqualForOs(existing, dir)) return;
    }
    const copy = try gpa.dupe(u8, dir);
    errdefer gpa.free(copy);
    try list.append(gpa, copy);
}

fn collectCandidateBinDirsAlloc(gpa: Allocator, self_exe: []const u8) Error![]const []u8 {
    const path_env = getEnvVarOwned(gpa, "PATH") orelse getEnvVarOwned(gpa, "Path") orelse return error.HelperNotOnPath;
    defer gpa.free(path_env);

    var candidates = std.ArrayList([]u8).empty;
    errdefer {
        for (candidates.items) |d| gpa.free(d);
        candidates.deinit(gpa);
    }

    // 1. Prefer `dirname(self_exe)` when already on PATH (e.g. `zig-out/bin` or custom bin dir).
    if (std.fs.path.dirname(self_exe)) |self_dir| {
        if (self_dir.len > 0 and isDirInPathEnv(path_env, self_dir)) {
            try appendCandidateDirUnique(gpa, &candidates, self_dir);
        }
    }

    // 2. Prefer user-local `~/.local/bin` when on PATH ahead of system `/usr/bin` (which may hold Python keyring).
    if (getHomeDir(gpa)) |home| {
        defer gpa.free(home);
        const local_bin = try std.fs.path.join(gpa, &.{ home, ".local", "bin" });
        defer gpa.free(local_bin);
        if (isDirInPathEnv(path_env, local_bin)) {
            try appendCandidateDirUnique(gpa, &candidates, local_bin);
        }
    }

    // 3. Any other PATH directory containing `keyring[.exe]`.
    const kr_name = keyringBinaryName();
    var it = std.mem.splitScalar(u8, path_env, pathListDelimiter());
    while (it.next()) |raw_entry| {
        const entry = std.mem.trim(u8, raw_entry, " \t\"");
        if (entry.len == 0) continue;
        const candidate_kr = std.fs.path.join(gpa, &.{ entry, kr_name }) catch continue;
        defer gpa.free(candidate_kr);
        if (fileExists(candidate_kr)) {
            try appendCandidateDirUnique(gpa, &candidates, entry);
        }
    }

    if (candidates.items.len == 0) {
        return error.HelperNotOnPath;
    }
    return candidates.toOwnedSlice(gpa);
}

fn hashFileSha256(io: Io, path: []const u8) Error![32]u8 {
    const file = Io.Dir.cwd().openFile(io, path, .{}) catch return error.StorageFailure;
    defer file.close(io);

    var reader_buf: [16 * 1024]u8 = undefined;
    var file_reader = file.reader(io, &reader_buf);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});

    var chunk: [16 * 1024]u8 = undefined;
    while (true) {
        const n = file_reader.interface.readSliceShort(&chunk) catch return error.StorageFailure;
        if (n == 0) break;
        hasher.update(chunk[0..n]);
    }
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

/// Ensure `docker-credential-keyring` (`docker-credential-keyring.exe` on Windows)
/// is installed in a directory on `PATH` and matches the running `keyring` binary
/// (`selfExePath`, handling `ghr` shims in `~/.local/bin`, read-only `/usr/bin`
/// fallbacks, and SHA-256 refreshes after same-size upgrades).
pub fn ensureHelperOnPath(gpa: Allocator) Error![]u8 {
    const io = Io.Threaded.global_single_threaded.io();
    const self_exe = try resolveSelfExeAlloc(gpa);
    defer gpa.free(self_exe);

    const candidate_dirs = try collectCandidateBinDirsAlloc(gpa, self_exe);
    defer {
        for (candidate_dirs) |d| gpa.free(d);
        gpa.free(candidate_dirs);
    }

    const src_stat = Io.Dir.cwd().statFile(io, self_exe, .{}) catch return error.StorageFailure;
    var cached_src_hash: ?[32]u8 = null;

    const perms: ?Io.File.Permissions = if (builtin.os.tag == .windows or builtin.os.tag == .wasi)
        null
    else
        .fromMode(0o755);

    for (candidate_dirs) |target_dir| {
        const dest_path = try std.fs.path.join(gpa, &.{ target_dir, helperBinaryName() });
        if (pathsEqualForOs(self_exe, dest_path)) {
            return dest_path;
        }

        if (Io.Dir.cwd().statFile(io, dest_path, .{})) |dst_stat| {
            if (dst_stat.size == src_stat.size and dst_stat.kind == .file) {
                const src_hash = cached_src_hash orelse blk: {
                    const h = try hashFileSha256(io, self_exe);
                    cached_src_hash = h;
                    break :blk h;
                };
                if (hashFileSha256(io, dest_path)) |dst_hash| {
                    if (std.mem.eql(u8, &src_hash, &dst_hash)) {
                        return dest_path;
                    }
                } else |_| {}
            }
        } else |_| {}

        if (Io.Dir.cwd().createDirPathStatus(io, target_dir, .default_dir)) |_| {
            if (!fileExists(dest_path)) {
                if (Io.Dir.cwd().hardLink(self_exe, Io.Dir.cwd(), dest_path, io, .{})) |_| {
                    return dest_path;
                } else |_| {}
            }

            if (Io.Dir.cwd().copyFile(self_exe, Io.Dir.cwd(), dest_path, io, .{
                .permissions = perms,
                .replace = true,
                .make_path = true,
            })) |_| {
                return dest_path;
            } else |_| {}
        } else |_| {}

        gpa.free(dest_path);
    }

    return error.HelperNotOnPath;
}

// ---------------------------------------------------------------------------
// Provider Credential Resolution (GHCR, ACR, Generic, & auth.json Fallback)
// ---------------------------------------------------------------------------

fn readExistingAuthsCredential(
    gpa: Allocator,
    auth_path: ?[]const u8,
    bare_host: []const u8,
) Error!?registry_auth.RegistryCredential {
    const path = auth_path orelse return null;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const bytes = (try registry_auth.readFileIfExists(a, path)) orelse return null;
    defer std.crypto.secureZero(u8, bytes);
    if (bytes.len == 0) return null;

    const root = parseAuthJsonRootLeaky(a, bytes) catch return null;
    const auths_obj = root.get("auths").?.object;
    const entry = auths_obj.get(bare_host) orelse return null;
    if (entry != .object) return null;
    const auth_val = entry.object.get("auth") orelse return null;
    if (auth_val != .string or auth_val.string.len == 0) return null;

    const pair = decodeBasicAuthAlloc(gpa, auth_val.string) catch return null;
    errdefer pair.deinit(gpa);
    if (pair.username.len == 0 or pair.secret.len == 0) {
        pair.deinit(gpa);
        return null;
    }

    const srv = try gpa.dupe(u8, bare_host);
    return .{
        .kind = .basic,
        .server = srv,
        .username = pair.username,
        .secret = pair.secret,
        .expires_at = registry_auth.extractJwtExpiration(gpa, pair.secret),
    };
}

fn mapRegistryAuthError(err: registry_auth.Error) Error {
    return switch (err) {
        error.InvalidServer => error.InvalidServer,
        error.InvalidInput => error.InvalidInput,
        error.EntryNotFound => error.EntryNotFound,
        error.NoStorageAccess => error.NoStorageAccess,
        error.Locked => error.Locked,
        error.StorageFailure => error.StorageFailure,
        error.AuthenticationFailed => error.AuthenticationFailed,
        error.NetworkFailure => error.NetworkFailure,
        error.OutOfMemory => error.OutOfMemory,
    };
}

fn mapArmError(err: ado.Error) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.NoStorageAccess => error.EntryNotFound,
        error.NetworkFailure => error.NetworkFailure,
        else => error.AuthenticationFailed,
    };
}

pub const CredentialOrigin = enum {
    dynamic_provider,
    reused_auths_provider,
    generic_keyring_primary,
    migrated_fallback,
};

pub const ResolvedPodmanCredential = struct {
    credential: registry_auth.RegistryCredential,
    origin: CredentialOrigin,
};

fn lookupStoredOrAuthsFallback(
    gpa: Allocator,
    bare_host: []const u8,
    auth_path: ?[]const u8,
    requested_username: ?[]const u8,
) Error!?ResolvedPodmanCredential {
    const now = activeProviderHooks().nowSeconds();

    if (registry_auth.getGenericCredentialDetailed(gpa, bare_host, requested_username)) |res| {
        if (res.credential.expires_at) |exp| {
            if (exp <= now) {
                res.credential.deinit(gpa);
                return null;
            }
        }
        return .{
            .credential = res.credential,
            .origin = switch (res.source) {
                .primary_container_registry => .generic_keyring_primary,
                .legacy_https_service => .migrated_fallback,
            },
        };
    } else |err| switch (err) {
        error.EntryNotFound => {},
        else => return mapRegistryAuthError(err),
    }

    if (try readExistingAuthsCredential(gpa, auth_path, bare_host)) |existing| {
        if (requested_username == null or std.mem.eql(u8, existing.username, requested_username.?)) {
            if (existing.expires_at) |exp| {
                if (exp <= now) {
                    existing.deinit(gpa);
                    return null;
                }
            }
            return .{
                .credential = existing,
                .origin = .migrated_fallback,
            };
        }
        existing.deinit(gpa);
    }

    return null;
}

pub fn resolvePodmanCredential(
    gpa: Allocator,
    bare_host: []const u8,
    auth_path: ?[]const u8,
    requested_username: ?[]const u8,
    force: bool,
    allow_interactive: bool,
    stderr: *Io.Writer,
) Error!registry_auth.RegistryCredential {
    return (try resolvePodmanCredentialDetailed(
        gpa,
        bare_host,
        auth_path,
        requested_username,
        force,
        allow_interactive,
        stderr,
    )).credential;
}

pub fn resolvePodmanCredentialDetailed(
    gpa: Allocator,
    bare_host: []const u8,
    auth_path: ?[]const u8,
    requested_username: ?[]const u8,
    force: bool,
    allow_interactive: bool,
    stderr: *Io.Writer,
) Error!ResolvedPodmanCredential {
    const hooks = activeProviderHooks();
    const can_interact = allow_interactive and !isNonInteractive(gpa);

    // 1. GitHub Container Registry (`ghcr.io`, `containers.<tenant>.ghe.com`, `docker.<ghes>`).
    if ((registry_auth.resolveGhcrGitHubHostAlloc(gpa, bare_host) catch |err| return mapRegistryAuthError(err))) |gh_host| {
        defer gpa.free(gh_host);

        if (!force) {
            if (registry_auth.getGenericCredentialDetailed(gpa, bare_host, requested_username)) |res| {
                if (res.credential.expires_at == null or res.credential.expires_at.? > hooks.nowSeconds()) {
                    return .{
                        .credential = res.credential,
                        .origin = switch (res.source) {
                            .primary_container_registry => .generic_keyring_primary,
                            .legacy_https_service => .migrated_fallback,
                        },
                    };
                }
                res.credential.deinit(gpa);
            } else |err| switch (err) {
                error.EntryNotFound => {},
                else => return mapRegistryAuthError(err),
            }

            if (can_interact) {
                if (try lookupStoredOrAuthsFallback(gpa, bare_host, auth_path, requested_username)) |existing| {
                    var keep = false;
                    defer if (!keep) existing.credential.deinit(gpa);
                    const probe = hooks.acquireGhCredential(gpa, gh_host, requested_username, false, false, stderr) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.Locked => return error.Locked,
                        else => null,
                    };
                    if (probe) |gh_cred| {
                        gh_cred.deinit(gpa);
                    } else {
                        keep = true;
                        return existing;
                    }
                }
            }

            const maybe_cred = hooks.acquireGhCredential(gpa, gh_host, requested_username, allow_interactive, false, stderr) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Locked => return error.Locked,
                error.NoStorageAccess => return error.NoStorageAccess,
                error.NetworkFailure => return error.NetworkFailure,
                else => {
                    if (try lookupStoredOrAuthsFallback(gpa, bare_host, auth_path, requested_username)) |fb| return fb;
                    return error.AuthenticationFailed;
                },
            };

            if (maybe_cred) |cred| {
                defer cred.deinit(gpa);
                const user = requested_username orelse cred.username;
                const srv_copy = try gpa.dupe(u8, bare_host);
                errdefer gpa.free(srv_copy);
                const usr_copy = try gpa.dupe(u8, user);
                errdefer gpa.free(usr_copy);
                const sec_copy = try gpa.dupe(u8, cred.token);
                return .{
                    .credential = .{
                        .kind = .basic,
                        .server = srv_copy,
                        .username = usr_copy,
                        .secret = sec_copy,
                    },
                    .origin = .dynamic_provider,
                };
            }

            if (try lookupStoredOrAuthsFallback(gpa, bare_host, auth_path, requested_username)) |fb| return fb;
            return error.EntryNotFound;
        }

        // Under `-f`, only keep a generic credential if `requested_username` explicitly targets a legacy `https://` entry;
        // otherwise `login -f ghcr.io` reauthenticates via `gh` and retires any stale `container-registry://ghcr.io` override.
        if (requested_username) |user| {
            if (registry_auth.getGenericCredentialDetailed(gpa, bare_host, user)) |res| {
                if (res.source == .legacy_https_service and
                    (res.credential.expires_at == null or res.credential.expires_at.? > hooks.nowSeconds()))
                {
                    return .{ .credential = res.credential, .origin = .migrated_fallback };
                }
                res.credential.deinit(gpa);
            } else |err| switch (err) {
                error.EntryNotFound => {},
                else => return mapRegistryAuthError(err),
            }
        }

        const maybe_cred = hooks.acquireGhCredential(gpa, gh_host, requested_username, allow_interactive, true, stderr) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.Locked => error.Locked,
            error.NoStorageAccess => error.NoStorageAccess,
            error.NetworkFailure => error.NetworkFailure,
            else => error.AuthenticationFailed,
        };
        const cred = maybe_cred orelse return error.EntryNotFound;
        defer cred.deinit(gpa);

        const user = requested_username orelse cred.username;
        const srv_copy = try gpa.dupe(u8, bare_host);
        errdefer gpa.free(srv_copy);
        const usr_copy = try gpa.dupe(u8, user);
        errdefer gpa.free(usr_copy);
        const sec_copy = try gpa.dupe(u8, cred.token);
        return .{
            .credential = .{
                .kind = .basic,
                .server = srv_copy,
                .username = usr_copy,
                .secret = sec_copy,
            },
            .origin = .dynamic_provider,
        };
    }

    // 2. Azure Container Registry (`*.azurecr.*`).
    if (registry_auth.isAcrServer(bare_host)) {
        if (registry_auth.getGenericCredentialDetailed(gpa, bare_host, requested_username)) |res| {
            const origin: CredentialOrigin = switch (res.source) {
                .primary_container_registry => .generic_keyring_primary,
                .legacy_https_service => .migrated_fallback,
            };
            if (res.credential.expires_at) |exp| {
                const threshold = if (allow_interactive) hooks.nowSeconds() + 300 else hooks.nowSeconds();
                if (!force and exp > threshold) {
                    return .{ .credential = res.credential, .origin = origin };
                }
                res.credential.deinit(gpa);
            } else if (!force or !registry_auth.isAcrSentinelUsername(res.credential.username)) {
                return .{ .credential = res.credential, .origin = origin };
            } else {
                res.credential.deinit(gpa);
            }
        } else |err| switch (err) {
            error.EntryNotFound => {},
            else => return mapRegistryAuthError(err),
        }

        if (requested_username) |user| {
            if (!registry_auth.isAcrSentinelUsername(user)) {
                if (!force) {
                    if (try readExistingAuthsCredential(gpa, auth_path, bare_host)) |existing| {
                        if (std.mem.eql(u8, existing.username, user)) {
                            if (existing.expires_at) |exp| {
                                if (exp > hooks.nowSeconds() + 300) {
                                    return .{ .credential = existing, .origin = .migrated_fallback };
                                }
                            } else {
                                return .{ .credential = existing, .origin = .migrated_fallback };
                            }
                        }
                        existing.deinit(gpa);
                    }
                }
                return error.EntryNotFound;
            }
        }

        if (!force) {
            if (try readExistingAuthsCredential(gpa, auth_path, bare_host)) |existing| {
                if (requested_username == null or std.mem.eql(u8, existing.username, requested_username.?)) {
                    if (existing.expires_at) |exp| {
                        if (exp > hooks.nowSeconds() + 300) {
                            return .{
                                .credential = existing,
                                .origin = if (registry_auth.isAcrSentinelUsername(existing.username))
                                    .reused_auths_provider
                                else
                                    .migrated_fallback,
                            };
                        }
                    } else if (!registry_auth.isAcrSentinelUsername(existing.username)) {
                        return .{ .credential = existing, .origin = .migrated_fallback };
                    }
                }
                existing.deinit(gpa);
            }
        }

        const discovered_tid = hooks.discoverAcrTenant(gpa, bare_host);
        defer if (discovered_tid) |tid| gpa.free(tid);

        const arm_token = hooks.acquireArmTokenForTenant(gpa, stderr, can_interact, force, discovered_tid) catch |err| return mapArmError(err);
        defer {
            std.crypto.secureZero(u8, arm_token);
            gpa.free(arm_token);
        }

        const maybe_tid = if (discovered_tid) |tid|
            try gpa.dupe(u8, tid)
        else
            registry_auth.extractJwtTenantIdAlloc(gpa, arm_token);
        defer if (maybe_tid) |tid| gpa.free(tid);

        const acr_token = hooks.exchangeAcrToken(gpa, bare_host, arm_token, maybe_tid) catch |err| retry: {
            if (err != error.AuthenticationFailed or force) return mapRegistryAuthError(err);

            const refreshed_arm = hooks.acquireArmTokenForTenant(gpa, stderr, can_interact, true, discovered_tid) catch |arm_err| return mapArmError(arm_err);
            defer {
                std.crypto.secureZero(u8, refreshed_arm);
                gpa.free(refreshed_arm);
            }

            const refreshed_tid = if (discovered_tid) |tid|
                try gpa.dupe(u8, tid)
            else
                registry_auth.extractJwtTenantIdAlloc(gpa, refreshed_arm);
            defer if (refreshed_tid) |tid| gpa.free(tid);

            break :retry hooks.exchangeAcrToken(gpa, bare_host, refreshed_arm, refreshed_tid) catch |e2| return mapRegistryAuthError(e2);
        };
        errdefer {
            std.crypto.secureZero(u8, acr_token);
            gpa.free(acr_token);
        }

        const srv_copy = try gpa.dupe(u8, bare_host);
        errdefer gpa.free(srv_copy);
        const usr_copy = try gpa.dupe(u8, registry_auth.acr_token_username);
        return .{
            .credential = .{
                .kind = .basic,
                .server = srv_copy,
                .username = usr_copy,
                .secret = acr_token,
                .expires_at = registry_auth.extractJwtExpiration(gpa, acr_token),
            },
            .origin = .dynamic_provider,
        };
    }

    // 3. Generic OCI registry (`docker.io`, `quay.io`, custom registries).
    if (try lookupStoredOrAuthsFallback(gpa, bare_host, auth_path, requested_username)) |res| {
        return res;
    }
    return error.EntryNotFound;
}

// ---------------------------------------------------------------------------
// Subcommand Execution: login, config, logout, status, credential, diagnose
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
        .config => |opts| runConfig(gpa, opts, stdout, stderr),
        .logout => |opts| runLogout(gpa, opts, stdout, stderr),
        .status => |opts| runStatus(gpa, opts, stdout, stderr),
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

    const paths = resolveAuthFilePaths(a, opts.authfile) catch |err| {
        return reportError(stderr, "podman login", null, err);
    };

    if (opts.password_stdin) {
        const raw_srv = opts.first_server.?;
        const bare_host = registry_auth.normalizeServerAlloc(a, raw_srv, .bare_docker_io) catch {
            try stderr.print("keyring: podman login: invalid registry server '{s}'\n", .{raw_srv});
            try stderr.flush();
            return 2;
        };
        const user = opts.username.?;
        if (std.mem.indexOfScalar(u8, user, ':') != null) {
            try stderr.writeAll("keyring: podman login: username cannot contain ':'\n");
            try stderr.flush();
            return 2;
        }
        const secret = registry_auth.readBoundedStdinLine(a, stdin, registry_auth.max_helper_input_bytes) catch {
            try stderr.writeAll("keyring: podman login: invalid password on stdin\n");
            try stderr.flush();
            return 2;
        };
        defer std.crypto.secureZero(u8, secret);

        if (opts.mode != .helper_only and std.mem.indexOfScalar(u8, secret, ':') != null) {
            try stderr.print(
                "keyring: note: secret for {s} contains ':'; Podman CLI handles this via credHelpers, while Podman Desktop's auth.json parser may truncate at ':'\n",
                .{bare_host},
            );
        }

        // Persist into OS keyring BEFORE enabling `credHelpers` so `docker-credential-keyring get` works immediately.
        if (opts.mode != .auths_only) {
            registry_auth.storeGenericCredential(a, bare_host, user, secret) catch |err| {
                return reportError(stderr, "podman login", bare_host, mapRegistryAuthError(err));
            };
        }

        try maybeProvisionHelper(a, opts.mode, stderr);

        const recs = [_]LoginRecord{.{ .server = bare_host, .username = user, .secret = secret }};
        _ = mutateAuthFileWithCas(a, paths.primary_path, ApplyLoginCtx{
            .records = &recs,
            .mode = opts.mode,
            .force = opts.force,
        }, applyLoginMutation) catch |err| {
            return reportError(stderr, "podman login", bare_host, err);
        };

        if (paths.persistent_helpers_path) |persist_path| {
            const srv_list = [_][]const u8{bare_host};
            if (opts.mode != .auths_only) {
                _ = mutateAuthFileWithCas(a, persist_path, ApplyConfigCtx{ .servers = &srv_list }, applyConfigMutation) catch |err| {
                    return reportError(stderr, "podman login", bare_host, err);
                };
            } else if ((registry_auth.readFileIfExists(a, persist_path) catch |err| {
                return reportError(stderr, "podman login", bare_host, mapRegistryAuthError(err));
            })) |persist_bytes| {
                std.crypto.secureZero(u8, persist_bytes);
                _ = mutateAuthFileWithCas(a, persist_path, RemoveHelpersForAuthsOnlyCtx{
                    .servers = &srv_list,
                    .force = opts.force,
                }, removeHelpersForAuthsOnlyMutation) catch |err| {
                    return reportError(stderr, "podman login", bare_host, err);
                };
            }
        }

        try printLoginSuccess(stdout, bare_host, user, opts.mode);
        try stdout.flush();
        try stderr.flush();
        return 0;
    }

    var target_servers = std.ArrayList([]const u8).empty;
    var srv_it = opts.serverIterator();
    while (srv_it.next()) |srv| {
        const bare_host = registry_auth.normalizeServerAlloc(a, srv, .bare_docker_io) catch {
            try stderr.print("keyring: podman login: invalid registry server '{s}'\n", .{srv});
            try stderr.flush();
            return 2;
        };
        if (!containsString(target_servers.items, bare_host)) {
            try target_servers.append(a, bare_host);
        }
    }

    if (target_servers.items.len == 0) {
        var skipped_scoped: usize = 0;
        try collectConfiguredBareServers(a, paths.primary_path, &target_servers, &skipped_scoped);
        if (paths.persistent_helpers_path) |persist_path| {
            try collectConfiguredBareServers(a, persist_path, &target_servers, &skipped_scoped);
        }
        if (skipped_scoped > 0) {
            try stderr.print(
                "keyring: note: preserved {d} repository-scoped auth.json entry/entries unchanged\n",
                .{skipped_scoped},
            );
        }

        if (target_servers.items.len == 0) {
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
            try stderr.writeAll("keyring: podman login: specify at least one <server> (e.g. 'keyring podman login ghcr.io myregistry.azurecr.io')\n");
            try stderr.flush();
            return 2;
        }
    }

    var resolved = try std.ArrayList(ResolvedPodmanCredential).initCapacity(a, target_servers.items.len);
    defer {
        for (resolved.items) |*r| r.credential.deinit(a);
    }

    var records = try std.ArrayList(LoginRecord).initCapacity(a, target_servers.items.len);
    for (target_servers.items) |bare_host| {
        const res = resolvePodmanCredentialDetailed(
            a,
            bare_host,
            paths.primary_path,
            opts.username,
            opts.force,
            true,
            stderr,
        ) catch |err| {
            return reportError(stderr, "podman login", bare_host, err);
        };
        if (opts.mode != .helper_only and std.mem.indexOfScalar(u8, res.credential.username, ':') != null) {
            res.credential.deinit(a);
            try stderr.print("keyring: podman login: username for {s} cannot contain ':'\n", .{bare_host});
            try stderr.flush();
            return 2;
        }
        try resolved.append(a, res);
    }

    // Sync OS-keyring `container-registry://<host>` BEFORE mutating `auth.json`:
    // - `.migrated_fallback` (`auth.json` `"auths"` or legacy `https://<host>`): persist to `container-registry://<host>`
    //   when enabling `credHelpers` (`opts.mode != .auths_only`) so `--helper-only` never loses the secret!
    // - `.dynamic_provider` (`gh` or Entra `/oauth2/exchange`): retire any stale `container-registry://<host>` entry
    //   so `docker-credential-keyring get` and `list` serve the newly authenticated identity!
    for (resolved.items) |res| {
        switch (res.origin) {
            .migrated_fallback => {
                if (opts.mode != .auths_only) {
                    registry_auth.storeGenericCredential(a, res.credential.server, res.credential.username, res.credential.secret) catch |err| {
                        return reportError(stderr, "podman login", res.credential.server, mapRegistryAuthError(err));
                    };
                }
            },
            .dynamic_provider => {
                registry_auth.deleteGenericCredential(a, res.credential.server) catch |err| switch (err) {
                    error.EntryNotFound, error.NoStorageAccess => {},
                    else => return reportError(stderr, "podman login", res.credential.server, mapRegistryAuthError(err)),
                };
            },
            .generic_keyring_primary, .reused_auths_provider => {},
        }

        try records.append(a, .{
            .server = res.credential.server,
            .username = res.credential.username,
            .secret = res.credential.secret,
        });
    }

    try maybeProvisionHelper(a, opts.mode, stderr);

    _ = mutateAuthFileWithCas(a, paths.primary_path, ApplyLoginCtx{
        .records = records.items,
        .mode = opts.mode,
        .force = opts.force,
    }, applyLoginMutation) catch |err| {
        return reportError(stderr, "podman login", target_servers.items[0], err);
    };

    if (paths.persistent_helpers_path) |persist_path| {
        if (opts.mode != .auths_only) {
            _ = mutateAuthFileWithCas(a, persist_path, ApplyConfigCtx{ .servers = target_servers.items }, applyConfigMutation) catch |err| {
                return reportError(stderr, "podman login", target_servers.items[0], err);
            };
        } else if ((registry_auth.readFileIfExists(a, persist_path) catch |err| {
            return reportError(stderr, "podman login", target_servers.items[0], mapRegistryAuthError(err));
        })) |persist_bytes| {
            std.crypto.secureZero(u8, persist_bytes);
            _ = mutateAuthFileWithCas(a, persist_path, RemoveHelpersForAuthsOnlyCtx{
                .servers = target_servers.items,
                .force = opts.force,
            }, removeHelpersForAuthsOnlyMutation) catch |err| {
                return reportError(stderr, "podman login", target_servers.items[0], err);
            };
        }
    }

    for (records.items) |rec| {
        try printLoginSuccess(stdout, rec.server, rec.username, opts.mode);
    }
    try stdout.flush();
    try stderr.flush();
    return 0;
}

fn maybeProvisionHelper(a: Allocator, mode: LoginMode, stderr: *Io.Writer) Error!void {
    if (mode == .auths_only) return;
    if (ensureHelperOnPath(a)) |helper_path| {
        a.free(helper_path);
        return;
    } else |err| {
        if (mode == .helper_only) return err;
        stderr.print(
            "keyring: warning: could not provision {s} onto PATH ({s}); Podman Desktop auths written, ensure {s} is on PATH for dynamic Podman CLI refresh\n",
            .{ helperBinaryName(), @errorName(err), helperBinaryName() },
        ) catch {};
    }
}

fn printLoginSuccess(stdout: *Io.Writer, server: []const u8, username: []const u8, mode: LoginMode) !void {
    const mode_label = switch (mode) {
        .dual => "Podman Desktop auths + Podman CLI credHelpers",
        .helper_only => "Podman CLI credHelpers only",
        .auths_only => "Podman auths only",
    };
    try stdout.print("Logged in to {s} as {s} ({s})\n", .{ server, username, mode_label });
}

fn collectConfiguredBareServers(
    a: Allocator,
    auth_path: []const u8,
    out: *std.ArrayList([]const u8),
    skipped_scoped: *usize,
) Error!void {
    const bytes = (try registry_auth.readFileIfExists(a, auth_path)) orelse return;
    defer std.crypto.secureZero(u8, bytes);
    if (bytes.len == 0) return;

    const root = try parseAuthJsonRootLeaky(a, bytes);
    const auths_obj = root.get("auths").?.object;
    var it = auths_obj.iterator();
    while (it.next()) |kv| {
        const key = kv.key_ptr.*;
        if (std.mem.indexOfScalar(u8, key, '/') != null) {
            skipped_scoped.* += 1;
            continue;
        }
        const norm = registry_auth.normalizeServerAlloc(a, key, .bare_docker_io) catch continue;
        if (!containsString(out.items, norm)) {
            try out.append(a, norm);
        }
    }

    if (root.get("credHelpers")) |ch_val| {
        if (ch_val == .object) {
            var ch_it = ch_val.object.iterator();
            while (ch_it.next()) |kv| {
                if (kv.value_ptr.* == .string and std.mem.eql(u8, kv.value_ptr.string, helper_value)) {
                    const key = kv.key_ptr.*;
                    if (std.mem.indexOfScalar(u8, key, '/') != null) continue;
                    const norm = registry_auth.normalizeServerAlloc(a, key, .bare_docker_io) catch continue;
                    if (!containsString(out.items, norm)) {
                        try out.append(a, norm);
                    }
                }
            }
        }
    }
}

fn runConfig(
    gpa: Allocator,
    opts: ConfigOptions,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const paths = resolveAuthFilePaths(a, opts.authfile) catch |err| {
        return reportError(stderr, "podman config", null, err);
    };

    var servers = std.ArrayList([]const u8).empty;
    var it = opts.serverIterator();
    while (it.next()) |raw_srv| {
        const bare_host = registry_auth.normalizeServerAlloc(a, raw_srv, .bare_docker_io) catch {
            try stderr.print("keyring: podman config: invalid registry server '{s}'\n", .{raw_srv});
            try stderr.flush();
            return 2;
        };
        if (!containsString(servers.items, bare_host)) {
            try servers.append(a, bare_host);
        }
    }

    const helper_path = ensureHelperOnPath(a) catch |err| {
        return reportError(stderr, "podman config", null, err);
    };
    defer a.free(helper_path);

    _ = mutateAuthFileWithCas(a, paths.primary_path, ApplyConfigCtx{ .servers = servers.items }, applyConfigMutation) catch |err| {
        return reportError(stderr, "podman config", servers.items[0], err);
    };

    if (paths.persistent_helpers_path) |persist_path| {
        _ = mutateAuthFileWithCas(a, persist_path, ApplyConfigCtx{ .servers = servers.items }, applyConfigMutation) catch |err| {
            return reportError(stderr, "podman config", servers.items[0], err);
        };
    }

    for (servers.items) |srv| {
        try stdout.print("Configured Podman credHelpers for {s} -> {s} ({s})\n", .{ srv, helper_value, helper_path });
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

    const paths = resolveAuthFilePaths(a, opts.authfile) catch |err| {
        return reportError(stderr, "podman logout", null, err);
    };

    var servers = std.ArrayList([]const u8).empty;
    if (!opts.all) {
        var it = opts.serverIterator();
        while (it.next()) |raw_srv| {
            const bare_host = registry_auth.normalizeServerAlloc(a, raw_srv, .bare_docker_io) catch {
                try stderr.print("keyring: podman logout: invalid registry server '{s}'\n", .{raw_srv});
                try stderr.flush();
                return 2;
            };
            if (!containsString(servers.items, bare_host)) {
                try servers.append(a, bare_host);
            }
        }
    }

    var removed_servers = std.ArrayList([]u8).empty;
    defer {
        for (removed_servers.items) |s| gpa.free(s);
        removed_servers.deinit(gpa);
    }

    if ((registry_auth.readFileIfExists(a, paths.primary_path) catch |err| {
        return reportError(stderr, "podman logout", null, mapRegistryAuthError(err));
    })) |initial_primary| {
        std.crypto.secureZero(u8, initial_primary);
        _ = mutateAuthFileWithCas(a, paths.primary_path, ApplyLogoutCtx{
            .servers = servers.items,
            .all = opts.all,
            .removed_servers = &removed_servers,
            .gpa = gpa,
        }, applyLogoutMutation) catch |err| {
            return reportError(stderr, "podman logout", null, err);
        };
    }

    if (paths.persistent_helpers_path) |persist_path| {
        if ((registry_auth.readFileIfExists(a, persist_path) catch |err| {
            try stderr.print("keyring: podman logout: failed reading persistent config {s}: {s}\n", .{ persist_path, @errorName(err) });
            try stderr.flush();
            return 1;
        })) |initial_persist| {
            std.crypto.secureZero(u8, initial_persist);
            _ = mutateAuthFileWithCas(a, persist_path, ApplyLogoutCtx{
                .servers = servers.items,
                .all = opts.all,
                .removed_servers = &removed_servers,
                .gpa = gpa,
            }, applyLogoutMutation) catch |err| {
                try stderr.print("keyring: podman logout: failed updating persistent config {s}: {s}\n", .{ persist_path, @errorName(err) });
                try stderr.flush();
                return reportError(stderr, "podman logout", null, err);
            };
        }
    }

    if (opts.all) {
        if (registry_auth.listGenericIndexAlloc(a)) |idx_entries| {
            for (idx_entries) |e| {
                try recordRemovedUnique(gpa, &removed_servers, e.server);
            }
        } else |_| {}

        for (removed_servers.items) |srv| {
            registry_auth.deleteGenericCredential(a, srv) catch |err| switch (err) {
                error.EntryNotFound, error.NoStorageAccess => {},
                else => return reportError(stderr, "podman logout", srv, mapRegistryAuthError(err)),
            };
            try stdout.print("Removed Podman credentials for {s}\n", .{srv});
        }
        if (removed_servers.items.len == 0) {
            try stdout.writeAll("No Podman credentials configured\n");
        }
        try stdout.flush();
        return 0;
    }

    var any_missing = false;
    for (servers.items) |srv| {
        var deleted_generic = true;
        registry_auth.deleteGenericCredential(a, srv) catch |err| switch (err) {
            error.EntryNotFound, error.NoStorageAccess => deleted_generic = false,
            else => return reportError(stderr, "podman logout", srv, mapRegistryAuthError(err)),
        };

        const removed_from_auth = containsString(removed_servers.items, srv);
        if (!removed_from_auth and !deleted_generic) {
            try stderr.print("keyring: podman logout: not logged in to {s}\n", .{srv});
            any_missing = true;
            continue;
        }
        try stdout.print("Removed Podman credentials for {s}\n", .{srv});
    }
    try stdout.flush();
    try stderr.flush();
    return if (any_missing) 3 else 0;
}

fn runStatus(
    gpa: Allocator,
    opts: StatusOptions,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const paths = resolveAuthFilePaths(a, opts.authfile) catch |err| {
        return reportError(stderr, "podman status", null, err);
    };

    try writeStatusReport(a, paths, stdout);
    try stdout.flush();
    return 0;
}

pub fn diagnose(gpa: Allocator, stdout: *Io.Writer) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const paths = resolveAuthFilePaths(a, null) catch return;
    const primary_exists = (registry_auth.readFileIfExists(a, paths.primary_path) catch null) != null;
    const persist_exists = if (paths.persistent_helpers_path) |pp|
        (registry_auth.readFileIfExists(a, pp) catch null) != null
    else
        false;

    if (!primary_exists and !persist_exists and !paths.explicit_override) {
        return;
    }
    try writeStatusReport(a, paths, stdout);
}

fn writeStatusReport(a: Allocator, paths: AuthFilePaths, stdout: *Io.Writer) !void {
    try stdout.print("podman auth.json: {s}\n", .{paths.primary_path});
    if (paths.persistent_helpers_path) |persist_path| {
        try stdout.print("podman persistent credHelpers: {s}\n", .{persist_path});
    }
    if (paths.desktop_path) |dp| {
        if (!paths.explicit_override or pathsEqualForOs(paths.primary_path, dp)) {
            try stdout.writeAll("podman desktop path alignment: aligned\n");
        } else {
            try stdout.print("podman desktop path alignment: diverges (Podman Desktop reads {s})\n", .{dp});
        }
    } else if (effectiveOsTag() == .linux) {
        try stdout.writeAll("podman desktop path alignment: XDG_RUNTIME_DIR unset (headless session)\n");
    }

    if (findHelperOnPathAlloc(a)) |hp| {
        try stdout.print("docker-credential-keyring on PATH: {s}\n", .{hp});
    } else {
        try stdout.writeAll("docker-credential-keyring on PATH: not found (run 'keyring podman config <server>' or 'keyring podman login')\n");
    }

    const maybe_bytes = registry_auth.readFileIfExists(a, paths.primary_path) catch |err| {
        try stdout.print("podman registries: unavailable ({s})\n", .{@errorName(err)});
        return;
    };
    defer if (maybe_bytes) |b| std.crypto.secureZero(u8, b);

    const maybe_persist_bytes: ?[]u8 = if (paths.persistent_helpers_path) |pp|
        registry_auth.readFileIfExists(a, pp) catch null
    else
        null;
    defer if (maybe_persist_bytes) |pb| std.crypto.secureZero(u8, pb);

    if ((maybe_bytes == null or maybe_bytes.?.len == 0) and
        (maybe_persist_bytes == null or maybe_persist_bytes.?.len == 0))
    {
        try stdout.writeAll("podman registries: none configured\n");
        return;
    }

    const root = parseAuthJsonRootLeaky(a, maybe_bytes) catch {
        try stdout.writeAll("podman registries: invalid auth.json\n");
        return;
    };

    const persist_root: ?std.json.ObjectMap = if (maybe_persist_bytes) |pb|
        if (pb.len > 0) parseAuthJsonRootLeaky(a, pb) catch null else null
    else
        null;

    const auths_obj = root.get("auths").?.object;
    const ch_obj: ?std.json.ObjectMap = if (root.get("credHelpers")) |v|
        if (v == .object) v.object else null
    else
        null;
    const persist_ch_obj: ?std.json.ObjectMap = if (persist_root) |pr|
        if (pr.get("credHelpers")) |v| (if (v == .object) v.object else null) else null
    else
        null;

    var all_keys = std.ArrayList([]const u8).empty;
    var auth_it = auths_obj.iterator();
    while (auth_it.next()) |kv| {
        if (!containsString(all_keys.items, kv.key_ptr.*)) {
            try all_keys.append(a, kv.key_ptr.*);
        }
    }
    if (ch_obj) |ch| {
        var ch_it = ch.iterator();
        while (ch_it.next()) |kv| {
            if (!containsString(all_keys.items, kv.key_ptr.*)) {
                try all_keys.append(a, kv.key_ptr.*);
            }
        }
    }
    if (persist_ch_obj) |pch| {
        var pch_it = pch.iterator();
        while (pch_it.next()) |kv| {
            if (!containsString(all_keys.items, kv.key_ptr.*)) {
                try all_keys.append(a, kv.key_ptr.*);
            }
        }
    }

    if (all_keys.items.len == 0) {
        try stdout.writeAll("podman registries: none configured\n");
        return;
    }

    const now = activeProviderHooks().nowSeconds();
    try stdout.print("podman registries ({d}):\n", .{all_keys.items.len});
    for (all_keys.items) |key| {
        const is_scoped = std.mem.indexOfScalar(u8, key, '/') != null;
        var helper_name: ?[]const u8 = if (ch_obj) |ch|
            if (ch.get(key)) |hv| (if (hv == .string) hv.string else null) else null
        else
            null;
        if (helper_name == null) {
            if (persist_ch_obj) |pch| {
                if (pch.get(key)) |hv| {
                    if (hv == .string) helper_name = hv.string;
                }
            }
        }

        var has_auth = false;
        var decoded_pair: ?BasicPair = null;
        defer if (decoded_pair) |p| p.deinit(a);

        if (auths_obj.get(key)) |av| {
            if (av == .object) {
                if (av.object.get("auth")) |astr| {
                    if (astr == .string and astr.string.len > 0) {
                        has_auth = true;
                        decoded_pair = decodeBasicAuthAlloc(a, astr.string) catch null;
                    }
                }
            }
        }

        const mode_str = if (is_scoped)
            "scoped-auths"
        else if (helper_name != null and std.mem.eql(u8, helper_name.?, helper_value) and has_auth)
            "dual (auths + credHelpers)"
        else if (helper_name != null and std.mem.eql(u8, helper_name.?, helper_value))
            "helper-only (credHelpers)"
        else if (helper_name != null)
            "external-helper"
        else if (has_auth)
            "auths-only"
        else
            "empty";

        const user_label = if (decoded_pair) |p| p.username else "-";
        if (decoded_pair) |p| {
            if (registry_auth.extractJwtExpiration(a, p.secret)) |exp| {
                if (exp > now) {
                    const mins = @divFloor(exp - now, 60);
                    try stdout.print("  {s}: mode={s}, user={s}, auths=valid (expires in {d}m)\n", .{
                        key,
                        mode_str,
                        user_label,
                        mins,
                    });
                } else {
                    try stdout.print("  {s}: mode={s}, user={s}, auths=expired (run 'keyring podman login -f {s}')\n", .{
                        key,
                        mode_str,
                        user_label,
                        key,
                    });
                }
                continue;
            }
        }

        try stdout.print("  {s}: mode={s}, user={s}\n", .{ key, mode_str, user_label });
    }
}

fn runCredentialHelper(
    gpa: Allocator,
    op: registry_auth.HelperOperation,
    stdin: *Io.Reader,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    switch (op) {
        .version => {
            try stdout.print("docker-credential-keyring {s}\n", .{app_build_options.version});
            try stdout.flush();
            return 0;
        },
        .get => {
            const raw_server = registry_auth.readBoundedStdinLine(a, stdin, 4096) catch {
                try stdout.writeAll("invalid registry server input\n");
                try stdout.flush();
                return 1;
            };
            const bare_host = registry_auth.normalizeServerAlloc(a, raw_server, .bare_docker_io) catch {
                try stdout.writeAll("invalid registry server URL\n");
                try stdout.flush();
                return 1;
            };
            const maybe_paths = resolveAuthFilePaths(a, null) catch null;
            const auth_path = if (maybe_paths) |p| p.primary_path else null;

            const cred = resolvePodmanCredential(
                a,
                bare_host,
                auth_path,
                null,
                false,
                false,
                stderr,
            ) catch |err| {
                const msg = switch (err) {
                    error.EntryNotFound => registry_auth.helper_not_found_message,
                    error.Locked => "credential store is locked\n",
                    else => "failed to retrieve credentials\n",
                };
                try stdout.writeAll(msg);
                try stdout.flush();
                return 1;
            };
            defer cred.deinit(a);

            try registry_auth.writeHelperGetResponse(gpa, stdout, raw_server, cred.username, cred.secret);
            return 0;
        },
        .store => {
            const payload = registry_auth.parseHelperStoreStdinAlloc(a, stdin) catch {
                try stderr.writeAll("keyring: docker-credential-keyring store: invalid JSON payload\n");
                try stderr.flush();
                return 1;
            };
            defer payload.deinit(a);

            registry_auth.storeGenericCredential(a, payload.server_url, payload.username, payload.secret) catch |err| {
                try stderr.print("keyring: docker-credential-keyring store: {s}\n", .{@errorName(err)});
                try stderr.flush();
                return 1;
            };
            return 0;
        },
        .erase => {
            const raw_server = registry_auth.readBoundedStdinLine(a, stdin, 4096) catch return 1;
            registry_auth.deleteGenericCredential(a, raw_server) catch |err| switch (err) {
                error.EntryNotFound => return 0,
                else => return 1,
            };
            return 0;
        },
        .list => {
            _ = registry_auth.readBoundedStdinAll(a, stdin, 4096) catch {};
            var list_entries = std.ArrayList(registry_auth.RegistryIndexEntry).empty;

            if (registry_auth.listGenericIndexAlloc(a)) |generic_idx| {
                for (generic_idx) |item| {
                    try list_entries.append(a, item);
                }
            } else |_| {}

            if (resolveAuthFilePaths(a, null)) |paths| {
                try appendCredHelperListEntries(a, paths.primary_path, &list_entries, stderr);
                if (paths.persistent_helpers_path) |persist_path| {
                    try appendCredHelperListEntries(a, persist_path, &list_entries, stderr);
                }
            } else |_| {}

            try registry_auth.writeHelperListResponse(a, stdout, list_entries.items);
            return 0;
        },
    }
}

fn appendCredHelperListEntries(
    a: Allocator,
    auth_path: []const u8,
    out: *std.ArrayList(registry_auth.RegistryIndexEntry),
    stderr: *Io.Writer,
) !void {
    const bytes = (registry_auth.readFileIfExists(a, auth_path) catch null) orelse return;
    defer std.crypto.secureZero(u8, bytes);
    if (bytes.len == 0) return;

    const root = parseAuthJsonRootLeaky(a, bytes) catch return;
    const ch_val = root.get("credHelpers") orelse return;
    if (ch_val != .object) return;

    var it = ch_val.object.iterator();
    while (it.next()) |kv| {
        if (kv.value_ptr.* != .string or !std.mem.eql(u8, kv.value_ptr.string, helper_value)) continue;
        const server = kv.key_ptr.*;
        if (containsIndexServer(out.items, server)) continue;

        const user: []const u8 = if (registry_auth.isAcrServer(server))
            registry_auth.acr_token_username
        else if ((registry_auth.resolveGhcrGitHubHostAlloc(a, server) catch null)) |gh_host| blk: {
            if (activeProviderHooks().acquireGhCredential(a, gh_host, null, false, false, stderr) catch null) |cred| {
                defer cred.deinit(a);
                break :blk try a.dupe(u8, cred.username);
            }
            continue;
        } else continue;

        try out.append(a, .{
            .server = try a.dupe(u8, server),
            .username = try a.dupe(u8, user),
        });
    }
}

fn containsIndexServer(entries: []const registry_auth.RegistryIndexEntry, server: []const u8) bool {
    for (entries) |e| {
        if (std.mem.eql(u8, e.server, server)) return true;
    }
    return false;
}

fn containsString(list: []const []const u8, needle: []const u8) bool {
    for (list) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
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

fn reportError(stderr: *Io.Writer, cmd_label: []const u8, maybe_server: ?[]const u8, err: Error) !u8 {
    const target = maybe_server orelse "Podman";
    switch (err) {
        error.EntryNotFound => {
            try stderr.print("keyring: {s}: no credentials found for {s}\n", .{ cmd_label, target });
            try stderr.flush();
            return 3;
        },
        error.Locked => {
            try stderr.print("keyring: {s}: credential store is locked (run 'keyring unlock' first)\n", .{cmd_label});
            try stderr.flush();
            return 1;
        },
        error.ExternalHelperConflict => {
            try stderr.print(
                "keyring: {s}: {s} already uses an external credHelper in auth.json (pass -f to replace it)\n",
                .{ cmd_label, target },
            );
            try stderr.flush();
            return 1;
        },
        error.HelperNotOnPath => {
            try stderr.print(
                "keyring: {s}: could not locate a writable PATH directory containing keyring to provision {s}\n",
                .{ cmd_label, helperBinaryName() },
            );
            try stderr.flush();
            return 1;
        },
        error.NoStorageAccess, error.StorageFailure => {
            try stderr.print("keyring: {s}: storage failure for {s}: {s}\n", .{ cmd_label, target, @errorName(err) });
            try stderr.flush();
            return 4;
        },
        error.InvalidServer, error.InvalidInput => {
            try stderr.print("keyring: {s}: invalid input for {s}\n", .{ cmd_label, target });
            try stderr.flush();
            return 2;
        },
        else => {
            try stderr.print("keyring: {s}: failed to authenticate {s}: {s}\n", .{ cmd_label, target, @errorName(err) });
            try stderr.flush();
            return 1;
        },
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

const TestGenericBackend = struct {
    var map: ?std.StringHashMap([]u8) = null;

    fn reset(gpa: Allocator) void {
        deinit(gpa);
        map = std.StringHashMap([]u8).init(gpa);
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

    fn get(gpa: Allocator, service: []const u8, account: []const u8) @import("keyring_zig").Error![]u8 {
        const m = &(map orelse return error.EntryNotFound);
        const key = std.fmt.allocPrint(gpa, "{s}|{s}", .{ service, account }) catch return error.OutOfMemory;
        defer gpa.free(key);
        const v = m.get(key) orelse return error.EntryNotFound;
        return gpa.dupe(u8, v) catch error.OutOfMemory;
    }

    fn set(_: Allocator, service: []const u8, account: []const u8, password: []const u8) @import("keyring_zig").Error!void {
        var m = &(map orelse return error.PlatformFailure);
        const key = std.fmt.allocPrint(m.allocator, "{s}|{s}", .{ service, account }) catch return error.OutOfMemory;
        errdefer m.allocator.free(key);
        const val = m.allocator.dupe(u8, password) catch return error.OutOfMemory;
        errdefer m.allocator.free(val);
        if (m.fetchPut(key, val) catch return error.OutOfMemory) |prev| {
            m.allocator.free(key);
            std.crypto.secureZero(u8, prev.value);
            m.allocator.free(prev.value);
        }
    }

    fn delete(gpa: Allocator, service: []const u8, account: []const u8) @import("keyring_zig").Error!void {
        var m = &(map orelse return error.EntryNotFound);
        const key = std.fmt.allocPrint(gpa, "{s}|{s}", .{ service, account }) catch return error.OutOfMemory;
        defer gpa.free(key);
        const removed = m.fetchRemove(key) orelse return error.EntryNotFound;
        m.allocator.free(removed.key);
        std.crypto.secureZero(u8, removed.value);
        m.allocator.free(removed.value);
    }
};

const FakeProviders = struct {
    var now_ts: i64 = 1_700_000_000;
    var acr_exchange_calls: usize = 0;
    var interactive_called: bool = false;

    fn reset() void {
        now_ts = 1_700_000_000;
        acr_exchange_calls = 0;
        interactive_called = false;
    }

    fn acquireGh(
        gpa: Allocator,
        gh_host: []const u8,
        requested_username: ?[]const u8,
        allow_interactive: bool,
        _: bool,
        _: *Io.Writer,
    ) gh.AuthError!?gh.GitCredential {
        if (allow_interactive) interactive_called = true;
        if (std.mem.eql(u8, gh_host, "github.com") or std.mem.eql(u8, gh_host, "acme.ghe.com")) {
            const user = try gpa.dupe(u8, requested_username orelse "octocat");
            errdefer gpa.free(user);
            const tok = try gpa.dupe(u8, "gho_test_podman_token");
            return .{ .username = user, .token = tok };
        }
        return null;
    }

    fn acquireArm(
        gpa: Allocator,
        _: *Io.Writer,
        allow_interactive: bool,
        _: bool,
        _: ?[]const u8,
    ) ado.Error![]u8 {
        if (allow_interactive) interactive_called = true;
        // Header {"alg":"none"}.Payload {"tid":"11111111-2222-3333-4444-555555555555","exp":1700003600}.sig
        return gpa.dupe(u8, "eyJhbGciOiJub25lIn0.eyJ0aWQiOiIxMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTUiLCJleHAiOjE3MDAwMDM2MDB9.sig");
    }

    fn discoverAcr(_: Allocator, _: []const u8) ?[]u8 {
        return null;
    }

    fn exchangeAcr(
        gpa: Allocator,
        _: []const u8,
        _: []const u8,
        _: ?[]const u8,
    ) registry_auth.Error![]u8 {
        acr_exchange_calls += 1;
        //ACR refresh JWT with exp = 1700010800 (+3h)
        return gpa.dupe(u8, "eyJhbGciOiJub25lIn0.eyJleHAiOjE3MDAwMTA4MDB9.acr_rt");
    }

    fn now() i64 {
        return now_ts;
    }

    const hooks: ProviderHooks = .{
        .acquireGhCredential = acquireGh,
        .acquireArmTokenForTenant = acquireArm,
        .discoverAcrTenant = discoverAcr,
        .exchangeAcrToken = exchangeAcr,
        .nowSeconds = now,
    };
};

const FakeEnv = struct {
    var home: ?[]const u8 = null;
    var path_val: ?[]const u8 = null;
    var xdg_runtime: ?[]const u8 = null;
    var xdg_config: ?[]const u8 = null;
    var registry_auth_file: ?[]const u8 = null;

    fn reset() void {
        home = null;
        path_val = null;
        xdg_runtime = null;
        xdg_config = null;
        registry_auth_file = null;
    }

    fn get(name: []const u8) ?[]const u8 {
        if (std.mem.eql(u8, name, "HOME") or std.mem.eql(u8, name, "USERPROFILE")) return home;
        if (std.mem.eql(u8, name, "PATH") or std.mem.eql(u8, name, "Path")) return path_val;
        if (std.mem.eql(u8, name, "XDG_RUNTIME_DIR")) return xdg_runtime;
        if (std.mem.eql(u8, name, "XDG_CONFIG_HOME")) return xdg_config;
        if (std.mem.eql(u8, name, "REGISTRY_AUTH_FILE")) return registry_auth_file;
        return null;
    }
};

test "isDockerCredentialArgv0 and parseArgs handle subcommands and flag constraints" {
    try std.testing.expect(isDockerCredentialArgv0("docker-credential-keyring"));
    try std.testing.expect(isDockerCredentialArgv0("/usr/local/bin/docker-credential-keyring"));
    try std.testing.expect(isDockerCredentialArgv0("C:\\Users\\cat\\.local\\bin\\docker-credential-keyring.EXE"));
    try std.testing.expect(!isDockerCredentialArgv0("keyring"));

    const login_cmd = parseArgs(&.{ "login", "ghcr.io", "-f", "myacr.azurecr.io", "--helper-only" }).?;
    try std.testing.expectEqual(@as(usize, 2), login_cmd.login.server_count);
    try std.testing.expect(login_cmd.login.force);
    try std.testing.expectEqual(LoginMode.helper_only, login_cmd.login.mode);

    // Reject conflicting --helper-only + --auths-only
    try std.testing.expect(parseArgs(&.{ "login", "ghcr.io", "--helper-only", "--auths-only" }) == null);
    // Reject logout --all with positional server
    try std.testing.expect(parseArgs(&.{ "logout", "--all", "ghcr.io" }) == null);
    try std.testing.expect(parseArgs(&.{ "credential", "list" }) != null);
}

test "dual-mode login preserves podmanDesktopAlias, unknown keys, and scoped entries, and helper get works noninteractively" {
    const gpa = std.testing.allocator;
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_dir = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    defer gpa.free(root_dir);

    const bin_dir = try std.fs.path.join(gpa, &.{ root_dir, ".local", "bin" });
    defer gpa.free(bin_dir);
    const cache_dir = try std.fs.path.join(gpa, &.{ root_dir, "ghr-cache" });
    defer gpa.free(cache_dir);
    const state_dir = try std.fs.path.join(gpa, &.{ root_dir, "state" });
    defer gpa.free(state_dir);

    _ = try Io.Dir.cwd().createDirPathStatus(io, bin_dir, .default_dir);
    _ = try Io.Dir.cwd().createDirPathStatus(io, cache_dir, .default_dir);

    // Simulate `ghr` layout: shim in `.local/bin/keyring[.exe]` (size 8), real binary in `ghr-cache/keyring[.exe]` (size 24).
    const shim_path = try std.fs.path.join(gpa, &.{ bin_dir, keyringBinaryName() });
    defer gpa.free(shim_path);
    try registry_auth.writeProtectedFileAtomic(gpa, shim_path, "ghr-shim");

    const real_exe = try std.fs.path.join(gpa, &.{ cache_dir, keyringBinaryName() });
    defer gpa.free(real_exe);
    try registry_auth.writeProtectedFileAtomic(gpa, real_exe, "real-keyring-binary-v1.0");

    const auth_path = try std.fs.path.join(gpa, &.{ root_dir, ".config", "containers", "auth.json" });
    defer gpa.free(auth_path);
    try registry_auth.writeProtectedFileAtomic(gpa, auth_path,
        \\{
        \\  "auths": {
        \\    "ghcr.io": {
        \\      "auth": "b2xkOm9sZA==",
        \\      "podmanDesktopAlias": "GitHub Personal"
        \\    },
        \\    "quay.io/myorg/app": {
        \\      "auth": "c2NvcGVkOnNlY3JldA=="
        \\    }
        \\  },
        \\  "credHelpers": {
        \\    "123456.dkr.ecr.us-east-1.amazonaws.com": "ecr-login"
        \\  },
        \\  "HttpHeaders": {
        \\    "User-Agent": "PodmanDesktop/1.30"
        \\  }
        \\}
    );

    TestGenericBackend.reset(gpa);
    defer TestGenericBackend.deinit(gpa);
    registry_auth.generic_store_override = .{
        .get = TestGenericBackend.get,
        .set = TestGenericBackend.set,
        .delete = TestGenericBackend.delete,
    };
    defer registry_auth.generic_store_override = null;

    registry_auth.state_dir_override = state_dir;
    defer registry_auth.state_dir_override = null;

    FakeProviders.reset();
    provider_hooks_override = FakeProviders.hooks;
    defer provider_hooks_override = null;

    FakeEnv.reset();
    FakeEnv.home = root_dir;
    FakeEnv.path_val = bin_dir;
    env_override_fn = FakeEnv.get;
    defer env_override_fn = null;

    self_exe_override = real_exe;
    defer self_exe_override = null;

    var empty_in = Io.Reader.fixed("");
    var out_w = Io.Writer.Allocating.init(gpa);
    defer out_w.deinit();
    var err_w = Io.Writer.Allocating.init(gpa);
    defer err_w.deinit();

    const cmd = parseArgs(&.{ "login", "ghcr.io", "myacr.azurecr.io" }).?;
    const rc = try run(gpa, cmd, &empty_in, &out_w.writer, &err_w.writer);
    try std.testing.expectEqual(@as(u8, 0), rc);
    try std.testing.expectEqual(@as(usize, 1), FakeProviders.acr_exchange_calls);

    // Verify `docker-credential-keyring[.exe]` was provisioned from `real_exe` (24 bytes), NOT `shim_path` (8 bytes)!
    const provisioned_helper = try std.fs.path.join(gpa, &.{ bin_dir, helperBinaryName() });
    defer gpa.free(provisioned_helper);
    const helper_bytes = (try registry_auth.readFileIfExists(gpa, provisioned_helper)).?;
    defer gpa.free(helper_bytes);
    try std.testing.expectEqualStrings("real-keyring-binary-v1.0", helper_bytes);

    // Verify `auth.json` preserved `podmanDesktopAlias`, `quay.io/myorg/app`, `ecr-login`, and `HttpHeaders`,
    // and wrote ACR with `00000000-0000-0000-0000-000000000000` (never `<token>`).
    const updated_auth = (try registry_auth.readFileIfExists(gpa, auth_path)).?;
    defer gpa.free(updated_auth);
    try std.testing.expect(std.mem.indexOf(u8, updated_auth, "\"podmanDesktopAlias\": \"GitHub Personal\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, updated_auth, "\"quay.io/myorg/app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, updated_auth, "\"ecr-login\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, updated_auth, "\"HttpHeaders\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, updated_auth, "\"ghcr.io\": \"keyring\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, updated_auth, "\"myacr.azurecr.io\": \"keyring\"") != null);

    // Second no-arg `keyring podman login` reuses valid ACR JWT without calling `/oauth2/exchange` again,
    // and skips `quay.io/myorg/app` without collapsing it to `quay.io`!
    out_w.clearRetainingCapacity();
    err_w.clearRetainingCapacity();
    const refresh_cmd = parseArgs(&.{"login"}).?;
    const rc2 = try run(gpa, refresh_cmd, &empty_in, &out_w.writer, &err_w.writer);
    try std.testing.expectEqual(@as(u8, 0), rc2);
    try std.testing.expectEqual(@as(usize, 1), FakeProviders.acr_exchange_calls);
    try std.testing.expect(std.mem.indexOf(u8, err_w.written(), "preserved 1 repository-scoped") != null);

    // Noninteractive `credential get` for unconfigured registry returns exact Docker helper miss message on stdout + exit 1.
    FakeProviders.interactive_called = false;
    var miss_in = Io.Reader.fixed("unknown.example.com");
    out_w.clearRetainingCapacity();
    err_w.clearRetainingCapacity();
    const miss_rc = try run(gpa, .{ .credential = .get }, &miss_in, &out_w.writer, &err_w.writer);
    try std.testing.expectEqual(@as(u8, 1), miss_rc);
    try std.testing.expectEqualStrings("credentials not found in native keychain\n", out_w.written());
    try std.testing.expect(!FakeProviders.interactive_called);
}

test "Linux dual-file mode separates tmpfs auths from persistent credHelpers and logout cleans both" {
    const gpa = std.testing.allocator;
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_dir = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    defer gpa.free(root_dir);

    const rt_dir = try std.fs.path.join(gpa, &.{ root_dir, "run-user" });
    defer gpa.free(rt_dir);
    const cfg_dir = try std.fs.path.join(gpa, &.{ root_dir, "xdg-config" });
    defer gpa.free(cfg_dir);
    const bin_dir = try std.fs.path.join(gpa, &.{ root_dir, "bin" });
    defer gpa.free(bin_dir);
    const state_dir = try std.fs.path.join(gpa, &.{ root_dir, "state" });
    defer gpa.free(state_dir);

    _ = try Io.Dir.cwd().createDirPathStatus(io, rt_dir, .default_dir);
    _ = try Io.Dir.cwd().createDirPathStatus(io, cfg_dir, .default_dir);
    _ = try Io.Dir.cwd().createDirPathStatus(io, bin_dir, .default_dir);

    os_tag_override = .linux;
    defer os_tag_override = null;

    const fake_self = try std.fs.path.join(gpa, &.{ bin_dir, "keyring" });
    defer gpa.free(fake_self);
    try registry_auth.writeProtectedFileAtomic(gpa, fake_self, "elf-keyring");
    self_exe_override = fake_self;
    defer self_exe_override = null;

    TestGenericBackend.reset(gpa);
    defer TestGenericBackend.deinit(gpa);
    registry_auth.generic_store_override = .{
        .get = TestGenericBackend.get,
        .set = TestGenericBackend.set,
        .delete = TestGenericBackend.delete,
    };
    defer registry_auth.generic_store_override = null;

    registry_auth.state_dir_override = state_dir;
    defer registry_auth.state_dir_override = null;

    FakeProviders.reset();
    provider_hooks_override = FakeProviders.hooks;
    defer provider_hooks_override = null;

    FakeEnv.reset();
    FakeEnv.home = root_dir;
    FakeEnv.path_val = bin_dir;
    FakeEnv.xdg_runtime = rt_dir;
    FakeEnv.xdg_config = cfg_dir;
    env_override_fn = FakeEnv.get;
    defer env_override_fn = null;

    var pw_in = Io.Reader.fixed("super-secret-pat\n");
    var out_w = Io.Writer.Allocating.init(gpa);
    defer out_w.deinit();
    var err_w = Io.Writer.Allocating.init(gpa);
    defer err_w.deinit();

    const login_cmd = parseArgs(&.{ "login", "-u", "alice", "--password-stdin", "registry.example.com" }).?;
    try std.testing.expectEqual(@as(u8, 0), try run(gpa, login_cmd, &pw_in, &out_w.writer, &err_w.writer));

    const rt_auth_path = try std.fs.path.join(gpa, &.{ rt_dir, "containers", "auth.json" });
    defer gpa.free(rt_auth_path);
    const cfg_auth_path = try std.fs.path.join(gpa, &.{ cfg_dir, "containers", "auth.json" });
    defer gpa.free(cfg_auth_path);

    const rt_bytes = (try registry_auth.readFileIfExists(gpa, rt_auth_path)).?;
    defer gpa.free(rt_bytes);
    const cfg_bytes = (try registry_auth.readFileIfExists(gpa, cfg_auth_path)).?;
    defer gpa.free(cfg_bytes);

    // Runtime `auth.json` has both `auths` and `credHelpers`; persistent `auth.json` has `credHelpers` ONLY (zero secrets)!
    try std.testing.expect(std.mem.indexOf(u8, rt_bytes, "YWxpY2U6c3VwZXItc2VjcmV0LXBhdA==") != null);
    try std.testing.expect(std.mem.indexOf(u8, cfg_bytes, "YWxpY2U6c3VwZXItc2VjcmV0LXBhdA==") == null);
    try std.testing.expect(std.mem.indexOf(u8, cfg_bytes, "\"registry.example.com\": \"keyring\"") != null);

    // `docker-credential-keyring get` resolves `registry.example.com` from OS keyring without username input!
    var get_in = Io.Reader.fixed("registry.example.com");
    out_w.clearRetainingCapacity();
    try std.testing.expectEqual(@as(u8, 0), try run(gpa, .{ .credential = .get }, &get_in, &out_w.writer, &err_w.writer));
    try std.testing.expect(std.mem.indexOf(u8, out_w.written(), "\"Secret\":\"super-secret-pat\"") != null);

    // `logout` removes from BOTH runtime and persistent Linux `auth.json` + OS keyring!
    var empty_in = Io.Reader.fixed("");
    const logout_cmd = parseArgs(&.{ "logout", "registry.example.com" }).?;
    try std.testing.expectEqual(@as(u8, 0), try run(gpa, logout_cmd, &empty_in, &out_w.writer, &err_w.writer));

    const cfg_after = (try registry_auth.readFileIfExists(gpa, cfg_auth_path)).?;
    defer gpa.free(cfg_after);
    try std.testing.expect(std.mem.indexOf(u8, cfg_after, "registry.example.com") == null);
}

test "--auths-only removes owned keyring helper and refuses external helper without --force" {
    const gpa = std.testing.allocator;
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_dir = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    defer gpa.free(root_dir);

    const auth_path = try std.fs.path.join(gpa, &.{ root_dir, "auth.json" });
    defer gpa.free(auth_path);
    try registry_auth.writeProtectedFileAtomic(gpa, auth_path,
        \\{
        \\  "auths": {},
        \\  "credHelpers": {
        \\    "ghcr.io": "keyring",
        \\    "containers.acme.ghe.com": "osxkeychain"
        \\  }
        \\}
    );

    const state_dir = try std.fs.path.join(gpa, &.{ root_dir, "state" });
    defer gpa.free(state_dir);
    registry_auth.state_dir_override = state_dir;
    defer registry_auth.state_dir_override = null;

    FakeProviders.reset();
    provider_hooks_override = FakeProviders.hooks;
    defer provider_hooks_override = null;

    var empty_in = Io.Reader.fixed("");
    var out_w = Io.Writer.Allocating.init(gpa);
    defer out_w.deinit();
    var err_w = Io.Writer.Allocating.init(gpa);
    defer err_w.deinit();

    // Switching `ghcr.io` to `--auths-only` removes owned `"ghcr.io": "keyring"` mapping.
    const c1 = parseArgs(&.{ "login", "--auths-only", "--authfile", auth_path, "ghcr.io" }).?;
    try std.testing.expectEqual(@as(u8, 0), try run(gpa, c1, &empty_in, &out_w.writer, &err_w.writer));
    const after_c1 = (try registry_auth.readFileIfExists(gpa, auth_path)).?;
    defer gpa.free(after_c1);
    try std.testing.expect(std.mem.indexOf(u8, after_c1, "\"ghcr.io\": \"keyring\"") == null);

    // Switching `containers.acme.ghe.com` (mapped to `osxkeychain`) without `-f` fails with ExternalHelperConflict (exit 1).
    const c2 = parseArgs(&.{ "login", "--auths-only", "--authfile", auth_path, "containers.acme.ghe.com" }).?;
    try std.testing.expectEqual(@as(u8, 1), try run(gpa, c2, &empty_in, &out_w.writer, &err_w.writer));
}

test "explicit stored GHCR and ACR credentials take precedence in helper get, same-size upgrades refresh SHA-256, and Linux reboot status shows persistent credHelpers" {
    const gpa = std.testing.allocator;
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_dir = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    defer gpa.free(root_dir);

    const rt_dir = try std.fs.path.join(gpa, &.{ root_dir, "run-user" });
    defer gpa.free(rt_dir);
    const cfg_dir = try std.fs.path.join(gpa, &.{ root_dir, "xdg-config" });
    defer gpa.free(cfg_dir);
    const bin_dir = try std.fs.path.join(gpa, &.{ root_dir, ".local", "bin" });
    defer gpa.free(bin_dir);
    const cache_dir = try std.fs.path.join(gpa, &.{ root_dir, "ghr-cache" });
    defer gpa.free(cache_dir);
    const state_dir = try std.fs.path.join(gpa, &.{ root_dir, "state" });
    defer gpa.free(state_dir);

    _ = try Io.Dir.cwd().createDirPathStatus(io, rt_dir, .default_dir);
    _ = try Io.Dir.cwd().createDirPathStatus(io, cfg_dir, .default_dir);
    _ = try Io.Dir.cwd().createDirPathStatus(io, bin_dir, .default_dir);
    _ = try Io.Dir.cwd().createDirPathStatus(io, cache_dir, .default_dir);

    os_tag_override = .linux;
    defer os_tag_override = null;

    // Create initial helper with exact same 16-byte length ("keyring-ver-0.51") vs upgraded self_exe ("keyring-ver-0.52").
    const helper_dest = try std.fs.path.join(gpa, &.{ bin_dir, "docker-credential-keyring" });
    defer gpa.free(helper_dest);
    try registry_auth.writeProtectedFileAtomic(gpa, helper_dest, "keyring-ver-0.51");

    const upgraded_exe = try std.fs.path.join(gpa, &.{ cache_dir, "keyring" });
    defer gpa.free(upgraded_exe);
    try registry_auth.writeProtectedFileAtomic(gpa, upgraded_exe, "keyring-ver-0.52");
    self_exe_override = upgraded_exe;
    defer self_exe_override = null;

    TestGenericBackend.reset(gpa);
    defer TestGenericBackend.deinit(gpa);
    registry_auth.generic_store_override = .{
        .get = TestGenericBackend.get,
        .set = TestGenericBackend.set,
        .delete = TestGenericBackend.delete,
    };
    defer registry_auth.generic_store_override = null;

    registry_auth.state_dir_override = state_dir;
    defer registry_auth.state_dir_override = null;

    FakeProviders.reset();
    provider_hooks_override = FakeProviders.hooks;
    defer provider_hooks_override = null;

    FakeEnv.reset();
    FakeEnv.home = root_dir;
    FakeEnv.path_val = bin_dir;
    FakeEnv.xdg_runtime = rt_dir;
    FakeEnv.xdg_config = cfg_dir;
    env_override_fn = FakeEnv.get;
    defer env_override_fn = null;

    var out_w = Io.Writer.Allocating.init(gpa);
    defer out_w.deinit();
    var err_w = Io.Writer.Allocating.init(gpa);
    defer err_w.deinit();

    // 1. Store explicit bot PAT for `ghcr.io` (--helper-only) despite `octocat` existing in `gh`!
    var ghcr_in = Io.Reader.fixed("ghp_bot_explicit_secret\n");
    const c_ghcr = parseArgs(&.{ "login", "--helper-only", "-u", "ci-bot", "--password-stdin", "ghcr.io" }).?;
    try std.testing.expectEqual(@as(u8, 0), try run(gpa, c_ghcr, &ghcr_in, &out_w.writer, &err_w.writer));

    // Same-size helper binary must be refreshed to "keyring-ver-0.52"!
    const refreshed_helper = (try registry_auth.readFileIfExists(gpa, helper_dest)).?;
    defer gpa.free(refreshed_helper);
    try std.testing.expectEqualStrings("keyring-ver-0.52", refreshed_helper);

    // `credential get` for `ghcr.io` returns `ci-bot`, NOT `octocat`!
    var get_ghcr = Io.Reader.fixed("ghcr.io");
    out_w.clearRetainingCapacity();
    try std.testing.expectEqual(@as(u8, 0), try run(gpa, .{ .credential = .get }, &get_ghcr, &out_w.writer, &err_w.writer));
    try std.testing.expect(std.mem.indexOf(u8, out_w.written(), "\"Username\":\"ci-bot\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out_w.written(), "\"Secret\":\"ghp_bot_explicit_secret\"") != null);

    // 2. Store explicit non-JWT ACR repository token (--helper-only) and verify `credential get` + `login -f` preserve it!
    var acr_in = Io.Reader.fixed("acr_scope_map_secret_123\n");
    const c_acr = parseArgs(&.{ "login", "--helper-only", "-u", "pull-token", "--password-stdin", "teamacr.azurecr.io" }).?;
    try std.testing.expectEqual(@as(u8, 0), try run(gpa, c_acr, &acr_in, &out_w.writer, &err_w.writer));

    var get_acr = Io.Reader.fixed("teamacr.azurecr.io");
    out_w.clearRetainingCapacity();
    try std.testing.expectEqual(@as(u8, 0), try run(gpa, .{ .credential = .get }, &get_acr, &out_w.writer, &err_w.writer));
    try std.testing.expect(std.mem.indexOf(u8, out_w.written(), "\"Username\":\"pull-token\"") != null);
    try std.testing.expectEqual(@as(usize, 0), FakeProviders.acr_exchange_calls);

    // 3. Simulate Linux reboot by deleting runtime `auth.json` and verify `status` still reports persistent `credHelpers`,
    // and `--auths-only` removes `"keyring"` from persistent `auth.json` too!
    const rt_auth_path = try std.fs.path.join(gpa, &.{ rt_dir, "containers", "auth.json" });
    defer gpa.free(rt_auth_path);
    const cfg_auth_path = try std.fs.path.join(gpa, &.{ cfg_dir, "containers", "auth.json" });
    defer gpa.free(cfg_auth_path);
    Io.Dir.cwd().deleteFile(io, rt_auth_path) catch {};

    var empty_in = Io.Reader.fixed("");
    out_w.clearRetainingCapacity();
    const st_cmd = parseArgs(&.{"status"}).?;
    try std.testing.expectEqual(@as(u8, 0), try run(gpa, st_cmd, &empty_in, &out_w.writer, &err_w.writer));
    try std.testing.expect(std.mem.indexOf(u8, out_w.written(), "teamacr.azurecr.io: mode=helper-only") != null);

    const switch_auths = parseArgs(&.{ "login", "--auths-only", "ghcr.io" }).?;
    try std.testing.expectEqual(@as(u8, 0), try run(gpa, switch_auths, &empty_in, &out_w.writer, &err_w.writer));
    const cfg_after_switch = (try registry_auth.readFileIfExists(gpa, cfg_auth_path)).?;
    defer gpa.free(cfg_after_switch);
    try std.testing.expect(std.mem.indexOf(u8, cfg_after_switch, "\"ghcr.io\"") == null);

    // 4. `login -f ghcr.io` retires the stale `ci-bot` `container-registry://ghcr.io` override so `credential get` serves `octocat`!
    const force_ghcr = parseArgs(&.{ "login", "-f", "ghcr.io" }).?;
    try std.testing.expectEqual(@as(u8, 0), try run(gpa, force_ghcr, &empty_in, &out_w.writer, &err_w.writer));
    var get_ghcr_after_force = Io.Reader.fixed("ghcr.io");
    out_w.clearRetainingCapacity();
    try std.testing.expectEqual(@as(u8, 0), try run(gpa, .{ .credential = .get }, &get_ghcr_after_force, &out_w.writer, &err_w.writer));
    try std.testing.expect(std.mem.indexOf(u8, out_w.written(), "\"Username\":\"octocat\"") != null);

    // 5. Migrating an existing `"auths"` entry (`quay.io`) to `--helper-only` without `--password-stdin` persists it into OS keyring first!
    const seed_auths = parseArgs(&.{ "login", "--auths-only", "-u", "quayuser", "--password-stdin", "quay.io" }).?;
    var quay_in = Io.Reader.fixed("quay_static_secret\n");
    try std.testing.expectEqual(@as(u8, 0), try run(gpa, seed_auths, &quay_in, &out_w.writer, &err_w.writer));

    const migrate_helper = parseArgs(&.{ "login", "--helper-only", "quay.io" }).?;
    try std.testing.expectEqual(@as(u8, 0), try run(gpa, migrate_helper, &empty_in, &out_w.writer, &err_w.writer));
    var get_quay = Io.Reader.fixed("quay.io");
    out_w.clearRetainingCapacity();
    try std.testing.expectEqual(@as(u8, 0), try run(gpa, .{ .credential = .get }, &get_quay, &out_w.writer, &err_w.writer));
    try std.testing.expect(std.mem.indexOf(u8, out_w.written(), "\"Secret\":\"quay_static_secret\"") != null);
}
