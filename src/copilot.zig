//! `keyring copilot` — Cross-platform secure credential management for GitHub
//! Copilot CLI (`copilot`).
//!
//! How Copilot CLI accesses OS secure storage:
//! - **Windows** (`windows-native-keyring-store` 1.1.0, including inside WSL via
//!   `ghr link cataggar/keyring`): Generic credential in Windows Credential
//!   Manager with `TargetName = "<https-host>:<login>.copilot-cli"`, UTF-16LE
//!   `CredentialBlob`, and `UserName = "<https-host>:<login>"` (with read/delete
//!   compatibility for legacy `keytar` `copilot-cli/<https-host>:<login>` UTF-8
//!   targets and `<https-host>:<login>@copilot-cli`).
//! - **macOS** (`apple-native-keyring-store` / `/usr/bin/security`): Generic
//!   password in Keychain with `service = "copilot-cli"`,
//!   `account = "<https-host>:<login>"`, and raw UTF-8 secret bytes.
//! - **Linux** (`zbus-secret-service-keyring-store` 1.0.1): Secret Service item
//!   (`org.freedesktop.secrets`) with attributes `service = "copilot-cli"` and
//!   `username = "<https-host>:<login>"`.
//! - **Config directory**: `$COPILOT_HOME` or `~/.copilot` (`config.json` and
//!   `settings.json`, formatted as JSONC with leading `//` comments).
const std = @import("std");
const builtin = @import("builtin");
const keyring_zig = @import("keyring_zig");
const ado = @import("ado.zig");
const color = @import("color.zig");
const credential_provider = @import("credential_provider.zig");
const gh = @import("gh.zig");
const keychain = @import("keychain.zig");
const registry_auth = @import("registry_auth.zig");
const stored_provider = @import("stored_provider.zig");
const term = @import("term.zig");
const wincred = @import("wincred.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const service_name = "copilot-cli";
pub const config_filename = "config.json";
pub const settings_filename = "settings.json";
pub const copilot_lock_filename = "copilot-config.lock";
pub const config_header_comments =
    "// User settings belong in settings.json.\n" ++
    "// This file is managed automatically.\n";

const cas_max_attempts: usize = 3;

pub const SecretError = error{
    EntryNotFound,
    NoStorageAccess,
    Locked,
    StorageFailure,
    OutOfMemory,
};

pub const Error = SecretError || gh.AuthError || error{
    InvalidInput,
    InvalidJson,
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
var copilot_config_dir_override: ?[]const u8 = null;
var env_override_fn: ?*const fn (name: []const u8) ?[]const u8 = null;
threadlocal var noninteractive_secret_read: bool = false;

pub fn setTestOverrides(
    store: ?SecretStore,
    config_dir: ?[]const u8,
    env_fn: ?*const fn (name: []const u8) ?[]const u8,
) void {
    secret_store_override = store;
    copilot_config_dir_override = config_dir;
    env_override_fn = env_fn;
}

fn activeSecretStore() SecretStore {
    return secret_store_override orelse live_secret_store;
}

pub fn isDefaultNativeStoreActive() bool {
    if (secret_store_override != null) return false;
    if (stored_provider.is_app_backend_disallowed_fn) |disallowed_fn| {
        if (disallowed_fn()) return false;
    }
    return switch (builtin.os.tag) {
        .windows => keyring_zig.currentBackend() == .win_credential,
        .macos => keyring_zig.currentBackend() == .keychain,
        .linux => keyring_zig.currentBackend() == .secret_service,
        else => false,
    };
}

pub const ShellKind = enum {
    sh,
    pwsh,
    cmd,
    fish,

    pub fn fromString(raw: []const u8) ?ShellKind {
        if (std.ascii.eqlIgnoreCase(raw, "sh") or
            std.ascii.eqlIgnoreCase(raw, "bash") or
            std.ascii.eqlIgnoreCase(raw, "zsh"))
        {
            return .sh;
        }
        if (std.ascii.eqlIgnoreCase(raw, "pwsh") or
            std.ascii.eqlIgnoreCase(raw, "powershell"))
        {
            return .pwsh;
        }
        if (std.ascii.eqlIgnoreCase(raw, "cmd") or
            std.ascii.eqlIgnoreCase(raw, "bat"))
        {
            return .cmd;
        }
        if (std.ascii.eqlIgnoreCase(raw, "fish")) {
            return .fish;
        }
        return null;
    }
};

pub const LoginOptions = struct {
    hostname: []const u8 = "github.com",
    username: ?[]const u8 = null,
    mode: gh.LoginMode = .auto,
    force: bool = false,
};

pub const LogoutOptions = struct {
    hostname: ?[]const u8 = null,
    username: ?[]const u8 = null,
    all: bool = false,
};

pub const LookupOptions = struct {
    hostname: ?[]const u8 = null,
    username: ?[]const u8 = null,
};

pub const EnvOptions = struct {
    hostname: ?[]const u8 = null,
    username: ?[]const u8 = null,
    shell: ?ShellKind = null,
};

pub const Subcommand = union(enum) {
    login: LoginOptions,
    logout: LogoutOptions,
    status,
    token: LookupOptions,
    env: EnvOptions,
    import_cmd: struct { source: ?[]const u8 = null },
    export_cmd: struct { dir: []const u8 },
};

pub const AccountSpec = struct {
    host: []const u8,
    login: []const u8,
};

pub const OwnedAccount = struct {
    host: []u8,
    login: []u8,

    pub fn deinit(self: *const OwnedAccount, gpa: Allocator) void {
        gpa.free(self.host);
        gpa.free(self.login);
    }
};

// ---------------------------------------------------------------------------
// CLI Argument Parsing
// ---------------------------------------------------------------------------

pub fn parseArgs(args: []const []const u8) ?Subcommand {
    if (args.len == 0) return null;
    const sub = args[0];
    const rest = args[1..];

    if (std.mem.eql(u8, sub, "login")) {
        return .{ .login = parseLoginArgs(rest) orelse return null };
    }
    if (std.mem.eql(u8, sub, "logout")) {
        return .{ .logout = parseLogoutArgs(rest) orelse return null };
    }
    if (std.mem.eql(u8, sub, "status")) {
        return if (rest.len == 0) .status else null;
    }
    if (std.mem.eql(u8, sub, "token")) {
        return .{ .token = parseLookupArgs(rest) orelse return null };
    }
    if (std.mem.eql(u8, sub, "env")) {
        return .{ .env = parseEnvArgs(rest) orelse return null };
    }
    if (std.mem.eql(u8, sub, "import")) {
        if (rest.len == 0) return .{ .import_cmd = .{ .source = null } };
        if (rest.len == 1 and rest[0].len > 0 and
            (!std.mem.startsWith(u8, rest[0], "-") or std.mem.eql(u8, rest[0], "-")))
        {
            return .{ .import_cmd = .{ .source = rest[0] } };
        }
        return null;
    }
    if (std.mem.eql(u8, sub, "export")) {
        if (rest.len == 1 and rest[0].len > 0 and !std.mem.startsWith(u8, rest[0], "-")) {
            return .{ .export_cmd = .{ .dir = rest[0] } };
        }
        return null;
    }
    return null;
}

fn parseLoginArgs(args: []const []const u8) ?LoginOptions {
    var opts: LoginOptions = .{};
    var saw_web = false;
    var saw_device = false;
    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--hostname")) {
            if (i + 1 >= args.len or hasForbiddenControlOrSpace(args[i + 1])) return null;
            opts.hostname = args[i + 1];
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--hostname=")) {
            const val = arg["--hostname=".len..];
            if (hasForbiddenControlOrSpace(val)) return null;
            opts.hostname = val;
            i += 1;
        } else if (std.mem.eql(u8, arg, "-u") or
            std.mem.eql(u8, arg, "--user") or
            std.mem.eql(u8, arg, "--username"))
        {
            if (i + 1 >= args.len or !isValidLoginInput(args[i + 1])) return null;
            opts.username = args[i + 1];
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--user=")) {
            const val = arg["--user=".len..];
            if (!isValidLoginInput(val)) return null;
            opts.username = val;
            i += 1;
        } else if (std.mem.startsWith(u8, arg, "--username=")) {
            const val = arg["--username=".len..];
            if (!isValidLoginInput(val)) return null;
            opts.username = val;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--web")) {
            if (saw_device) return null;
            saw_web = true;
            opts.mode = .web;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--device")) {
            if (saw_web) return null;
            saw_device = true;
            opts.mode = .device;
            i += 1;
        } else if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--force")) {
            opts.force = true;
            i += 1;
        } else {
            return null;
        }
    }
    return opts;
}

fn parseLogoutArgs(args: []const []const u8) ?LogoutOptions {
    var opts: LogoutOptions = .{};
    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--all")) {
            opts.all = true;
            i += 1;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--hostname")) {
            if (i + 1 >= args.len or hasForbiddenControlOrSpace(args[i + 1])) return null;
            opts.hostname = args[i + 1];
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--hostname=")) {
            const val = arg["--hostname=".len..];
            if (hasForbiddenControlOrSpace(val)) return null;
            opts.hostname = val;
            i += 1;
        } else if (std.mem.eql(u8, arg, "-u") or
            std.mem.eql(u8, arg, "--user") or
            std.mem.eql(u8, arg, "--username"))
        {
            if (i + 1 >= args.len or !isValidLoginInput(args[i + 1])) return null;
            opts.username = args[i + 1];
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--user=")) {
            const val = arg["--user=".len..];
            if (!isValidLoginInput(val)) return null;
            opts.username = val;
            i += 1;
        } else if (std.mem.startsWith(u8, arg, "--username=")) {
            const val = arg["--username=".len..];
            if (!isValidLoginInput(val)) return null;
            opts.username = val;
            i += 1;
        } else {
            return null;
        }
    }
    if (opts.all and (opts.hostname != null or opts.username != null)) return null;
    return opts;
}

fn parseLookupArgs(args: []const []const u8) ?LookupOptions {
    var opts: LookupOptions = .{};
    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--hostname")) {
            if (i + 1 >= args.len or hasForbiddenControlOrSpace(args[i + 1])) return null;
            opts.hostname = args[i + 1];
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--hostname=")) {
            const val = arg["--hostname=".len..];
            if (hasForbiddenControlOrSpace(val)) return null;
            opts.hostname = val;
            i += 1;
        } else if (std.mem.eql(u8, arg, "-u") or
            std.mem.eql(u8, arg, "--user") or
            std.mem.eql(u8, arg, "--username"))
        {
            if (i + 1 >= args.len or !isValidLoginInput(args[i + 1])) return null;
            opts.username = args[i + 1];
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--user=")) {
            const val = arg["--user=".len..];
            if (!isValidLoginInput(val)) return null;
            opts.username = val;
            i += 1;
        } else if (std.mem.startsWith(u8, arg, "--username=")) {
            const val = arg["--username=".len..];
            if (!isValidLoginInput(val)) return null;
            opts.username = val;
            i += 1;
        } else {
            return null;
        }
    }
    return opts;
}

fn parseEnvArgs(args: []const []const u8) ?EnvOptions {
    var opts: EnvOptions = .{};
    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--hostname")) {
            if (i + 1 >= args.len or hasForbiddenControlOrSpace(args[i + 1])) return null;
            opts.hostname = args[i + 1];
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--hostname=")) {
            const val = arg["--hostname=".len..];
            if (hasForbiddenControlOrSpace(val)) return null;
            opts.hostname = val;
            i += 1;
        } else if (std.mem.eql(u8, arg, "-u") or
            std.mem.eql(u8, arg, "--user") or
            std.mem.eql(u8, arg, "--username"))
        {
            if (i + 1 >= args.len or !isValidLoginInput(args[i + 1])) return null;
            opts.username = args[i + 1];
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--user=")) {
            const val = arg["--user=".len..];
            if (!isValidLoginInput(val)) return null;
            opts.username = val;
            i += 1;
        } else if (std.mem.startsWith(u8, arg, "--username=")) {
            const val = arg["--username=".len..];
            if (!isValidLoginInput(val)) return null;
            opts.username = val;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--shell")) {
            if (i + 1 >= args.len) return null;
            opts.shell = ShellKind.fromString(args[i + 1]) orelse return null;
            i += 2;
        } else if (std.mem.startsWith(u8, arg, "--shell=")) {
            opts.shell = ShellKind.fromString(arg["--shell=".len..]) orelse return null;
            i += 1;
        } else {
            return null;
        }
    }
    return opts;
}

// ---------------------------------------------------------------------------
// Host / Account Key Normalization & Config Path Resolution
// ---------------------------------------------------------------------------

fn hasForbiddenControlOrSpace(s: []const u8) bool {
    if (s.len == 0) return true;
    for (s) |c| {
        if (c <= 0x20 or c == 0x7f) return true;
    }
    return false;
}

fn isValidLoginInput(login: []const u8) bool {
    if (hasForbiddenControlOrSpace(login)) return false;
    if (std.mem.indexOfAny(u8, login, "/:") != null) return false;
    return true;
}

fn normalizeValidatedHostnameAlloc(gpa: Allocator, raw_input: []const u8) gh.AuthError![]u8 {
    if (hasForbiddenControlOrSpace(raw_input)) return error.InvalidHostname;
    const canonical = try gh.normalizeHostnameAlloc(gpa, raw_input);
    if (hasForbiddenControlOrSpace(canonical)) {
        gpa.free(canonical);
        return error.InvalidHostname;
    }
    return canonical;
}

pub fn normalizeCopilotHostUrlAlloc(gpa: Allocator, raw_input: []const u8) gh.AuthError![]u8 {
    const canonical = try normalizeValidatedHostnameAlloc(gpa, raw_input);
    defer gpa.free(canonical);
    return std.fmt.allocPrint(gpa, "https://{s}", .{canonical});
}

pub fn extractBareHostAlloc(gpa: Allocator, host_or_url: []const u8) gh.AuthError![]u8 {
    return normalizeValidatedHostnameAlloc(gpa, host_or_url);
}

pub fn formatAccountKeyAlloc(gpa: Allocator, https_host: []const u8, login: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "{s}:{s}", .{ https_host, login });
}

/// Split `"<https_host>:<login>"` (e.g. `"https://github.com:alice"`).
pub fn parseAccountKey(key: []const u8) ?AccountSpec {
    const last_colon = std.mem.lastIndexOfScalar(u8, key, ':') orelse return null;
    if (last_colon == 0 or last_colon + 1 >= key.len) return null;

    const host_part = key[0..last_colon];
    const login_part = key[last_colon + 1 ..];

    if (hasForbiddenControlOrSpace(host_part) or !isValidLoginInput(login_part)) return null;
    if (std.mem.eql(u8, host_part, "https") or std.mem.eql(u8, host_part, "http")) return null;
    if (std.mem.indexOf(u8, host_part, "://")) |scheme_end| {
        if (scheme_end + 3 >= host_part.len) return null;
    }
    return .{ .host = host_part, .login = login_part };
}

fn getEnvVarOwned(gpa: Allocator, name: []const u8) ?[]u8 {
    if (env_override_fn) |override_fn| {
        if (override_fn(name)) |val| return gpa.dupe(u8, val) catch null;
        return null;
    }
    return registry_auth.getEnvVarOwned(gpa, name);
}

fn getHomeDir(gpa: Allocator) ?[]u8 {
    if (builtin.os.tag == .windows) {
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

pub fn resolveCopilotConfigDir(gpa: Allocator) ?[]u8 {
    if (copilot_config_dir_override) |override| {
        return gpa.dupe(u8, override) catch null;
    }
    if (getEnvVarOwned(gpa, "COPILOT_HOME")) |dir| {
        if (dir.len > 0) return dir;
        gpa.free(dir);
    }
    const home = getHomeDir(gpa) orelse return null;
    defer gpa.free(home);
    return std.fs.path.join(gpa, &.{ home, ".copilot" }) catch null;
}

fn resolveLockPath(gpa: Allocator, config_path: []const u8) ![]u8 {
    if (copilot_config_dir_override == null and env_override_fn == null) {
        if (registry_auth.resolveKeyringStateDir(gpa)) |state_dir| {
            defer gpa.free(state_dir);
            return std.fs.path.join(gpa, &.{ state_dir, copilot_lock_filename });
        }
    }
    const parent = std.fs.path.dirname(config_path) orelse ".";
    return std.fs.path.join(gpa, &.{ parent, ".keyring-copilot.lock" });
}

// ---------------------------------------------------------------------------
// JSONC Stripping, Config Parsing, & Protected Atomic Persistence
// ---------------------------------------------------------------------------

/// Strip `//` line comments, `/* ... */` block comments, and trailing commas
/// before `}` or `]`, while preserving string literals (`"https://..."`, `\"`).
pub fn stripJsonCommentsAndTrailingCommasAlloc(gpa: Allocator, raw: []const u8) Error![]u8 {
    var pass1: std.ArrayList(u8) = .empty;
    defer {
        std.crypto.secureZero(u8, pass1.items);
        pass1.deinit(gpa);
    }

    const start_idx: usize = if (std.mem.startsWith(u8, raw, "\xEF\xBB\xBF")) 3 else 0;
    var i: usize = start_idx;
    var in_string = false;

    while (i < raw.len) {
        const c = raw[i];
        if (in_string) {
            try pass1.append(gpa, c);
            if (c == '\\' and i + 1 < raw.len) {
                try pass1.append(gpa, raw[i + 1]);
                i += 2;
                continue;
            }
            if (c == '"') in_string = false;
            i += 1;
            continue;
        }

        if (c == '"') {
            in_string = true;
            try pass1.append(gpa, c);
            i += 1;
            continue;
        }

        if (c == '/' and i + 1 < raw.len and raw[i + 1] == '/') {
            i += 2;
            while (i < raw.len and raw[i] != '\n') : (i += 1) {}
            continue;
        }

        if (c == '/' and i + 1 < raw.len and raw[i + 1] == '*') {
            i += 2;
            while (i + 1 < raw.len and !(raw[i] == '*' and raw[i + 1] == '/')) : (i += 1) {}
            if (i + 1 < raw.len) {
                i += 2;
            } else {
                return error.InvalidJson;
            }
            continue;
        }

        try pass1.append(gpa, c);
        i += 1;
    }

    // Second pass: remove trailing commas outside string literals.
    var out: std.ArrayList(u8) = .empty;
    errdefer {
        std.crypto.secureZero(u8, out.items);
        out.deinit(gpa);
    }

    in_string = false;
    i = 0;
    const src = pass1.items;
    while (i < src.len) {
        const c = src[i];
        if (in_string) {
            try out.append(gpa, c);
            if (c == '\\' and i + 1 < src.len) {
                try out.append(gpa, src[i + 1]);
                i += 2;
                continue;
            }
            if (c == '"') in_string = false;
            i += 1;
            continue;
        }

        if (c == '"') {
            in_string = true;
            try out.append(gpa, c);
            i += 1;
            continue;
        }

        if (c == ',') {
            var look = i + 1;
            while (look < src.len and (src[look] == ' ' or src[look] == '\t' or src[look] == '\r' or src[look] == '\n')) : (look += 1) {}
            if (look < src.len and (src[look] == '}' or src[look] == ']')) {
                i += 1;
                continue;
            }
        }

        try out.append(gpa, c);
        i += 1;
    }

    return out.toOwnedSlice(gpa);
}

fn zeroCopilotTokensInObject(root: *const std.json.ObjectMap) void {
    for ([_][]const u8{ "copilotTokens", "copilot_tokens" }) |field_name| {
        if (root.get(field_name)) |tv| {
            if (tv == .object) {
                for (tv.object.values()) |v| {
                    if (v == .string) {
                        std.crypto.secureZero(u8, @constCast(v.string));
                    }
                }
            }
        }
    }
}

fn zeroSnapshotSecrets(snap: *const ParsedConfigSnapshot) void {
    for (snap.plaintext_tokens.values()) |v| {
        std.crypto.secureZero(u8, @constCast(v));
    }
    for (snap.raw_plaintext_tokens.items) |rt| {
        std.crypto.secureZero(u8, rt.token);
    }
}

fn parseJsoncObjectLeaky(a: Allocator, maybe_bytes: ?[]const u8) Error!std.json.ObjectMap {
    if (maybe_bytes) |bytes| {
        const stripped = try stripJsonCommentsAndTrailingCommasAlloc(a, bytes);
        defer std.crypto.secureZero(u8, stripped);
        const trimmed = std.mem.trim(u8, stripped, " \t\r\n");
        if (trimmed.len > 0) {
            const val = std.json.parseFromSliceLeaky(std.json.Value, a, trimmed, .{
                .allocate = .alloc_always,
            }) catch return error.InvalidJson;
            if (val != .object) return error.InvalidJson;
            return val.object;
        }
    }
    return .empty;
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

fn mutateConfigFileWithCas(
    gpa: Allocator,
    config_path: []const u8,
    ctx: anytype,
    comptime mutateFn: fn (a: Allocator, root: *std.json.ObjectMap, ctx: @TypeOf(ctx)) Error!bool,
) Error!bool {
    const lock_path = resolveLockPath(gpa, config_path) catch return error.OutOfMemory;
    defer gpa.free(lock_path);
    var lock = registry_auth.acquireLockFile(lock_path) catch return error.StorageFailure;
    defer lock.release();

    var attempt: usize = 0;
    while (attempt < cas_max_attempts) : (attempt += 1) {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();

        const initial_bytes = registry_auth.readFileIfExists(a, config_path) catch return error.StorageFailure;
        defer if (initial_bytes) |b| std.crypto.secureZero(u8, b);
        const initial_hash = sha256Bytes(initial_bytes);

        var root = try parseJsoncObjectLeaky(a, initial_bytes);
        defer zeroCopilotTokensInObject(&root);
        const changed = try mutateFn(a, &root, ctx);
        if (!changed and initial_bytes != null) {
            return false;
        }

        const verify_bytes = registry_auth.readFileIfExists(a, config_path) catch return error.StorageFailure;
        defer if (verify_bytes) |b| std.crypto.secureZero(u8, b);
        if (!digestsMatch(initial_hash, sha256Bytes(verify_bytes))) {
            continue;
        }

        const root_val: std.json.Value = .{ .object = root };
        const serialized_json = std.json.Stringify.valueAlloc(a, root_val, .{
            .whitespace = .indent_2,
        }) catch return error.OutOfMemory;
        defer std.crypto.secureZero(u8, serialized_json);

        const serialized = std.fmt.allocPrint(a, "{s}{s}\n", .{ config_header_comments, serialized_json }) catch
            return error.OutOfMemory;
        defer std.crypto.secureZero(u8, serialized);

        registry_auth.writeProtectedFileAtomic(a, config_path, serialized) catch return error.StorageFailure;
        return changed;
    }
    return error.StorageFailure;
}

// ---------------------------------------------------------------------------
// Native OS Secret Store Implementation (Windows / macOS / Linux)
// ---------------------------------------------------------------------------

pub fn encodeWindowsPasswordUtf16LeAlloc(gpa: Allocator, utf8: []const u8) Error![]u8 {
    const utf16_slice = std.unicode.utf8ToUtf16LeAlloc(gpa, utf8) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidInput,
    };
    defer {
        std.crypto.secureZero(u16, utf16_slice);
        gpa.free(utf16_slice);
    }
    const out = try gpa.alloc(u8, utf16_slice.len * 2);
    for (utf16_slice, 0..) |unit, idx| {
        std.mem.writeInt(u16, out[idx * 2 ..][0..2], unit, .little);
    }
    return out;
}

pub fn decodeWindowsUtf16LeBlobAlloc(gpa: Allocator, blob: []const u8) Error![]u8 {
    if (blob.len == 0) return gpa.dupe(u8, "");
    if (blob.len % 2 != 0) return error.StorageFailure;

    var byte_slice = blob;
    if (std.mem.startsWith(u8, byte_slice, "\xFF\xFE")) {
        byte_slice = byte_slice[2..];
    }
    const unit_count = byte_slice.len / 2;
    const units = try gpa.alloc(u16, unit_count);
    defer {
        std.crypto.secureZero(u16, units);
        gpa.free(units);
    }
    for (0..unit_count) |idx| {
        units[idx] = std.mem.readInt(u16, byte_slice[idx * 2 ..][0..2], .little);
    }
    var trimmed_units: []const u16 = units;
    while (trimmed_units.len > 0 and trimmed_units[trimmed_units.len - 1] == 0) {
        trimmed_units = trimmed_units[0 .. trimmed_units.len - 1];
    }
    if (std.mem.indexOfScalar(u16, trimmed_units, 0) != null) return error.StorageFailure;
    return std.unicode.utf16LeToUtf8Alloc(gpa, trimmed_units) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.StorageFailure,
    };
}

pub fn decodeWindowsUtf8BlobAlloc(gpa: Allocator, blob: []const u8) Error![]u8 {
    var trimmed = blob;
    while (trimmed.len > 0 and trimmed[trimmed.len - 1] == 0) {
        trimmed = trimmed[0 .. trimmed.len - 1];
    }
    if (std.mem.indexOfScalar(u8, trimmed, 0) != null) return error.StorageFailure;
    if (!std.unicode.utf8ValidateSlice(trimmed)) return error.StorageFailure;
    return gpa.dupe(u8, trimmed);
}

pub fn decodeWindowsCredentialBlobAlloc(gpa: Allocator, blob: []const u8) Error![]u8 {
    if (blob.len == 0) return gpa.dupe(u8, "");
    if (looksLikeUtf16LePassword(blob)) {
        return decodeWindowsUtf16LeBlobAlloc(gpa, blob);
    }
    return decodeWindowsUtf8BlobAlloc(gpa, blob);
}

fn looksLikeUtf16LePassword(blob: []const u8) bool {
    if (blob.len < 2 or blob.len % 2 != 0) return false;
    if (std.mem.startsWith(u8, blob, "\xFF\xFE")) return true;
    // Any ASCII UTF-16LE string has 0x00 in odd byte positions, whereas a valid
    // UTF-8 token never contains embedded 0x00 bytes before the end.
    if (std.mem.indexOfScalar(u8, blob[0 .. blob.len - 1], 0) != null) {
        return true;
    }
    return !std.unicode.utf8ValidateSlice(blob);
}

fn windowsDotTargetAlloc(gpa: Allocator, service: []const u8, account: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "{s}.{s}", .{ account, service });
}

fn windowsKeytarTargetAlloc(gpa: Allocator, service: []const u8, account: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "{s}/{s}", .{ service, account });
}

fn windowsAtTargetAlloc(gpa: Allocator, service: []const u8, account: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "{s}@{s}", .{ account, service });
}

fn mapProviderPreflightError(err: credential_provider.ProviderError) SecretError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.StorageLocked => error.Locked,
        error.StorageUnavailable, error.AccessDenied => error.NoStorageAccess,
        else => error.StorageFailure,
    };
}

fn preflightLiveSecretBackend(
    gpa: Allocator,
    interaction: credential_provider.InteractionPolicy,
) SecretError!void {
    stored_provider.checkSecureBackendAvailable(gpa) catch |err| return mapProviderPreflightError(err);
    const persistence = stored_provider.defaultKeyringPersistence();
    persistence.checkAvailableFn(persistence.ctx, gpa, .{
        .interaction = interaction,
    }) catch |err| return mapProviderPreflightError(err);
}

fn liveSecretGet(gpa: Allocator, service: []const u8, account: []const u8) SecretError![]u8 {
    try preflightLiveSecretBackend(gpa, if (noninteractive_secret_read) .never else .if_available);

    if (builtin.os.tag == .windows and keyring_zig.currentBackend() == .win_credential) {
        const target_dot = windowsDotTargetAlloc(gpa, service, account) catch return error.OutOfMemory;
        defer gpa.free(target_dot);
        if (wincred.get(gpa, target_dot)) |raw| {
            defer {
                std.crypto.secureZero(u8, raw);
                gpa.free(raw);
            }
            return decodeWindowsUtf16LeBlobAlloc(gpa, raw) catch |err| switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.StorageFailure,
            };
        } else |err| switch (err) {
            error.EntryNotFound => {},
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.NoStorageAccess,
        }

        const target_slash = windowsKeytarTargetAlloc(gpa, service, account) catch return error.OutOfMemory;
        defer gpa.free(target_slash);
        if (wincred.get(gpa, target_slash)) |raw| {
            defer {
                std.crypto.secureZero(u8, raw);
                gpa.free(raw);
            }
            return decodeWindowsUtf8BlobAlloc(gpa, raw) catch |err| switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.StorageFailure,
            };
        } else |err| switch (err) {
            error.EntryNotFound => {},
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.NoStorageAccess,
        }

        const target_at = windowsAtTargetAlloc(gpa, service, account) catch return error.OutOfMemory;
        defer gpa.free(target_at);
        if (wincred.get(gpa, target_at)) |raw| {
            defer {
                std.crypto.secureZero(u8, raw);
                gpa.free(raw);
            }
            return decodeWindowsUtf8BlobAlloc(gpa, raw) catch |err| switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.StorageFailure,
            };
        } else |err| return switch (err) {
            error.EntryNotFound => error.EntryNotFound,
            error.OutOfMemory => error.OutOfMemory,
            else => error.NoStorageAccess,
        };
    }

    if (builtin.os.tag == .macos and keyring_zig.currentBackend() == .keychain) {
        if (macosSecurityGetRaw(gpa, service, account)) |raw| {
            return raw;
        } else |sec_err| switch (sec_err) {
            error.EntryNotFound => return error.EntryNotFound,
            error.OutOfMemory => return error.OutOfMemory,
            error.NoStorageAccess, error.StorageFailure, error.Locked => {
                return keychain.get(gpa, service, account) catch |err| switch (err) {
                    error.EntryNotFound => error.EntryNotFound,
                    error.OutOfMemory => error.OutOfMemory,
                    error.NoStorageAccess => error.NoStorageAccess,
                    error.StorageFailure => error.StorageFailure,
                };
            },
        }
    }

    return keyring_zig.getAlloc(gpa, service, account) catch |err| switch (err) {
        error.EntryNotFound => error.EntryNotFound,
        error.Locked => error.Locked,
        error.OutOfMemory => error.OutOfMemory,
        else => error.NoStorageAccess,
    };
}

fn liveSecretSet(gpa: Allocator, service: []const u8, account: []const u8, value: []const u8) SecretError!void {
    try preflightLiveSecretBackend(gpa, .if_available);

    if (builtin.os.tag == .windows and keyring_zig.currentBackend() == .win_credential) {
        const target_dot = windowsDotTargetAlloc(gpa, service, account) catch return error.OutOfMemory;
        defer gpa.free(target_dot);
        const encoded = encodeWindowsPasswordUtf16LeAlloc(gpa, value) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.StorageFailure,
        };
        defer {
            std.crypto.secureZero(u8, encoded);
            gpa.free(encoded);
        }
        wincred.set(gpa, target_dot, account, encoded) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.StorageFailure,
        };

        // Best-effort cleanup of any stale legacy keytar or `@copilot-cli` targets for the same account.
        if (windowsKeytarTargetAlloc(gpa, service, account)) |target_slash| {
            defer gpa.free(target_slash);
            wincred.delete(gpa, target_slash) catch {};
        } else |_| {}
        if (windowsAtTargetAlloc(gpa, service, account)) |target_at| {
            defer gpa.free(target_at);
            wincred.delete(gpa, target_at) catch {};
        } else |_| {}
        return;
    }

    if (builtin.os.tag == .macos and keyring_zig.currentBackend() == .keychain) {
        if (macosSecuritySetRaw(gpa, service, account, value)) |_| {
            return;
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return keychain.set(service, account, value) catch |kerr| switch (kerr) {
                error.NoStorageAccess => error.NoStorageAccess,
                error.OutOfMemory => error.OutOfMemory,
                else => error.StorageFailure,
            },
        }
    }

    if (builtin.os.tag == .linux and keyring_zig.currentBackend() == .secret_service) {
        // Copilot CLI (`zbus-secret-service-keyring-store`) stores 2 attributes
        // (`service`, `username`), whereas `keyring_zig` adds `xdg:schema`. Delete
        // any existing matching items first so `CreateItem` never leaves 2 items
        // that cause `Error::Ambiguous` in Copilot CLI.
        for (0..64) |_| {
            keyring_zig.deleteAlloc(gpa, service, account) catch |err| switch (err) {
                error.EntryNotFound => break,
                error.Locked => return error.Locked,
                error.NoStorageAccess => return error.NoStorageAccess,
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.StorageFailure,
            };
        }
        return keyring_zig.setAlloc(gpa, service, account, value) catch |err| switch (err) {
            error.Locked => error.Locked,
            error.NoStorageAccess => error.NoStorageAccess,
            error.OutOfMemory => error.OutOfMemory,
            else => error.StorageFailure,
        };
    }

    return keyring_zig.setAlloc(gpa, service, account, value) catch |err| switch (err) {
        error.Locked => error.Locked,
        error.OutOfMemory => error.OutOfMemory,
        else => error.NoStorageAccess,
    };
}

fn liveSecretDelete(gpa: Allocator, service: []const u8, account: []const u8) SecretError!void {
    try preflightLiveSecretBackend(gpa, .if_available);

    if (builtin.os.tag == .windows and keyring_zig.currentBackend() == .win_credential) {
        var deleted_any = false;
        const target_dot = windowsDotTargetAlloc(gpa, service, account) catch return error.OutOfMemory;
        defer gpa.free(target_dot);
        if (wincred.delete(gpa, target_dot)) |_| {
            deleted_any = true;
        } else |err| switch (err) {
            error.EntryNotFound => {},
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.StorageFailure,
        }

        const target_slash = windowsKeytarTargetAlloc(gpa, service, account) catch return error.OutOfMemory;
        defer gpa.free(target_slash);
        if (wincred.delete(gpa, target_slash)) |_| {
            deleted_any = true;
        } else |err| switch (err) {
            error.EntryNotFound => {},
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.StorageFailure,
        }

        const target_at = windowsAtTargetAlloc(gpa, service, account) catch return error.OutOfMemory;
        defer gpa.free(target_at);
        if (wincred.delete(gpa, target_at)) |_| {
            deleted_any = true;
        } else |err| switch (err) {
            error.EntryNotFound => {},
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.StorageFailure,
        }

        if (!deleted_any) return error.EntryNotFound;
        return;
    }

    if (builtin.os.tag == .macos and keyring_zig.currentBackend() == .keychain) {
        if (macosSecurityDelete(gpa, service, account)) return;
        return keychain.delete(service, account) catch |err| switch (err) {
            error.EntryNotFound => error.EntryNotFound,
            error.OutOfMemory => error.OutOfMemory,
            else => error.StorageFailure,
        };
    }

    if (builtin.os.tag == .linux and keyring_zig.currentBackend() == .secret_service) {
        var deleted_count: usize = 0;
        for (0..64) |_| {
            if (keyring_zig.deleteAlloc(gpa, service, account)) |_| {
                deleted_count += 1;
            } else |err| switch (err) {
                error.EntryNotFound => break,
                error.Locked => return error.Locked,
                error.NoStorageAccess => return error.NoStorageAccess,
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.StorageFailure,
            }
        }
        if (deleted_count == 0) return error.EntryNotFound;
        return;
    }

    return keyring_zig.deleteAlloc(gpa, service, account) catch |err| switch (err) {
        error.EntryNotFound => error.EntryNotFound,
        error.Locked => error.Locked,
        error.OutOfMemory => error.OutOfMemory,
        else => error.NoStorageAccess,
    };
}

fn macosSecurityGetRaw(gpa: Allocator, service: []const u8, account: []const u8) SecretError![]u8 {
    var threaded = Io.Threaded.init(gpa, .{ .environ = ado.currentProcessEnviron() });
    defer threaded.deinit();
    const io = threaded.io();

    const argv = [_][]const u8{
        "/usr/bin/security",
        "find-generic-password",
        "-s",
        service,
        "-wa",
        account,
    };
    const result = std.process.run(gpa, io, .{
        .argv = &argv,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    }) catch return error.NoStorageAccess;
    defer gpa.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code != 0) {
            std.crypto.secureZero(u8, result.stdout);
            gpa.free(result.stdout);
            if (code == 44) return error.EntryNotFound;
            return error.NoStorageAccess;
        },
        else => {
            std.crypto.secureZero(u8, result.stdout);
            gpa.free(result.stdout);
            return error.NoStorageAccess;
        },
    }

    var trimmed: []const u8 = result.stdout;
    if (std.mem.endsWith(u8, trimmed, "\r\n")) {
        trimmed = trimmed[0 .. trimmed.len - 2];
    } else if (std.mem.endsWith(u8, trimmed, "\n")) {
        trimmed = trimmed[0 .. trimmed.len - 1];
    }
    const copy = gpa.dupe(u8, trimmed) catch {
        std.crypto.secureZero(u8, result.stdout);
        gpa.free(result.stdout);
        return error.OutOfMemory;
    };
    std.crypto.secureZero(u8, result.stdout);
    gpa.free(result.stdout);
    return copy;
}

fn validateMacosSecurityIdentifier(s: []const u8) Error!void {
    if (s.len == 0) return error.InvalidInput;
    for (s) |c| {
        if (c <= 0x20 or c >= 0x7f or c == '\'' or c == '"' or c == '\\') {
            return error.InvalidInput;
        }
    }
}

pub fn buildMacosSecurityAddHexCommandAlloc(
    gpa: Allocator,
    service: []const u8,
    account: []const u8,
    raw_secret: []const u8,
) Error![]u8 {
    try validateMacosSecurityIdentifier(service);
    try validateMacosSecurityIdentifier(account);

    if (raw_secret.len == 0) {
        return std.fmt.allocPrint(
            gpa,
            "add-generic-password -U -s '{s}' -a '{s}' -w ''\n",
            .{ service, account },
        );
    }

    const hex_alphabet = "0123456789abcdef";
    var out: std.ArrayList(u8) = .empty;
    errdefer {
        std.crypto.secureZero(u8, out.items);
        out.deinit(gpa);
    }
    const prefix = "add-generic-password -U -s '";
    const mid = "' -a '";
    const flag = "' -X ";
    try out.ensureTotalCapacity(gpa, prefix.len + service.len + mid.len + account.len + flag.len + raw_secret.len * 2 + 1);
    out.appendSliceAssumeCapacity(prefix);
    out.appendSliceAssumeCapacity(service);
    out.appendSliceAssumeCapacity(mid);
    out.appendSliceAssumeCapacity(account);
    out.appendSliceAssumeCapacity(flag);
    for (raw_secret) |b| {
        out.appendAssumeCapacity(hex_alphabet[b >> 4]);
        out.appendAssumeCapacity(hex_alphabet[b & 0x0f]);
    }
    out.appendAssumeCapacity('\n');
    return out.toOwnedSlice(gpa);
}

fn macosSecuritySetRaw(gpa: Allocator, service: []const u8, account: []const u8, raw_value: []const u8) SecretError!void {
    var threaded = Io.Threaded.init(gpa, .{ .environ = ado.currentProcessEnviron() });
    defer threaded.deinit();
    const io = threaded.io();

    const cmd = buildMacosSecurityAddHexCommandAlloc(gpa, service, account, raw_value) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.StorageFailure,
    };
    defer {
        std.crypto.secureZero(u8, cmd);
        gpa.free(cmd);
    }

    var child = std.process.spawn(io, .{
        .argv = &.{ "/usr/bin/security", "-i" },
        .stdin = .pipe,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return error.StorageFailure;

    if (child.stdin) |stdin_file| {
        stdin_file.writeStreamingAll(io, cmd) catch {
            stdin_file.close(io);
            child.stdin = null;
            _ = child.wait(io) catch {};
            return error.StorageFailure;
        };
        stdin_file.close(io);
        child.stdin = null;
    }

    const proc_term = child.wait(io) catch return error.StorageFailure;
    if (proc_term != .exited or proc_term.exited != 0) return error.StorageFailure;
}

fn macosSecurityDelete(gpa: Allocator, service: []const u8, account: []const u8) bool {
    var threaded = Io.Threaded.init(gpa, .{ .environ = ado.currentProcessEnviron() });
    defer threaded.deinit();
    const io = threaded.io();

    const argv = [_][]const u8{
        "/usr/bin/security",
        "delete-generic-password",
        "-s",
        service,
        "-a",
        account,
    };
    const result = std.process.run(gpa, io, .{
        .argv = &argv,
        .stdout_limit = .limited(16 * 1024),
        .stderr_limit = .limited(16 * 1024),
    }) catch return false;
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

// ---------------------------------------------------------------------------
// Config Model Helpers (`loggedInUsers`, `lastLoggedInUser`, `copilotTokens`)
// ---------------------------------------------------------------------------

const RawTokenEntry = struct {
    key: []const u8,
    token: []u8,
};

const ParsedConfigSnapshot = struct {
    last_user: ?AccountSpec = null,
    users: std.ArrayListUnmanaged(AccountSpec) = .empty,
    plaintext_tokens: std.StringArrayHashMapUnmanaged([]const u8) = .empty,
    raw_plaintext_tokens: std.ArrayListUnmanaged(RawTokenEntry) = .empty,
};

fn extractAccountObject(val: std.json.Value) ?AccountSpec {
    if (val != .object) return null;
    const host_v = val.object.get("host") orelse return null;
    const login_v = val.object.get("login") orelse return null;
    if (host_v != .string or login_v != .string) return null;
    if (hasForbiddenControlOrSpace(host_v.string) or !isValidLoginInput(login_v.string)) return null;
    return .{ .host = host_v.string, .login = login_v.string };
}

fn appendUniqueAccountLeaky(a: Allocator, list: *std.ArrayListUnmanaged(AccountSpec), spec: AccountSpec) !void {
    const norm_host = normalizeCopilotHostUrlAlloc(a, spec.host) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return,
    };
    for (list.items) |existing| {
        if (std.ascii.eqlIgnoreCase(existing.host, norm_host) and
            std.ascii.eqlIgnoreCase(existing.login, spec.login))
        {
            return;
        }
    }
    try list.append(a, .{ .host = norm_host, .login = spec.login });
}

fn readConfigSnapshotLeaky(a: Allocator, root: std.json.ObjectMap) !ParsedConfigSnapshot {
    var snap: ParsedConfigSnapshot = .{};

    const last_val = root.get("lastLoggedInUser") orelse root.get("last_logged_in_user");
    if (last_val) |lv| {
        if (extractAccountObject(lv)) |spec| {
            if (normalizeCopilotHostUrlAlloc(a, spec.host)) |norm_host| {
                snap.last_user = .{ .host = norm_host, .login = spec.login };
            } else |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {},
            }
        }
    }

    const users_val = root.get("loggedInUsers") orelse root.get("logged_in_users");
    if (users_val) |uv| {
        if (uv == .array) {
            for (uv.array.items) |item| {
                if (extractAccountObject(item)) |spec| {
                    try appendUniqueAccountLeaky(a, &snap.users, spec);
                }
            }
        }
    }

    for ([_][]const u8{ "copilotTokens", "copilot_tokens" }) |field_name| {
        if (root.get(field_name)) |tv| {
            if (tv == .object) {
                var it = tv.object.iterator();
                while (it.next()) |entry| {
                    if (entry.value_ptr.* != .string) continue;
                    const raw_tok = entry.value_ptr.*.string;
                    if (std.mem.indexOfAny(u8, raw_tok, "\r\n\x00") != null) continue;
                    const tok = std.mem.trim(u8, raw_tok, " \t");
                    if (tok.len == 0) continue;
                    if (parseAccountKey(entry.key_ptr.*)) |parsed| {
                        const norm_host = normalizeCopilotHostUrlAlloc(a, parsed.host) catch |err| switch (err) {
                            error.OutOfMemory => return error.OutOfMemory,
                            else => continue,
                        };
                        try snap.raw_plaintext_tokens.append(a, .{
                            .key = try a.dupe(u8, entry.key_ptr.*),
                            .token = try a.dupe(u8, tok),
                        });
                        const norm_key = try formatAccountKeyAlloc(a, norm_host, parsed.login);
                        const tok_copy = try a.dupe(u8, tok);
                        const gop = try snap.plaintext_tokens.getOrPut(a, norm_key);
                        if (gop.found_existing) {
                            std.crypto.secureZero(u8, @constCast(gop.value_ptr.*));
                        }
                        gop.value_ptr.* = tok_copy;
                        try appendUniqueAccountLeaky(a, &snap.users, .{ .host = norm_host, .login = parsed.login });
                    }
                }
            }
        }
    }

    if (snap.last_user) |lu| {
        try appendUniqueAccountLeaky(a, &snap.users, lu);
    }

    return snap;
}

fn resolveCanonicalLogin(snap: ParsedConfigSnapshot, https_host: []const u8, requested: []const u8) []const u8 {
    if (snap.last_user) |lu| {
        if (sameHost(lu.host, https_host) and std.ascii.eqlIgnoreCase(lu.login, requested)) {
            return lu.login;
        }
    }
    for (snap.users.items) |u| {
        if (sameHost(u.host, https_host) and std.ascii.eqlIgnoreCase(u.login, requested)) {
            return u.login;
        }
    }
    return requested;
}

fn readStoreTokenPlaintextSetting(gpa: Allocator, config_dir: []const u8) bool {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    for ([_][]const u8{ settings_filename, config_filename }) |fname| {
        const path = std.fs.path.join(a, &.{ config_dir, fname }) catch continue;
        const bytes = (registry_auth.readFileIfExists(a, path) catch null) orelse continue;
        defer std.crypto.secureZero(u8, bytes);
        const root = parseJsoncObjectLeaky(a, bytes) catch continue;
        defer zeroCopilotTokensInObject(&root);
        const v = root.get("storeTokenPlaintext") orelse root.get("store_token_plaintext") orelse continue;
        if (v == .bool) return v.bool;
    }
    return false;
}

fn makeAccountJsonValueLeaky(a: Allocator, host: []const u8, login: []const u8) !std.json.Value {
    var obj: std.json.ObjectMap = .empty;
    try obj.put(a, "host", .{ .string = try a.dupe(u8, host) });
    try obj.put(a, "login", .{ .string = try a.dupe(u8, login) });
    return .{ .object = obj };
}

fn findSnapshotPlaintextToken(
    snap: ParsedConfigSnapshot,
    https_host: []const u8,
    login: []const u8,
    exact_key: []const u8,
) ?[]const u8 {
    if (snap.plaintext_tokens.get(exact_key)) |pt| return pt;
    var matched: ?[]const u8 = null;
    for (snap.raw_plaintext_tokens.items) |rt| {
        const parsed = parseAccountKey(rt.key) orelse continue;
        if (sameHost(parsed.host, https_host) and std.ascii.eqlIgnoreCase(parsed.login, login)) {
            matched = rt.token;
        }
    }
    return matched;
}

fn hasMatchingExpectedToken(
    exp_map: ?*const std.StringArrayHashMapUnmanaged([]const u8),
    exp_raw: []const RawTokenEntry,
    https_host: []const u8,
    login: []const u8,
    current_token: []const u8,
) bool {
    for (exp_raw) |raw_entry| {
        const parsed = parseAccountKey(raw_entry.key) orelse continue;
        if (sameHost(parsed.host, https_host) and std.ascii.eqlIgnoreCase(parsed.login, login)) {
            if (std.mem.eql(u8, raw_entry.token, current_token)) return true;
        }
    }
    if (exp_map) |m| {
        var it = m.iterator();
        while (it.next()) |entry| {
            const parsed = parseAccountKey(entry.key_ptr.*) orelse continue;
            if (sameHost(parsed.host, https_host) and std.ascii.eqlIgnoreCase(parsed.login, login)) {
                if (std.mem.eql(u8, entry.value_ptr.*, current_token)) return true;
            }
        }
    }
    return false;
}

fn scrubPlaintextFromRoot(
    root: *std.json.ObjectMap,
    https_host: []const u8,
    maybe_login: ?[]const u8,
    expected_tokens: ?*const std.StringArrayHashMapUnmanaged([]const u8),
    expected_raw_tokens: []const RawTokenEntry,
) bool {
    var changed = false;
    const has_expected_filter = expected_tokens != null or expected_raw_tokens.len > 0;
    for ([_][]const u8{ "copilotTokens", "copilot_tokens" }) |field_name| {
        if (root.getPtr(field_name)) |tv| {
            if (tv.* == .object) {
                var idx: usize = 0;
                while (idx < tv.object.count()) {
                    const k = tv.object.keys()[idx];
                    const v = tv.object.values()[idx];
                    const parsed_opt = parseAccountKey(k);
                    const matches_target = if (parsed_opt) |parsed|
                        sameHost(parsed.host, https_host) and
                            (if (maybe_login) |login| std.ascii.eqlIgnoreCase(parsed.login, login) else true)
                    else
                        false;
                    const should_remove = if (!matches_target)
                        false
                    else if (has_expected_filter) blk: {
                        if (v != .string) break :blk false;
                        const cur_tok = std.mem.trim(u8, v.string, " \t");
                        const check_login = maybe_login orelse parsed_opt.?.login;
                        break :blk hasMatchingExpectedToken(
                            expected_tokens,
                            expected_raw_tokens,
                            https_host,
                            check_login,
                            cur_tok,
                        );
                    } else true;

                    if (should_remove) {
                        if (v == .string) {
                            std.crypto.secureZero(u8, @constCast(v.string));
                        }
                        _ = tv.object.orderedRemoveAt(idx);
                        changed = true;
                    } else {
                        idx += 1;
                    }
                }
                if (tv.object.count() == 0) {
                    _ = root.orderedRemove(field_name);
                    changed = true;
                }
            }
        }
    }
    return changed;
}

fn scrubPlaintextAccountFromRoot(
    root: *std.json.ObjectMap,
    https_host: []const u8,
    login: []const u8,
    expected_tokens: ?*const std.StringArrayHashMapUnmanaged([]const u8),
) bool {
    return scrubPlaintextFromRoot(root, https_host, login, expected_tokens, &.{});
}

fn sameHost(a_host: []const u8, b_host: []const u8) bool {
    var scratch_buf_a: [1024]u8 = undefined;
    var scratch_buf_b: [1024]u8 = undefined;
    var fba_a = std.heap.FixedBufferAllocator.init(&scratch_buf_a);
    var fba_b = std.heap.FixedBufferAllocator.init(&scratch_buf_b);
    const norm_a = normalizeCopilotHostUrlAlloc(fba_a.allocator(), a_host) catch a_host;
    const norm_b = normalizeCopilotHostUrlAlloc(fba_b.allocator(), b_host) catch b_host;
    return std.ascii.eqlIgnoreCase(norm_a, norm_b);
}

const UpsertAccountCtx = struct {
    https_host: []const u8,
    login: []const u8,
    make_active: bool,
};

fn upsertAccountAndScrubPlaintextMutation(a: Allocator, root: *std.json.ObjectMap, ctx: UpsertAccountCtx) Error!bool {
    var changed = false;

    const snap = readConfigSnapshotLeaky(a, root.*) catch return error.OutOfMemory;
    defer zeroSnapshotSecrets(&snap);
    var new_users = std.json.Array.init(a);
    var found_target = false;
    for (snap.users.items) |u| {
        if (sameHost(u.host, ctx.https_host) and std.ascii.eqlIgnoreCase(u.login, ctx.login)) {
            found_target = true;
            new_users.append(makeAccountJsonValueLeaky(a, ctx.https_host, ctx.login) catch return error.OutOfMemory) catch
                return error.OutOfMemory;
        } else {
            new_users.append(makeAccountJsonValueLeaky(a, u.host, u.login) catch return error.OutOfMemory) catch
                return error.OutOfMemory;
        }
    }
    if (!found_target) {
        new_users.append(makeAccountJsonValueLeaky(a, ctx.https_host, ctx.login) catch return error.OutOfMemory) catch
            return error.OutOfMemory;
        changed = true;
    }

    if (root.orderedRemove("logged_in_users")) changed = true;
    root.put(a, "loggedInUsers", .{ .array = new_users }) catch return error.OutOfMemory;

    if (ctx.make_active or (root.get("lastLoggedInUser") == null and root.get("last_logged_in_user") == null)) {
        if (root.orderedRemove("last_logged_in_user")) changed = true;
        const active_val = makeAccountJsonValueLeaky(a, ctx.https_host, ctx.login) catch return error.OutOfMemory;
        root.put(a, "lastLoggedInUser", active_val) catch return error.OutOfMemory;
        changed = true;
    }

    if (scrubPlaintextAccountFromRoot(root, ctx.https_host, ctx.login, null)) {
        changed = true;
    }
    return changed;
}

// ---------------------------------------------------------------------------
// Subcommand Dispatch & Implementations
// ---------------------------------------------------------------------------

pub fn run(
    gpa: Allocator,
    subcmd: Subcommand,
    stdin: *Io.Reader,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    return switch (subcmd) {
        .login => |opts| runLogin(gpa, opts, stdout, stderr),
        .logout => |opts| runLogout(gpa, opts, stdout, stderr),
        .status => runStatus(gpa, stdout, stderr),
        .token => |opts| runToken(gpa, opts, stdout, stderr),
        .env => |opts| runEnv(gpa, opts, stdout, stderr),
        .import_cmd => |opts| runImport(gpa, opts.source, stdin, stdout, stderr),
        .export_cmd => |opts| runExport(gpa, opts.dir, stdout, stderr),
    };
}

fn isClassicPat(tok: []const u8) bool {
    return std.mem.startsWith(u8, tok, "ghp_");
}

const ResolvedCredential = struct {
    https_host: []u8,
    login: []u8,
    token: []u8,
    from_gh_fallback: bool = false,

    fn deinit(self: *const ResolvedCredential, gpa: Allocator) void {
        gpa.free(self.https_host);
        gpa.free(self.login);
        std.crypto.secureZero(u8, self.token);
        gpa.free(self.token);
    }
};

fn resolveStoredCredential(
    gpa: Allocator,
    opts: LookupOptions,
) Error!ResolvedCredential {
    if (opts.username) |u| {
        if (!isValidLoginInput(u)) return error.InvalidInput;
    }
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var snap: ParsedConfigSnapshot = .{};
    defer zeroSnapshotSecrets(&snap);
    if (resolveCopilotConfigDir(a)) |config_dir| {
        const config_path = try std.fs.path.join(a, &.{ config_dir, config_filename });
        if (registry_auth.readFileIfExists(a, config_path) catch null) |bytes| {
            defer std.crypto.secureZero(u8, bytes);
            if (parseJsoncObjectLeaky(a, bytes)) |root| {
                defer zeroCopilotTokensInObject(&root);
                snap = try readConfigSnapshotLeaky(a, root);
            } else |_| {}
        }
    }

    const target_https_host: []const u8 = if (opts.hostname) |raw_h|
        try normalizeCopilotHostUrlAlloc(a, raw_h)
    else if (snap.last_user) |lu|
        lu.host
    else if (snap.users.items.len > 0)
        snap.users.items[0].host
    else
        "https://github.com";

    const store = activeSecretStore();
    var saw_locked = false;
    var saw_no_access = false;
    var saw_storage_failure = false;

    // 1. Explicit username requested -> canonicalize case against `config.json` and check `copilot-cli` vault.
    if (opts.username) |wanted_user| {
        const canonical_user = resolveCanonicalLogin(snap, target_https_host, wanted_user);
        const key_canon = try formatAccountKeyAlloc(a, target_https_host, canonical_user);
        if (store.get(gpa, service_name, key_canon)) |tok| {
            errdefer {
                std.crypto.secureZero(u8, tok);
                gpa.free(tok);
            }
            return .{
                .https_host = try gpa.dupe(u8, target_https_host),
                .login = try gpa.dupe(u8, canonical_user),
                .token = tok,
            };
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Locked => saw_locked = true,
            error.NoStorageAccess => saw_no_access = true,
            error.StorageFailure => saw_storage_failure = true,
            error.EntryNotFound => {
                if (!std.mem.eql(u8, canonical_user, wanted_user)) {
                    const key_raw = try formatAccountKeyAlloc(a, target_https_host, wanted_user);
                    if (store.get(gpa, service_name, key_raw)) |tok| {
                        errdefer {
                            std.crypto.secureZero(u8, tok);
                            gpa.free(tok);
                        }
                        return .{
                            .https_host = try gpa.dupe(u8, target_https_host),
                            .login = try gpa.dupe(u8, wanted_user),
                            .token = tok,
                        };
                    } else |err2| switch (err2) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.Locked => saw_locked = true,
                        error.NoStorageAccess => saw_no_access = true,
                        error.StorageFailure => saw_storage_failure = true,
                        error.EntryNotFound => {},
                    }
                }
            },
        }
    } else {
        // 2. Try `lastLoggedInUser` first when it matches `target_https_host`, then `loggedInUsers`.
        var candidates: std.ArrayListUnmanaged(AccountSpec) = .empty;
        if (snap.last_user) |lu| {
            if (sameHost(lu.host, target_https_host)) {
                try appendUniqueAccountLeaky(a, &candidates, lu);
            }
        }
        for (snap.users.items) |u| {
            if (sameHost(u.host, target_https_host)) {
                try appendUniqueAccountLeaky(a, &candidates, u);
            }
        }

        if (candidates.items.len == 0 and secret_store_override == null and keyring_zig.currentBackend() == .null_backend) {
            saw_no_access = true;
        }

        for (candidates.items) |cand| {
            const key = try formatAccountKeyAlloc(a, target_https_host, cand.login);
            if (store.get(gpa, service_name, key)) |tok| {
                errdefer {
                    std.crypto.secureZero(u8, tok);
                    gpa.free(tok);
                }
                return .{
                    .https_host = try gpa.dupe(u8, target_https_host),
                    .login = try gpa.dupe(u8, cand.login),
                    .token = tok,
                };
            } else |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Locked => saw_locked = true,
                error.NoStorageAccess => saw_no_access = true,
                error.StorageFailure => saw_storage_failure = true,
                error.EntryNotFound => {},
            }
        }
    }

    // 3. Fall back to stored GitHub CLI (`gh:<host>`) keyring credential ONLY when
    //    the platform's native OS store is active (skipping `GH_TOKEN`, plaintext
    //    `hosts.yml`, synthetic `"x-access-token"`, and classic `ghp_` PATs).
    if (isDefaultNativeStoreActive() and !saw_locked and !saw_no_access and !saw_storage_failure) {
        if (preflightLiveSecretBackend(gpa, if (noninteractive_secret_read) .never else .if_available)) |_| {
            const bare_host = try extractBareHostAlloc(a, target_https_host);
            const lookup_user = if (opts.username) |wanted|
                resolveCanonicalLogin(snap, target_https_host, wanted)
            else
                null;
            if (gh.lookupStoredKeyringCredential(gpa, bare_host, lookup_user)) |maybe_gh_cred| {
                if (maybe_gh_cred) |gh_cred| {
                    defer gh_cred.deinit(gpa);
                    if (!gh_cred.from_env and
                        gh_cred.stored_in_keyring and
                        isValidLoginInput(gh_cred.username) and
                        !std.mem.eql(u8, gh_cred.username, gh.token_username) and
                        !std.ascii.eqlIgnoreCase(gh_cred.username, gh.token_username) and
                        !isClassicPat(gh_cred.token))
                    {
                        return .{
                            .https_host = try gpa.dupe(u8, target_https_host),
                            .login = try gpa.dupe(u8, gh_cred.username),
                            .token = try gpa.dupe(u8, gh_cred.token),
                            .from_gh_fallback = true,
                        };
                    }
                }
            } else |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Locked => saw_locked = true,
                error.NoStorageAccess => saw_no_access = true,
                else => {},
            }
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Locked => saw_locked = true,
            error.NoStorageAccess => saw_no_access = true,
            error.StorageFailure => saw_storage_failure = true,
            error.EntryNotFound => {},
        }
    }

    // When no candidate account was probed yet (e.g. missing/empty config.json),
    // probe the keyring once so Locked / NoStorageAccess are surfaced accurately.
    if (opts.username == null and snap.users.items.len == 0 and !saw_locked and !saw_no_access and !saw_storage_failure) {
        if (store.get(a, service_name, "__keyring_copilot_probe__")) |probe_tok| {
            std.crypto.secureZero(u8, probe_tok);
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Locked => saw_locked = true,
            error.NoStorageAccess => saw_no_access = true,
            error.StorageFailure => saw_storage_failure = true,
            error.EntryNotFound => {},
        }
    }

    if (saw_locked) return error.Locked;
    if (saw_no_access) return error.NoStorageAccess;
    if (saw_storage_failure) return error.StorageFailure;
    return error.EntryNotFound;
}

fn writeInvalidHostStderr(stderr: *Io.Writer, subcmd_label: []const u8, raw_host: []const u8) !void {
    if (hasForbiddenControlOrSpace(raw_host)) {
        try stderr.print("keyring: copilot {s}: invalid hostname\n", .{subcmd_label});
    } else {
        try stderr.print("keyring: copilot {s}: invalid hostname '{s}'\n", .{ subcmd_label, raw_host });
    }
    try stderr.flush();
}

fn runLogin(
    gpa: Allocator,
    opts: LoginOptions,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    if (opts.username) |u| {
        if (!isValidLoginInput(u)) {
            try stderr.writeAll("keyring: copilot login: invalid username\n");
            try stderr.flush();
            return 2;
        }
    }
    const canonical_host = extractBareHostAlloc(gpa, opts.hostname) catch {
        try writeInvalidHostStderr(stderr, "login", opts.hostname);
        return 2;
    };
    defer gpa.free(canonical_host);

    const https_host = try std.fmt.allocPrint(gpa, "https://{s}", .{canonical_host});
    defer gpa.free(https_host);

    const config_dir = resolveCopilotConfigDir(gpa) orelse {
        try stderr.writeAll("keyring: copilot login: could not resolve Copilot config directory (HOME not set)\n");
        try stderr.flush();
        return 1;
    };
    defer gpa.free(config_dir);

    if (secret_store_override == null) {
        stored_provider.checkSecureBackendAvailable(gpa) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                try stderr.writeAll("keyring: copilot login: no access to OS keyring (run 'keyring diagnose' for guidance)\n");
                try stderr.flush();
                return 4;
            },
        };
    }

    var resolved_user: ?[]u8 = null;
    defer if (resolved_user) |u| gpa.free(u);
    var resolved_token: ?[]u8 = null;
    defer if (resolved_token) |t| {
        std.crypto.secureZero(u8, t);
        gpa.free(t);
    };

    if (!opts.force) {
        if (resolveStoredCredential(gpa, .{
            .hostname = canonical_host,
            .username = opts.username,
        })) |existing| {
            defer existing.deinit(gpa);
            if (!isClassicPat(existing.token)) {
                resolved_user = try gpa.dupe(u8, existing.login);
                resolved_token = try gpa.dupe(u8, existing.token);
            }
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Locked => {
                try stderr.writeAll("keyring: copilot login: OS keyring is locked (run 'keyring unlock' first)\n");
                try stderr.flush();
                return 1;
            },
            error.NoStorageAccess => {
                try stderr.writeAll("keyring: copilot login: no access to OS keyring (run 'keyring diagnose' for guidance)\n");
                try stderr.flush();
                return 4;
            },
            error.StorageFailure => {
                try stderr.writeAll("keyring: copilot login: failed to read from OS keyring\n");
                try stderr.flush();
                return 1;
            },
            error.EntryNotFound => {},
            else => {},
        }
    }

    if (resolved_token == null) {
        // Verify keyring accessibility before starting interactive OAuth so we
        // never mint a token or fall back to plaintext `hosts.yml` when the
        // keyring is locked or unavailable (including when `--force` is set).
        if (activeSecretStore().get(gpa, service_name, "__keyring_copilot_probe__")) |probe_tok| {
            std.crypto.secureZero(u8, probe_tok);
            gpa.free(probe_tok);
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Locked => {
                try stderr.writeAll("keyring: copilot login: OS keyring is locked (run 'keyring unlock' first)\n");
                try stderr.flush();
                return 1;
            },
            error.NoStorageAccess => {
                try stderr.writeAll("keyring: copilot login: no access to OS keyring (run 'keyring diagnose' for guidance)\n");
                try stderr.flush();
                return 4;
            },
            error.StorageFailure => {
                try stderr.writeAll("keyring: copilot login: failed to read from OS keyring\n");
                try stderr.flush();
                return 1;
            },
            error.EntryNotFound => {},
        }

        const cred = gh.loginOAuth(gpa, .{
            .hostname = canonical_host,
            .mode = opts.mode,
        }, stderr) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidHostname => blk: {
                try stderr.print("keyring: copilot login: invalid hostname '{s}'\n", .{opts.hostname});
                try stderr.flush();
                break :blk 2;
            },
            error.NoStorageAccess => blk: {
                try stderr.writeAll("keyring: copilot login: interactive login unavailable\n");
                try stderr.flush();
                break :blk 4;
            },
            else => blk: {
                try stderr.print("keyring: copilot login: authentication failed ({s})\n", .{@errorName(err)});
                try stderr.flush();
                break :blk 1;
            },
        };
        defer cred.deinit(gpa);

        if (!isValidLoginInput(cred.username)) {
            try stderr.writeAll("keyring: copilot login: authenticated login contains invalid characters\n");
            try stderr.flush();
            return 1;
        }
        if (opts.username) |wanted| {
            if (!std.ascii.eqlIgnoreCase(wanted, cred.username)) {
                try stderr.print(
                    "keyring: copilot login: authenticated as '{s}', expected '{s}'\n",
                    .{ cred.username, wanted },
                );
                try stderr.flush();
                return 1;
            }
        }
        resolved_user = try gpa.dupe(u8, cred.username);
        resolved_token = try gpa.dupe(u8, cred.token);
    }

    const final_user = resolved_user.?;
    const final_token = resolved_token.?;
    const account_key = try formatAccountKeyAlloc(gpa, https_host, final_user);
    defer gpa.free(account_key);

    activeSecretStore().set(gpa, service_name, account_key, final_token) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Locked => blk: {
            try stderr.writeAll("keyring: copilot login: OS keyring is locked (run 'keyring unlock' first)\n");
            try stderr.flush();
            break :blk 1;
        },
        error.NoStorageAccess => blk: {
            try stderr.writeAll("keyring: copilot login: no access to OS keyring (run 'keyring diagnose' for guidance)\n");
            try stderr.flush();
            break :blk 4;
        },
        else => blk: {
            try stderr.writeAll("keyring: copilot login: failed to store token in OS keyring\n");
            try stderr.flush();
            break :blk 1;
        },
    };

    const config_path = try std.fs.path.join(gpa, &.{ config_dir, config_filename });
    defer gpa.free(config_path);

    _ = mutateConfigFileWithCas(gpa, config_path, UpsertAccountCtx{
        .https_host = https_host,
        .login = final_user,
        .make_active = true,
    }, upsertAccountAndScrubPlaintextMutation) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => blk: {
            try stderr.print("keyring: copilot login: failed to update {s} ({s})\n", .{ config_path, @errorName(err) });
            try stderr.flush();
            break :blk 1;
        },
    };

    try stdout.print(
        "Authenticated Copilot CLI for {s} on {s} (stored in OS keyring).\n",
        .{ final_user, https_host },
    );
    try stdout.flush();
    return 0;
}

const LogoutMutationCtx = struct {
    all: bool,
    https_host: ?[]const u8,
    username: ?[]const u8,
};

fn applyLogoutConfigMutation(a: Allocator, root: *std.json.ObjectMap, ctx: LogoutMutationCtx) Error!bool {
    var changed = false;
    const snap = readConfigSnapshotLeaky(a, root.*) catch return error.OutOfMemory;
    defer zeroSnapshotSecrets(&snap);

    if (ctx.all) {
        zeroCopilotTokensInObject(root);
        if (root.orderedRemove("loggedInUsers")) changed = true;
        if (root.orderedRemove("logged_in_users")) changed = true;
        if (root.orderedRemove("lastLoggedInUser")) changed = true;
        if (root.orderedRemove("last_logged_in_user")) changed = true;
        if (root.orderedRemove("copilotTokens")) changed = true;
        if (root.orderedRemove("copilot_tokens")) changed = true;
        return changed;
    }

    const target_host = ctx.https_host orelse if (snap.last_user) |lu| lu.host else "https://github.com";
    const target_user: ?[]const u8 = ctx.username orelse if (ctx.https_host == null and snap.last_user != null)
        snap.last_user.?.login
    else
        null;

    var remaining = std.json.Array.init(a);
    for (snap.users.items) |u| {
        const match_host = sameHost(u.host, target_host);
        const match_user = if (target_user) |tu| std.ascii.eqlIgnoreCase(u.login, tu) else true;
        if (match_host and match_user) {
            changed = true;
            _ = scrubPlaintextAccountFromRoot(root, u.host, u.login, null);
        } else {
            remaining.append(makeAccountJsonValueLeaky(a, u.host, u.login) catch return error.OutOfMemory) catch
                return error.OutOfMemory;
        }
    }

    if (target_user) |tu| {
        if (scrubPlaintextAccountFromRoot(root, target_host, tu, null)) changed = true;
    } else {
        if (scrubPlaintextFromRoot(root, target_host, null, null, &.{})) changed = true;
    }

    if (changed) {
        _ = root.orderedRemove("logged_in_users");
        if (remaining.items.len > 0) {
            root.put(a, "loggedInUsers", .{ .array = remaining }) catch return error.OutOfMemory;
        } else {
            _ = root.orderedRemove("loggedInUsers");
        }

        if (snap.last_user) |lu| {
            const match_host = sameHost(lu.host, target_host);
            const match_user = if (target_user) |tu| std.ascii.eqlIgnoreCase(lu.login, tu) else true;
            if (match_host and match_user) {
                _ = root.orderedRemove("lastLoggedInUser");
                _ = root.orderedRemove("last_logged_in_user");
                if (remaining.items.len > 0) {
                    root.put(a, "lastLoggedInUser", remaining.items[0]) catch return error.OutOfMemory;
                }
            }
        }
    }
    return changed;
}

const LogoutDeleteOutcome = union(enum) {
    deleted,
    not_found,
    abort_exit: u8,
};

fn deleteKeyringEntryForLogout(
    a: Allocator,
    store: SecretStore,
    key: []const u8,
    stderr: *Io.Writer,
) !LogoutDeleteOutcome {
    if (store.delete(a, service_name, key)) |_| {
        return .deleted;
    } else |err| switch (err) {
        error.EntryNotFound => return .not_found,
        error.OutOfMemory => return error.OutOfMemory,
        error.Locked => {
            try stderr.writeAll("keyring: copilot logout: OS keyring is locked (run 'keyring unlock' first)\n");
            try stderr.flush();
            return .{ .abort_exit = 1 };
        },
        error.NoStorageAccess => {
            try stderr.writeAll("keyring: copilot logout: no access to OS keyring (run 'keyring diagnose' for guidance)\n");
            try stderr.flush();
            return .{ .abort_exit = 4 };
        },
        error.StorageFailure => {
            try stderr.writeAll("keyring: copilot logout: failed to delete credential from OS keyring\n");
            try stderr.flush();
            return .{ .abort_exit = 1 };
        },
    }
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

    if (opts.username) |u| {
        if (!isValidLoginInput(u)) {
            try stderr.writeAll("keyring: copilot logout: invalid username\n");
            try stderr.flush();
            return 2;
        }
    }
    const maybe_https_host: ?[]const u8 = if (opts.hostname) |raw_h| blk: {
        break :blk normalizeCopilotHostUrlAlloc(a, raw_h) catch {
            try writeInvalidHostStderr(stderr, "logout", raw_h);
            return 2;
        };
    } else null;

    if (secret_store_override == null) {
        stored_provider.checkSecureBackendAvailable(gpa) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                try stderr.writeAll("keyring: copilot logout: no access to OS keyring (run 'keyring diagnose' for guidance)\n");
                try stderr.flush();
                return 4;
            },
        };
    }

    var snap: ParsedConfigSnapshot = .{};
    defer zeroSnapshotSecrets(&snap);
    const maybe_config_dir = resolveCopilotConfigDir(a);
    const maybe_config_path: ?[]const u8 = if (maybe_config_dir) |dir|
        try std.fs.path.join(a, &.{ dir, config_filename })
    else
        null;

    var config_file_exists = false;
    if (maybe_config_path) |cp| {
        if (try registry_auth.readFileIfExists(a, cp)) |bytes| {
            config_file_exists = true;
            defer std.crypto.secureZero(u8, bytes);
            if (parseJsoncObjectLeaky(a, bytes)) |root| {
                defer zeroCopilotTokensInObject(&root);
                snap = try readConfigSnapshotLeaky(a, root);
            } else |_| {}
        }
    }

    const store = activeSecretStore();
    var removed_count: usize = 0;

    if (opts.all) {
        for (snap.users.items) |u| {
            const key = try formatAccountKeyAlloc(a, u.host, u.login);
            switch (try deleteKeyringEntryForLogout(a, store, key, stderr)) {
                .deleted => removed_count += 1,
                .not_found => {},
                .abort_exit => |code| return code,
            }
        }
    } else {
        const effective_host = maybe_https_host orelse if (snap.last_user) |lu| lu.host else "https://github.com";
        if (opts.username) |tu| {
            const canonical = resolveCanonicalLogin(snap, effective_host, tu);
            const key_canon = try formatAccountKeyAlloc(a, effective_host, canonical);
            switch (try deleteKeyringEntryForLogout(a, store, key_canon, stderr)) {
                .deleted => removed_count += 1,
                .not_found => {},
                .abort_exit => |code| return code,
            }
            if (!std.mem.eql(u8, canonical, tu)) {
                const key_raw = try formatAccountKeyAlloc(a, effective_host, tu);
                switch (try deleteKeyringEntryForLogout(a, store, key_raw, stderr)) {
                    .deleted => removed_count += 1,
                    .not_found => {},
                    .abort_exit => |code| return code,
                }
            }
        } else if (maybe_https_host == null and snap.last_user != null) {
            const lu = snap.last_user.?;
            const key = try formatAccountKeyAlloc(a, lu.host, lu.login);
            switch (try deleteKeyringEntryForLogout(a, store, key, stderr)) {
                .deleted => removed_count += 1,
                .not_found => {},
                .abort_exit => |code| return code,
            }
        } else {
            for (snap.users.items) |u| {
                if (sameHost(u.host, effective_host)) {
                    const key = try formatAccountKeyAlloc(a, u.host, u.login);
                    switch (try deleteKeyringEntryForLogout(a, store, key, stderr)) {
                        .deleted => removed_count += 1,
                        .not_found => {},
                        .abort_exit => |code| return code,
                    }
                }
            }
        }
    }

    var config_changed = false;
    if (config_file_exists) {
        if (maybe_config_path) |cp| {
            config_changed = mutateConfigFileWithCas(a, cp, LogoutMutationCtx{
                .all = opts.all,
                .https_host = maybe_https_host,
                .username = opts.username,
            }, applyLogoutConfigMutation) catch |err| return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => blk: {
                    try stderr.print("keyring: copilot logout: failed to update {s} ({s})\n", .{ cp, @errorName(err) });
                    try stderr.flush();
                    break :blk 1;
                },
            };
        }
    }

    if (removed_count == 0 and !config_changed) {
        try stderr.writeAll("keyring: copilot logout: no matching Copilot CLI credentials found\n");
        try stderr.flush();
        return 3;
    }

    try stdout.print("Removed Copilot CLI credentials ({d} keyring item(s)).\n", .{removed_count});
    try stdout.flush();
    return 0;
}

fn runToken(
    gpa: Allocator,
    opts: LookupOptions,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    if (opts.username) |u| {
        if (!isValidLoginInput(u)) {
            try stderr.writeAll("keyring: copilot token: invalid username\n");
            try stderr.flush();
            return 2;
        }
    }
    if (opts.hostname) |raw_h| {
        const check = extractBareHostAlloc(gpa, raw_h) catch {
            try writeInvalidHostStderr(stderr, "token", raw_h);
            return 2;
        };
        gpa.free(check);
    }

    const prev_ni = noninteractive_secret_read;
    noninteractive_secret_read = true;
    defer noninteractive_secret_read = prev_ni;

    const cred = resolveStoredCredential(gpa, opts) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Locked => blk: {
            try stderr.writeAll("keyring: copilot token: OS keyring is locked (run 'keyring unlock' first)\n");
            try stderr.flush();
            break :blk 1;
        },
        error.NoStorageAccess => blk: {
            try stderr.writeAll("keyring: copilot token: no access to OS keyring\n");
            try stderr.flush();
            break :blk 4;
        },
        error.StorageFailure => blk: {
            try stderr.writeAll("keyring: copilot token: failed to read from OS keyring\n");
            try stderr.flush();
            break :blk 1;
        },
        else => blk: {
            try stderr.writeAll("keyring: copilot token: no Copilot CLI token found (run 'keyring copilot login' first)\n");
            try stderr.flush();
            break :blk 3;
        },
    };
    defer cred.deinit(gpa);

    try stdout.writeAll(cred.token);
    try stdout.flush();
    return 0;
}

fn detectDefaultShell(gpa: Allocator) ShellKind {
    if (getEnvVarOwned(gpa, "WSL_DISTRO_NAME")) |v| {
        gpa.free(v);
        return .sh;
    }
    if (getEnvVarOwned(gpa, "WSL_INTEROP")) |v| {
        gpa.free(v);
        return .sh;
    }
    if (getEnvVarOwned(gpa, "SHELL")) |sh_path| {
        defer gpa.free(sh_path);
        if (std.mem.endsWith(u8, sh_path, "/fish") or std.mem.eql(u8, sh_path, "fish")) {
            return .fish;
        }
        if (sh_path.len > 0) return .sh;
    }
    if (builtin.os.tag == .windows) return .pwsh;
    return .sh;
}

pub fn formatShellExportAlloc(gpa: Allocator, shell: ShellKind, token: []const u8) Error![]u8 {
    if (token.len == 0) return error.InvalidInput;
    for (token) |c| {
        if (c <= 0x20 or c >= 0x7f) return error.InvalidInput;
    }

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    switch (shell) {
        .sh => {
            try out.appendSlice(gpa, "export COPILOT_GITHUB_TOKEN='");
            for (token) |c| {
                if (c == '\'') {
                    try out.appendSlice(gpa, "'\\''");
                } else {
                    try out.append(gpa, c);
                }
            }
            try out.appendSlice(gpa, "'\n");
        },
        .fish => {
            try out.appendSlice(gpa, "set -gx COPILOT_GITHUB_TOKEN '");
            for (token) |c| {
                if (c == '\'' or c == '\\') {
                    try out.append(gpa, '\\');
                }
                try out.append(gpa, c);
            }
            try out.appendSlice(gpa, "'\n");
        },
        .pwsh => {
            try out.appendSlice(gpa, "$env:COPILOT_GITHUB_TOKEN = '");
            for (token) |c| {
                if (c == '\'') {
                    try out.appendSlice(gpa, "''");
                } else {
                    try out.append(gpa, c);
                }
            }
            try out.appendSlice(gpa, "'\n");
        },
        .cmd => {
            if (std.mem.indexOfAny(u8, token, "\"%&|^<>!") != null) return error.InvalidInput;
            try out.appendSlice(gpa, "set \"COPILOT_GITHUB_TOKEN=");
            try out.appendSlice(gpa, token);
            try out.appendSlice(gpa, "\"\n");
        },
    }
    return out.toOwnedSlice(gpa);
}

fn runEnv(
    gpa: Allocator,
    opts: EnvOptions,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    if (opts.username) |u| {
        if (!isValidLoginInput(u)) {
            try stderr.writeAll("keyring: copilot env: invalid username\n");
            try stderr.flush();
            return 2;
        }
    }
    if (opts.hostname) |raw_h| {
        const check = extractBareHostAlloc(gpa, raw_h) catch {
            try writeInvalidHostStderr(stderr, "env", raw_h);
            return 2;
        };
        gpa.free(check);
    }

    const prev_ni = noninteractive_secret_read;
    noninteractive_secret_read = true;
    defer noninteractive_secret_read = prev_ni;

    const cred = resolveStoredCredential(gpa, .{
        .hostname = opts.hostname,
        .username = opts.username,
    }) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Locked => blk: {
            try stderr.writeAll("keyring: copilot env: OS keyring is locked (run 'keyring unlock' first)\n");
            try stderr.flush();
            break :blk 1;
        },
        error.NoStorageAccess => blk: {
            try stderr.writeAll("keyring: copilot env: no access to OS keyring\n");
            try stderr.flush();
            break :blk 4;
        },
        error.StorageFailure => blk: {
            try stderr.writeAll("keyring: copilot env: failed to read from OS keyring\n");
            try stderr.flush();
            break :blk 1;
        },
        else => blk: {
            try stderr.writeAll("keyring: copilot env: no Copilot CLI token found (run 'keyring copilot login' first)\n");
            try stderr.flush();
            break :blk 3;
        },
    };
    defer cred.deinit(gpa);

    const shell = opts.shell orelse detectDefaultShell(gpa);
    const export_line = formatShellExportAlloc(gpa, shell, cred.token) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => blk: {
            try stderr.writeAll("keyring: copilot env: token contains characters unsafe for the selected shell\n");
            try stderr.flush();
            break :blk 1;
        },
    };
    defer {
        std.crypto.secureZero(u8, export_line);
        gpa.free(export_line);
    }

    try stdout.writeAll(export_line);
    try stdout.flush();
    return 0;
}

const ImportMergeCtx = struct {
    accounts: []const AccountSpec,
    last_user: ?AccountSpec,
    expected_tokens: ?*const std.StringArrayHashMapUnmanaged([]const u8) = null,
    expected_raw_tokens: []const RawTokenEntry = &.{},
};

fn applyImportMergeMutation(a: Allocator, root: *std.json.ObjectMap, ctx: ImportMergeCtx) Error!bool {
    var changed = false;
    const snap = readConfigSnapshotLeaky(a, root.*) catch return error.OutOfMemory;
    defer zeroSnapshotSecrets(&snap);

    var merged: std.ArrayListUnmanaged(AccountSpec) = .empty;
    for (snap.users.items) |u| {
        appendUniqueAccountLeaky(a, &merged, u) catch return error.OutOfMemory;
    }
    for (ctx.accounts) |inc| {
        const before = merged.items.len;
        appendUniqueAccountLeaky(a, &merged, inc) catch return error.OutOfMemory;
        if (merged.items.len > before) changed = true;
        if (scrubPlaintextFromRoot(root, inc.host, inc.login, ctx.expected_tokens, ctx.expected_raw_tokens)) {
            changed = true;
        }
    }

    var arr = std.json.Array.init(a);
    for (merged.items) |u| {
        arr.append(makeAccountJsonValueLeaky(a, u.host, u.login) catch return error.OutOfMemory) catch
            return error.OutOfMemory;
    }
    if (root.orderedRemove("logged_in_users")) changed = true;
    if (arr.items.len > 0) {
        root.put(a, "loggedInUsers", .{ .array = arr }) catch return error.OutOfMemory;
        changed = true;
    }

    if (ctx.last_user) |lu| {
        _ = root.orderedRemove("last_logged_in_user");
        root.put(a, "lastLoggedInUser", makeAccountJsonValueLeaky(a, lu.host, lu.login) catch return error.OutOfMemory) catch
            return error.OutOfMemory;
        changed = true;
    } else if (snap.last_user == null and merged.items.len > 0) {
        root.put(a, "lastLoggedInUser", makeAccountJsonValueLeaky(a, merged.items[0].host, merged.items[0].login) catch return error.OutOfMemory) catch
            return error.OutOfMemory;
        changed = true;
    }

    return changed;
}

fn readImportSourceBytesAlloc(
    a: Allocator,
    source: ?[]const u8,
    local_config_path: []const u8,
    stdin: *Io.Reader,
) !?[]u8 {
    if (source == null) {
        return registry_auth.readFileIfExists(a, local_config_path) catch null;
    }
    const src = source.?;
    if (std.mem.eql(u8, src, "-")) {
        return registry_auth.readBoundedStdinAll(a, stdin, 4 * 1024 * 1024) catch return error.InvalidInput;
    }

    const io = Io.Threaded.global_single_threaded.io();
    if (Io.Dir.cwd().openDir(io, src, .{})) |dir_val| {
        var dir = dir_val;
        defer dir.close(io);
        const joined = try std.fs.path.join(a, &.{ src, config_filename });
        return registry_auth.readFileIfExists(a, joined) catch null;
    } else |_| {}

    return registry_auth.readFileIfExists(a, src) catch null;
}

fn runImport(
    gpa: Allocator,
    source: ?[]const u8,
    stdin: *Io.Reader,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const config_dir = resolveCopilotConfigDir(a) orelse {
        try stderr.writeAll("keyring: copilot import: could not resolve Copilot config directory (HOME not set)\n");
        try stderr.flush();
        return 1;
    };
    const local_config_path = try std.fs.path.join(a, &.{ config_dir, config_filename });

    const source_bytes = (readImportSourceBytesAlloc(a, source, local_config_path, stdin) catch {
        try stderr.writeAll("keyring: copilot import: failed to read input\n");
        try stderr.flush();
        return 1;
    }) orelse {
        try stderr.writeAll("keyring: copilot import: Copilot config file not found\n");
        try stderr.flush();
        return 3;
    };
    defer std.crypto.secureZero(u8, source_bytes);

    const parsed_root = parseJsoncObjectLeaky(a, source_bytes) catch {
        try stderr.writeAll("keyring: copilot import: invalid JSON in Copilot config\n");
        try stderr.flush();
        return 1;
    };
    defer zeroCopilotTokensInObject(&parsed_root);
    const snap = try readConfigSnapshotLeaky(a, parsed_root);
    defer zeroSnapshotSecrets(&snap);

    if (snap.plaintext_tokens.count() == 0) {
        try stderr.writeAll("keyring: copilot import: no plaintext copilotTokens found to import\n");
        try stderr.flush();
        return 3;
    }

    const store = activeSecretStore();
    var imported_specs: std.ArrayListUnmanaged(AccountSpec) = .empty;
    var it = snap.plaintext_tokens.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        const tok = entry.value_ptr.*;
        const spec = parseAccountKey(key) orelse continue;
        const canonical_login = resolveCanonicalLogin(snap, spec.host, spec.login);
        const canonical_key = try formatAccountKeyAlloc(a, spec.host, canonical_login);

        store.set(a, service_name, canonical_key, tok) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.Locked => blk: {
                try stderr.writeAll("keyring: copilot import: OS keyring is locked (run 'keyring unlock' first)\n");
                try stderr.flush();
                break :blk 1;
            },
            error.NoStorageAccess => blk: {
                try stderr.writeAll("keyring: copilot import: no access to OS keyring (run 'keyring diagnose' for guidance)\n");
                try stderr.flush();
                break :blk 4;
            },
            else => blk: {
                try stderr.writeAll("keyring: copilot import: failed to write token to OS keyring\n");
                try stderr.flush();
                break :blk 1;
            },
        };

        try appendUniqueAccountLeaky(a, &imported_specs, .{ .host = spec.host, .login = canonical_login });
    }

    _ = mutateConfigFileWithCas(a, local_config_path, ImportMergeCtx{
        .accounts = imported_specs.items,
        .last_user = snap.last_user,
        .expected_tokens = if (source == null) &snap.plaintext_tokens else null,
        .expected_raw_tokens = if (source == null) snap.raw_plaintext_tokens.items else &.{},
    }, applyImportMergeMutation) catch {
        try stderr.print("keyring: copilot import: failed to update {s}\n", .{local_config_path});
        try stderr.flush();
        return 1;
    };

    try stdout.print(
        "Imported {d} Copilot CLI token(s) into the OS keyring and scrubbed plaintext tokens from {s}.\n",
        .{ imported_specs.items.len, local_config_path },
    );
    if (readStoreTokenPlaintextSetting(a, config_dir)) {
        try stdout.writeAll("note: 'storeTokenPlaintext' is enabled in settings.json; unset it so future logins stay in the OS keyring.\n");
    }
    try stdout.flush();
    return 0;
}

fn runExport(
    gpa: Allocator,
    dest_dir_path: []const u8,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const config_dir = resolveCopilotConfigDir(a) orelse {
        try stderr.writeAll("keyring: copilot export: could not resolve Copilot config directory (HOME not set)\n");
        try stderr.flush();
        return 1;
    };
    const local_config_path = try std.fs.path.join(a, &.{ config_dir, config_filename });
    const bytes = (registry_auth.readFileIfExists(a, local_config_path) catch null) orelse {
        try stderr.print("keyring: copilot export: no Copilot config found at {s}\n", .{local_config_path});
        try stderr.flush();
        return 3;
    };
    defer std.crypto.secureZero(u8, bytes);

    const root = parseJsoncObjectLeaky(a, bytes) catch {
        try stderr.print("keyring: copilot export: invalid JSON in {s}\n", .{local_config_path});
        try stderr.flush();
        return 1;
    };
    defer zeroCopilotTokensInObject(&root);
    const snap = try readConfigSnapshotLeaky(a, root);
    defer zeroSnapshotSecrets(&snap);
    if (snap.users.items.len == 0) {
        try stderr.print("keyring: copilot export: no accounts configured in {s}\n", .{local_config_path});
        try stderr.flush();
        return 3;
    }

    const store = activeSecretStore();
    var exported_users = std.json.Array.init(a);
    var exported_specs: std.ArrayListUnmanaged(AccountSpec) = .empty;
    var tokens_obj: std.json.ObjectMap = .empty;
    defer {
        for (tokens_obj.values()) |v| {
            if (v == .string) std.crypto.secureZero(u8, @constCast(v.string));
        }
    }
    var exported_count: usize = 0;
    var saw_locked = false;
    var saw_no_access = false;

    for (snap.users.items) |u| {
        const key = try formatAccountKeyAlloc(a, u.host, u.login);
        var tok_owned: ?[]u8 = null;
        if (store.get(a, service_name, key)) |vault_tok| {
            tok_owned = vault_tok;
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Locked => saw_locked = true,
            error.NoStorageAccess => saw_no_access = true,
            else => {},
        }

        if (tok_owned == null) {
            if (findSnapshotPlaintextToken(snap, u.host, u.login, key)) |pt| {
                tok_owned = try a.dupe(u8, pt);
            }
        }
        if (tok_owned == null and isDefaultNativeStoreActive() and !saw_locked and !saw_no_access) {
            if (extractBareHostAlloc(a, u.host) catch null) |bare| {
                if (gh.lookupStoredKeyringCredential(a, bare, u.login) catch null) |gh_cred| {
                    defer gh_cred.deinit(a);
                    if (!gh_cred.from_env and
                        gh_cred.stored_in_keyring and
                        isValidLoginInput(gh_cred.username) and
                        !std.mem.eql(u8, gh_cred.username, gh.token_username) and
                        !std.ascii.eqlIgnoreCase(gh_cred.username, gh.token_username) and
                        !isClassicPat(gh_cred.token))
                    {
                        tok_owned = try a.dupe(u8, gh_cred.token);
                    }
                }
            }
        }

        if (tok_owned) |tok| {
            try exported_users.append(try makeAccountJsonValueLeaky(a, u.host, u.login));
            try exported_specs.append(a, .{ .host = u.host, .login = u.login });
            try tokens_obj.put(a, key, .{ .string = tok });
            exported_count += 1;
        }
    }

    if (exported_count == 0) {
        if (saw_locked) {
            try stderr.writeAll("keyring: copilot export: OS keyring is locked (run 'keyring unlock' first)\n");
            try stderr.flush();
            return 1;
        }
        if (saw_no_access) {
            try stderr.writeAll("keyring: copilot export: no access to OS keyring\n");
            try stderr.flush();
            return 4;
        }
        try stderr.writeAll("keyring: copilot export: no stored Copilot CLI tokens found\n");
        try stderr.flush();
        return 3;
    }

    var out_root: std.json.ObjectMap = .empty;
    try out_root.put(a, "loggedInUsers", .{ .array = exported_users });
    var active_exported: ?AccountSpec = null;
    if (snap.last_user) |lu| {
        for (exported_specs.items) |eu| {
            if (sameHost(lu.host, eu.host) and std.ascii.eqlIgnoreCase(lu.login, eu.login)) {
                active_exported = eu;
                break;
            }
        }
    }
    if (active_exported) |eu| {
        try out_root.put(a, "lastLoggedInUser", try makeAccountJsonValueLeaky(a, eu.host, eu.login));
    } else if (exported_users.items.len > 0) {
        try out_root.put(a, "lastLoggedInUser", exported_users.items[0]);
    }
    try out_root.put(a, "copilotTokens", .{ .object = tokens_obj });

    const out_val: std.json.Value = .{ .object = out_root };
    const json_str = try std.json.Stringify.valueAlloc(a, out_val, .{ .whitespace = .indent_2 });
    defer std.crypto.secureZero(u8, json_str);
    const payload = try std.fmt.allocPrint(a, "{s}{s}\n", .{ config_header_comments, json_str });
    defer std.crypto.secureZero(u8, payload);

    const dest_path = try std.fs.path.join(a, &.{ dest_dir_path, config_filename });
    registry_auth.writeProtectedFileAtomic(a, dest_path, payload) catch {
        try stderr.print("keyring: copilot export: failed to write {s}\n", .{dest_path});
        try stderr.flush();
        return 1;
    };

    try stdout.print("Exported {d} Copilot CLI account(s) to {s}.\n", .{ exported_count, dest_path });
    try stdout.flush();
    return 0;
}

fn envLookupForColors(name: []const u8) ?[]const u8 {
    if (env_override_fn) |override_fn| return override_fn(name);
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return null;
    var i: usize = 0;
    while (std.c.environ[i]) |entry| : (i += 1) {
        const item = std.mem.span(entry);
        if (item.len >= name.len + 1 and item[name.len] == '=' and std.mem.eql(u8, item[0..name.len], name)) {
            return item[name.len + 1 ..];
        }
    }
    return null;
}

fn runStatus(
    gpa: Allocator,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    const prev_ni = noninteractive_secret_read;
    noninteractive_secret_read = true;
    defer noninteractive_secret_read = prev_ni;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const config_dir = resolveCopilotConfigDir(a) orelse {
        try stderr.writeAll("keyring: copilot status: could not resolve Copilot config directory (HOME not set)\n");
        try stderr.flush();
        return 1;
    };
    const config_path = try std.fs.path.join(a, &.{ config_dir, config_filename });
    const maybe_bytes = registry_auth.readFileIfExists(a, config_path) catch null;
    defer if (maybe_bytes) |b| std.crypto.secureZero(u8, b);

    try stdout.print("copilot config: {s} ({s})\n", .{
        config_path,
        if (maybe_bytes != null) "present" else "missing",
    });
    const plaintext_setting = readStoreTokenPlaintextSetting(a, config_dir);
    try stdout.print("storeTokenPlaintext: {s}\n", .{if (plaintext_setting) "enabled" else "disabled"});

    if (maybe_bytes == null) {
        try stdout.writeAll("accounts: none configured\n");
        try stdout.flush();
        return 0;
    }

    const root = parseJsoncObjectLeaky(a, maybe_bytes) catch {
        try stderr.print("keyring: copilot status: invalid JSON in {s}\n", .{config_path});
        try stderr.flush();
        return 1;
    };
    defer zeroCopilotTokensInObject(&root);
    const snap = try readConfigSnapshotLeaky(a, root);
    defer zeroSnapshotSecrets(&snap);
    if (snap.users.items.len == 0) {
        try stdout.writeAll("accounts: none configured\n");
        try stdout.flush();
        return 0;
    }

    const store = activeSecretStore();
    for (snap.users.items) |u| {
        const is_active = if (snap.last_user) |lu|
            sameHost(lu.host, u.host) and std.ascii.eqlIgnoreCase(lu.login, u.login)
        else
            false;
        const prefix = if (is_active) "* " else "  ";
        const key = try formatAccountKeyAlloc(a, u.host, u.login);

        const has_pt = findSnapshotPlaintextToken(snap, u.host, u.login, key) != null;
        var status_label: []const u8 = "missing";
        if (store.get(a, service_name, key)) |tok| {
            const classic = isClassicPat(tok);
            std.crypto.secureZero(u8, tok);
            status_label = if (classic) "stored in keyring (warning: classic ghp_ PAT rejected by Copilot CLI)" else "stored in keyring";
        } else |err| switch (err) {
            error.Locked => status_label = "keyring locked",
            error.NoStorageAccess => {
                status_label = if (has_pt)
                    "stored in plaintext config.json (keyring unavailable)"
                else
                    "keyring unavailable";
            },
            else => {
                if (has_pt) {
                    status_label = "stored in plaintext config.json";
                } else if (isDefaultNativeStoreActive()) {
                    if (extractBareHostAlloc(a, u.host) catch null) |bare| {
                        if (gh.lookupStoredKeyringCredential(a, bare, u.login) catch null) |gh_cred| {
                            defer gh_cred.deinit(a);
                            if (!gh_cred.from_env and
                                gh_cred.stored_in_keyring and
                                isValidLoginInput(gh_cred.username) and
                                !std.mem.eql(u8, gh_cred.username, gh.token_username) and
                                !std.ascii.eqlIgnoreCase(gh_cred.username, gh.token_username) and
                                !isClassicPat(gh_cred.token))
                            {
                                status_label = "available via gh keyring";
                            }
                        }
                    }
                }
            },
        }

        try stdout.print("{s}{s} ({s}): {s}\n", .{ prefix, u.login, u.host, status_label });
    }

    try stdout.flush();
    return 0;
}

pub fn diagnose(gpa: Allocator, stdout: *Io.Writer) !void {
    const prev_ni = noninteractive_secret_read;
    noninteractive_secret_read = true;
    defer noninteractive_secret_read = prev_ni;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const config_dir = resolveCopilotConfigDir(a) orelse return;
    const config_path = try std.fs.path.join(a, &.{ config_dir, config_filename });
    const bytes = (registry_auth.readFileIfExists(a, config_path) catch null) orelse return;
    defer std.crypto.secureZero(u8, bytes);

    const root = parseJsoncObjectLeaky(a, bytes) catch {
        try stdout.print("copilot: {s} (invalid JSON)\n", .{config_path});
        return;
    };
    defer zeroCopilotTokensInObject(&root);
    const snap = try readConfigSnapshotLeaky(a, root);
    defer zeroSnapshotSecrets(&snap);
    const store = activeSecretStore();

    var in_keyring: usize = 0;
    var in_plaintext: usize = 0;
    for (snap.users.items) |u| {
        const key = try formatAccountKeyAlloc(a, u.host, u.login);
        if (store.get(a, service_name, key)) |tok| {
            std.crypto.secureZero(u8, tok);
            in_keyring += 1;
        } else |_| {}
        if (findSnapshotPlaintextToken(snap, u.host, u.login, key) != null) {
            in_plaintext += 1;
        }
    }

    const colors = color.Color.detect(envLookupForColors, term.isStdoutTty());
    try stdout.print(
        "copilot: {d} account(s) ({d} in keyring, {d} plaintext)\n",
        .{ snap.users.items.len, in_keyring, in_plaintext },
    );
    if (in_plaintext > 0) {
        try stdout.print(
            "{s}note:{s} Copilot CLI has {d} plaintext token(s) in {s}; run 'keyring copilot import' to move them to the OS keyring.\n",
            .{ colors.yellow(), colors.reset(), in_plaintext, config_path },
        );
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

const MockStoreState = struct {
    var gpa_ref: Allocator = undefined;
    var entries: std.StringHashMapUnmanaged([]u8) = .empty;
    var mode: enum { ok, locked, no_access, storage_failure } = .ok;

    fn reset(gpa: Allocator) void {
        deinit();
        gpa_ref = gpa;
        entries = .empty;
        mode = .ok;
    }

    fn deinit() void {
        if (entries.count() > 0 or entries.capacity() > 0) {
            var it = entries.iterator();
            while (it.next()) |e| {
                gpa_ref.free(e.key_ptr.*);
                gpa_ref.free(e.value_ptr.*);
            }
            entries.deinit(gpa_ref);
            entries = .empty;
        }
    }

    fn compoundKey(gpa: Allocator, svc: []const u8, acct: []const u8) SecretError![]u8 {
        return std.fmt.allocPrint(gpa, "{s}\x00{s}", .{ svc, acct }) catch error.OutOfMemory;
    }

    fn getFn(gpa: Allocator, svc: []const u8, acct: []const u8) SecretError![]u8 {
        switch (mode) {
            .locked => return error.Locked,
            .no_access => return error.NoStorageAccess,
            .storage_failure => return error.StorageFailure,
            .ok => {},
        }
        const k = try compoundKey(gpa, svc, acct);
        defer gpa.free(k);
        const val = entries.get(k) orelse return error.EntryNotFound;
        return gpa.dupe(u8, val) catch error.OutOfMemory;
    }

    fn setFn(_: Allocator, svc: []const u8, acct: []const u8, val: []const u8) SecretError!void {
        switch (mode) {
            .locked => return error.Locked,
            .no_access => return error.NoStorageAccess,
            .storage_failure => return error.StorageFailure,
            .ok => {},
        }
        const k = try compoundKey(gpa_ref, svc, acct);
        errdefer gpa_ref.free(k);
        const v_owned = gpa_ref.dupe(u8, val) catch return error.OutOfMemory;
        errdefer gpa_ref.free(v_owned);

        const gop = entries.getOrPut(gpa_ref, k) catch return error.OutOfMemory;
        if (gop.found_existing) {
            gpa_ref.free(k);
            gpa_ref.free(gop.value_ptr.*);
        }
        gop.value_ptr.* = v_owned;
    }

    fn deleteFn(gpa: Allocator, svc: []const u8, acct: []const u8) SecretError!void {
        switch (mode) {
            .locked => return error.Locked,
            .no_access => return error.NoStorageAccess,
            .storage_failure => return error.StorageFailure,
            .ok => {},
        }
        const k = try compoundKey(gpa, svc, acct);
        defer gpa.free(k);
        const kv = entries.fetchRemove(k) orelse return error.EntryNotFound;
        gpa_ref.free(kv.key);
        gpa_ref.free(kv.value);
    }

    const store: SecretStore = .{
        .get = getFn,
        .set = setFn,
        .delete = deleteFn,
    };
};

fn testNoColorEnv(name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, name, "NO_COLOR")) return "1";
    return null;
}

fn testTmpDirPath(tmp: *std.testing.TmpDir, gpa: Allocator) ![]u8 {
    var root: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(Io.Threaded.global_single_threaded.io(), &root);
    return gpa.dupe(u8, root[0..len]);
}

test "stripJsonCommentsAndTrailingCommasAlloc preserves URLs and strips comments" {
    const gpa = std.testing.allocator;
    const raw =
        \\// User settings belong in settings.json.
        \\/* Block comment with "https://ignored" */
        \\{
        \\  "lastLoggedInUser": {
        \\    "host": "https://github.com", // inline comment
        \\    "login": "alice",
        \\  },
        \\  "escaped": "quote \" // not a comment",
        \\}
    ;
    const stripped = try stripJsonCommentsAndTrailingCommasAlloc(gpa, raw);
    defer gpa.free(stripped);

    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, stripped, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .object);
    try std.testing.expectEqualStrings(
        "quote \" // not a comment",
        parsed.value.object.get("escaped").?.string,
    );
    const lu = parsed.value.object.get("lastLoggedInUser").?.object;
    try std.testing.expectEqualStrings("https://github.com", lu.get("host").?.string);
    try std.testing.expectEqualStrings("alice", lu.get("login").?.string);
}

test "normalizeCopilotHostUrlAlloc and parseAccountKey handle GitHub and GHE hosts" {
    const gpa = std.testing.allocator;

    const h1 = try normalizeCopilotHostUrlAlloc(gpa, "GitHub.com");
    defer gpa.free(h1);
    try std.testing.expectEqualStrings("https://github.com", h1);

    const h2 = try normalizeCopilotHostUrlAlloc(gpa, "https://api.Example.ghe.com/");
    defer gpa.free(h2);
    try std.testing.expectEqualStrings("https://example.ghe.com", h2);

    const p1 = parseAccountKey("https://github.com:alice").?;
    try std.testing.expectEqualStrings("https://github.com", p1.host);
    try std.testing.expectEqualStrings("alice", p1.login);

    const p2 = parseAccountKey("https://tenant.ghe.com:bob-smith").?;
    try std.testing.expectEqualStrings("https://tenant.ghe.com", p2.host);
    try std.testing.expectEqualStrings("bob-smith", p2.login);

    try std.testing.expect(parseAccountKey("https://github.com") == null);
    try std.testing.expect(parseAccountKey("https://github.com:") == null);
    try std.testing.expect(parseAccountKey(":alice") == null);
}

test "Windows UTF-16LE password encode/decode and legacy UTF-8 fallback" {
    const gpa = std.testing.allocator;

    const secret = "gho_AbCdEf0123456789xyzXYZ";
    const encoded = try encodeWindowsPasswordUtf16LeAlloc(gpa, secret);
    defer gpa.free(encoded);
    try std.testing.expectEqual(secret.len * 2, encoded.len);

    const decoded = try decodeWindowsCredentialBlobAlloc(gpa, encoded);
    defer gpa.free(decoded);
    try std.testing.expectEqualStrings(secret, decoded);

    // Legacy keytar raw UTF-8 blob (even and odd lengths) must also decode cleanly.
    const utf8_even = "gho_legacy1234";
    const dec_even = try decodeWindowsCredentialBlobAlloc(gpa, utf8_even);
    defer gpa.free(dec_even);
    try std.testing.expectEqualStrings(utf8_even, dec_even);

    const utf8_odd = "gho_legacy12345";
    const dec_odd = try decodeWindowsCredentialBlobAlloc(gpa, utf8_odd);
    defer gpa.free(dec_odd);
    try std.testing.expectEqualStrings(utf8_odd, dec_odd);
}

test "parseArgs covers all subcommands and rejects invalid flags" {
    const login_cmd = parseArgs(&.{ "login", "-h", "example.ghe.com", "-u", "alice", "--device", "-f" }).?;
    try std.testing.expectEqualStrings("example.ghe.com", login_cmd.login.hostname);
    try std.testing.expectEqualStrings("alice", login_cmd.login.username.?);
    try std.testing.expectEqual(gh.LoginMode.device, login_cmd.login.mode);
    try std.testing.expect(login_cmd.login.force);

    try std.testing.expect(parseArgs(&.{ "login", "--web", "--device" }) == null);
    try std.testing.expect(parseArgs(&.{ "logout", "--all", "-u", "alice" }) == null);
    try std.testing.expect(parseArgs(&.{"status"}).? == .status);
    try std.testing.expect(parseArgs(&.{ "status", "extra" }) == null);

    const env_cmd = parseArgs(&.{ "env", "--shell=fish", "--hostname=github.com" }).?;
    try std.testing.expectEqual(ShellKind.fish, env_cmd.env.shell.?);
    try std.testing.expectEqualStrings("github.com", env_cmd.env.hostname.?);

    const imp_default = parseArgs(&.{"import"}).?;
    try std.testing.expect(imp_default.import_cmd.source == null);
    const imp_stdin = parseArgs(&.{ "import", "-" }).?;
    try std.testing.expectEqualStrings("-", imp_stdin.import_cmd.source.?);

    const exp_cmd = parseArgs(&.{ "export", "/tmp/out" }).?;
    try std.testing.expectEqualStrings("/tmp/out", exp_cmd.export_cmd.dir);
    try std.testing.expect(parseArgs(&.{"export"}) == null);
}

test "formatShellExportAlloc escapes tokens safely across sh, fish, pwsh, and cmd" {
    const gpa = std.testing.allocator;

    const sh_line = try formatShellExportAlloc(gpa, .sh, "tok'en");
    defer gpa.free(sh_line);
    try std.testing.expectEqualStrings("export COPILOT_GITHUB_TOKEN='tok'\\''en'\n", sh_line);

    const pwsh_line = try formatShellExportAlloc(gpa, .pwsh, "tok'en");
    defer gpa.free(pwsh_line);
    try std.testing.expectEqualStrings("$env:COPILOT_GITHUB_TOKEN = 'tok''en'\n", pwsh_line);

    const fish_line = try formatShellExportAlloc(gpa, .fish, "a'b\\c");
    defer gpa.free(fish_line);
    try std.testing.expectEqualStrings("set -gx COPILOT_GITHUB_TOKEN 'a\\'b\\\\c'\n", fish_line);

    const cmd_line = try formatShellExportAlloc(gpa, .cmd, "gho_safe123");
    defer gpa.free(cmd_line);
    try std.testing.expectEqualStrings("set \"COPILOT_GITHUB_TOKEN=gho_safe123\"\n", cmd_line);

    try std.testing.expectError(error.InvalidInput, formatShellExportAlloc(gpa, .cmd, "bad%tok"));
    try std.testing.expectError(error.InvalidInput, formatShellExportAlloc(gpa, .sh, "bad\ntok"));
}

test "import scrubs plaintext copilotTokens, preserves unknown fields, and supports token/env/status/export/logout" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root_path = try testTmpDirPath(&tmp, gpa);
    defer gpa.free(root_path);
    const copilot_dir = try std.fs.path.join(gpa, &.{ root_path, "copilot-home" });
    defer gpa.free(copilot_dir);
    const export_dir = try std.fs.path.join(gpa, &.{ root_path, "exported" });
    defer gpa.free(export_dir);
    const config_path = try std.fs.path.join(gpa, &.{ copilot_dir, config_filename });
    defer gpa.free(config_path);

    MockStoreState.reset(gpa);
    defer MockStoreState.deinit();
    setTestOverrides(MockStoreState.store, copilot_dir, testNoColorEnv);
    defer setTestOverrides(null, null, null);

    const initial_jsonc =
        \\// User settings belong in settings.json.
        \\{
        \\  "loggedInUsers": [
        \\    { "host": "https://github.com", "login": "alice" }
        \\  ],
        \\  "lastLoggedInUser": { "host": "https://github.com", "login": "alice" },
        \\  "copilotTokens": {
        \\    "https://github.com:alice": "gho_secret_token_alice"
        \\  },
        \\  "trustedFolders": ["/work/repo"]
        \\}
    ;
    try registry_auth.writeProtectedFileAtomic(gpa, config_path, initial_jsonc);

    var empty_in = Io.Reader.fixed("");
    var out = Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    var err_out = Io.Writer.Allocating.init(gpa);
    defer err_out.deinit();

    // 1. Migrate plaintext token into keyring.
    const rc_import = try run(gpa, .{ .import_cmd = .{ .source = null } }, &empty_in, &out.writer, &err_out.writer);
    try std.testing.expectEqual(@as(u8, 0), rc_import);

    const scrubbed = (try registry_auth.readFileIfExists(gpa, config_path)).?;
    defer gpa.free(scrubbed);
    try std.testing.expect(std.mem.indexOf(u8, scrubbed, "gho_secret_token_alice") == null);
    try std.testing.expect(std.mem.indexOf(u8, scrubbed, "trustedFolders") != null);
    try std.testing.expect(std.mem.indexOf(u8, scrubbed, "/work/repo") != null);

    // 2. `token` prints raw secret with no trailing newline.
    out.clearRetainingCapacity();
    const rc_tok = try run(gpa, .{ .token = .{} }, &empty_in, &out.writer, &err_out.writer);
    try std.testing.expectEqual(@as(u8, 0), rc_tok);
    try std.testing.expectEqualStrings("gho_secret_token_alice", out.written());

    // 3. `env --shell sh` prints POSIX export.
    out.clearRetainingCapacity();
    const rc_env = try run(gpa, .{ .env = .{ .shell = .sh } }, &empty_in, &out.writer, &err_out.writer);
    try std.testing.expectEqual(@as(u8, 0), rc_env);
    try std.testing.expectEqualStrings("export COPILOT_GITHUB_TOKEN='gho_secret_token_alice'\n", out.written());

    // 4. `status` and `diagnose` report keyring-backed account.
    out.clearRetainingCapacity();
    const rc_status = try run(gpa, .status, &empty_in, &out.writer, &err_out.writer);
    try std.testing.expectEqual(@as(u8, 0), rc_status);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "* alice (https://github.com): stored in keyring") != null);

    out.clearRetainingCapacity();
    try diagnose(gpa, &out.writer);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "copilot: 1 account(s) (1 in keyring, 0 plaintext)") != null);

    // 5. `export` writes exported config.json, then `logout --all` clears vault + config, then `import <dir>` restores!
    out.clearRetainingCapacity();
    const rc_exp = try run(gpa, .{ .export_cmd = .{ .dir = export_dir } }, &empty_in, &out.writer, &err_out.writer);
    try std.testing.expectEqual(@as(u8, 0), rc_exp);

    out.clearRetainingCapacity();
    const rc_logout = try run(gpa, .{ .logout = .{ .all = true } }, &empty_in, &out.writer, &err_out.writer);
    try std.testing.expectEqual(@as(u8, 0), rc_logout);

    out.clearRetainingCapacity();
    const rc_missing = try run(gpa, .{ .token = .{} }, &empty_in, &out.writer, &err_out.writer);
    try std.testing.expectEqual(@as(u8, 3), rc_missing);

    out.clearRetainingCapacity();
    const rc_reimport = try run(gpa, .{ .import_cmd = .{ .source = export_dir } }, &empty_in, &out.writer, &err_out.writer);
    try std.testing.expectEqual(@as(u8, 0), rc_reimport);

    out.clearRetainingCapacity();
    const rc_tok2 = try run(gpa, .{ .token = .{} }, &empty_in, &out.writer, &err_out.writer);
    try std.testing.expectEqual(@as(u8, 0), rc_tok2);
    try std.testing.expectEqualStrings("gho_secret_token_alice", out.written());
}

test "stripJsonCommentsAndTrailingCommasAlloc rejects unterminated block comment" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(
        error.InvalidJson,
        stripJsonCommentsAndTrailingCommasAlloc(gpa, "{ /* unterminated comment \"secret\": \"gho_123\" }"),
    );
    try std.testing.expectError(
        error.InvalidJson,
        stripJsonCommentsAndTrailingCommasAlloc(gpa, "/*"),
    );
    try std.testing.expectError(
        error.InvalidJson,
        stripJsonCommentsAndTrailingCommasAlloc(gpa, "/* *"),
    );
}

test "buildMacosSecurityAddHexCommandAlloc emits hex secret and rejects unsafe identifiers" {
    const gpa = std.testing.allocator;

    const cmd = try buildMacosSecurityAddHexCommandAlloc(
        gpa,
        "copilot-cli",
        "https://github.com:Alice",
        "gho_A'B\"C\n",
    );
    defer gpa.free(cmd);
    try std.testing.expectEqualStrings(
        "add-generic-password -U -s 'copilot-cli' -a 'https://github.com:Alice' -X 67686f5f41274222430a\n",
        cmd,
    );

    const empty_cmd = try buildMacosSecurityAddHexCommandAlloc(
        gpa,
        "copilot-cli",
        "https://github.com:Alice",
        "",
    );
    defer gpa.free(empty_cmd);
    try std.testing.expectEqualStrings(
        "add-generic-password -U -s 'copilot-cli' -a 'https://github.com:Alice' -w ''\n",
        empty_cmd,
    );

    for ([_][]const u8{
        "",
        "https://github.com:al'ice",
        "https://github.com:al\"ice",
        "https://github.com:al\\ice",
        "https://github.com:al ice",
        "https://github.com:al\nice",
        "https://github.com:al\x7fice",
    }) |bad_acct| {
        try std.testing.expectError(
            error.InvalidInput,
            buildMacosSecurityAddHexCommandAlloc(gpa, "copilot-cli", bad_acct, "gho_123"),
        );
    }
    try std.testing.expectError(
        error.InvalidInput,
        buildMacosSecurityAddHexCommandAlloc(gpa, "", "https://github.com:alice", "gho_123"),
    );
}

test "Windows target-specific UTF-16LE and UTF-8 decoders validate lengths and encodings" {
    const gpa = std.testing.allocator;

    const encoded = try encodeWindowsPasswordUtf16LeAlloc(gpa, "gho_WinCred123");
    defer gpa.free(encoded);

    const dec16 = try decodeWindowsUtf16LeBlobAlloc(gpa, encoded);
    defer gpa.free(dec16);
    try std.testing.expectEqualStrings("gho_WinCred123", dec16);

    // BOM + trailing UTF-16 NUL units are stripped cleanly.
    const with_bom_and_nul = try std.mem.concat(gpa, u8, &.{ "\xFF\xFE", encoded, "\x00\x00" });
    defer gpa.free(with_bom_and_nul);
    const dec_bom = try decodeWindowsUtf16LeBlobAlloc(gpa, with_bom_and_nul);
    defer gpa.free(dec_bom);
    try std.testing.expectEqualStrings("gho_WinCred123", dec_bom);

    // Odd-length blob fails strict UTF-16LE decoding (`target_dot`), while
    // 40-byte ASCII UTF-8 tokens (`target_at` / `target_slash`) decode cleanly via `decodeWindowsUtf8BlobAlloc`.
    try std.testing.expectError(error.StorageFailure, decodeWindowsUtf16LeBlobAlloc(gpa, "gho_odd"));
    const forty_char_tok = "gho_0123456789abcdefghijklmnopqrstuvwxyz";
    try std.testing.expectEqual(@as(usize, 40), forty_char_tok.len);
    const dec_at = try decodeWindowsUtf8BlobAlloc(gpa, forty_char_tok);
    defer gpa.free(dec_at);
    try std.testing.expectEqualStrings(forty_char_tok, dec_at);

    // Unicode curly single quote U+2019 (\xe2\x80\x99) must be rejected by formatShellExportAlloc (PowerShell quote breakout).
    try std.testing.expectError(error.InvalidInput, formatShellExportAlloc(gpa, .pwsh, "gho_bad\xe2\x80\x99;calc"));
    try std.testing.expectError(error.InvalidInput, formatShellExportAlloc(gpa, .sh, "gho_bad\xe2\x80\x99"));

    // Legacy keytar UTF-8 decoder trims trailing NULs and rejects invalid UTF-8 / interior NULs.
    const dec8 = try decodeWindowsUtf8BlobAlloc(gpa, "gho_keytar\x00\x00");
    defer gpa.free(dec8);
    try std.testing.expectEqualStrings("gho_keytar", dec8);
    try std.testing.expectError(error.StorageFailure, decodeWindowsUtf8BlobAlloc(gpa, "\xff\xfe"));
    try std.testing.expectError(error.StorageFailure, decodeWindowsUtf8BlobAlloc(gpa, "a\x00b"));
}

test "logout and login propagate Locked and NoStorageAccess without modifying config.json, and -u matches case-insensitively" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root_path = try testTmpDirPath(&tmp, gpa);
    defer gpa.free(root_path);
    const copilot_dir = try std.fs.path.join(gpa, &.{ root_path, "copilot-home" });
    defer gpa.free(copilot_dir);
    const config_path = try std.fs.path.join(gpa, &.{ copilot_dir, config_filename });
    defer gpa.free(config_path);

    MockStoreState.reset(gpa);
    defer MockStoreState.deinit();
    setTestOverrides(MockStoreState.store, copilot_dir, testNoColorEnv);
    defer setTestOverrides(null, null, null);

    try MockStoreState.setFn(gpa, service_name, "https://github.com:Alice", "gho_alice_cased_token");

    const initial_config =
        \\// User settings belong in settings.json.
        \\{
        \\  "loggedInUsers": [
        \\    { "host": "https://github.com", "login": "Alice" }
        \\  ],
        \\  "lastLoggedInUser": { "host": "https://github.com", "login": "Alice" }
        \\}
    ;
    try registry_auth.writeProtectedFileAtomic(gpa, config_path, initial_config);

    var empty_in = Io.Reader.fixed("");
    var out = Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    var err_out = Io.Writer.Allocating.init(gpa);
    defer err_out.deinit();

    // 1. Case-insensitive `-u alice` resolves `"Alice"` in `token`.
    const rc_tok = try run(gpa, .{ .token = .{ .username = "alice" } }, &empty_in, &out.writer, &err_out.writer);
    try std.testing.expectEqual(@as(u8, 0), rc_tok);
    try std.testing.expectEqualStrings("gho_alice_cased_token", out.written());

    // 2. When keyring is Locked, `logout` exits 1, `login` exits 1, and `config.json` is untouched!
    MockStoreState.mode = .locked;
    out.clearRetainingCapacity();
    err_out.clearRetainingCapacity();
    try std.testing.expectEqual(
        @as(u8, 1),
        try run(gpa, .{ .logout = .{ .username = "alice" } }, &empty_in, &out.writer, &err_out.writer),
    );
    out.clearRetainingCapacity();
    err_out.clearRetainingCapacity();
    try std.testing.expectEqual(
        @as(u8, 1),
        try run(gpa, .{ .login = .{ .username = "alice" } }, &empty_in, &out.writer, &err_out.writer),
    );
    {
        const after_locked = (try registry_auth.readFileIfExists(gpa, config_path)).?;
        defer gpa.free(after_locked);
        try std.testing.expectEqualStrings(initial_config, after_locked);
    }

    // 3. When keyring has NoStorageAccess, `logout` exits 4, `login` exits 4, and `config.json` is untouched!
    MockStoreState.mode = .no_access;
    out.clearRetainingCapacity();
    err_out.clearRetainingCapacity();
    try std.testing.expectEqual(
        @as(u8, 4),
        try run(gpa, .{ .logout = .{ .all = true } }, &empty_in, &out.writer, &err_out.writer),
    );
    out.clearRetainingCapacity();
    err_out.clearRetainingCapacity();
    try std.testing.expectEqual(
        @as(u8, 4),
        try run(gpa, .{ .login = .{} }, &empty_in, &out.writer, &err_out.writer),
    );
    {
        const after_no_access = (try registry_auth.readFileIfExists(gpa, config_path)).?;
        defer gpa.free(after_no_access);
        try std.testing.expectEqualStrings(initial_config, after_no_access);
    }

    // 4. Restoring `.ok` allows case-insensitive `-u alice` in `logout` to delete `"Alice"` from vault & config!
    MockStoreState.mode = .ok;
    out.clearRetainingCapacity();
    err_out.clearRetainingCapacity();
    try std.testing.expectEqual(
        @as(u8, 0),
        try run(gpa, .{ .logout = .{ .username = "alice" } }, &empty_in, &out.writer, &err_out.writer),
    );
    try std.testing.expectEqual(@as(usize, 0), MockStoreState.entries.count());
    {
        const after_logout = (try registry_auth.readFileIfExists(gpa, config_path)).?;
        defer gpa.free(after_logout);
        try std.testing.expect(std.mem.indexOf(u8, after_logout, "Alice") == null);
    }
}

test "concurrent import preserves newer plaintext token and snapshot skips invalid hosts or control-char tokens" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    // 1. Invalid hosts and tokens containing \r/\n/\x00 are skipped in readConfigSnapshotLeaky.
    const dirty_json =
        \\{
        \\  "loggedInUsers": [
        \\    { "host": "https://bad host/path", "login": "mallory" },
        \\    { "host": "https://github.com", "login": "alice" }
        \\  ],
        \\  "copilotTokens": {
        \\    "https://bad host:mallory": "gho_bad_host",
        \\    "https://github.com:bob": "gho_bad\ntoken",
        \\    "https://github.com:alice": "gho_old_token"
        \\  }
        \\}
    ;
    const initial_root = try parseJsoncObjectLeaky(a, dirty_json);
    const snap = try readConfigSnapshotLeaky(a, initial_root);
    try std.testing.expectEqual(@as(usize, 1), snap.users.items.len);
    try std.testing.expectEqualStrings("alice", snap.users.items[0].login);
    try std.testing.expectEqual(@as(usize, 1), snap.plaintext_tokens.count());

    // 2. Simulate concurrent writer updating `alice`'s token in `config.json` before CAS mutation runs.
    const concurrent_json =
        \\{
        \\  "loggedInUsers": [
        \\    { "host": "https://github.com", "login": "alice" },
        \\    { "host": "https://github.com", "login": "carol" }
        \\  ],
        \\  "copilotTokens": {
        \\    "https://github.com:alice": "gho_concurrently_refreshed",
        \\    "https://github.com:carol": "gho_carol_imported"
        \\  }
        \\}
    ;
    var expected: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
    try expected.put(a, "https://github.com:alice", "gho_old_token");
    try expected.put(a, "https://github.com:carol", "gho_carol_imported");

    var live_root = try parseJsoncObjectLeaky(a, concurrent_json);
    const imported_accounts = [_]AccountSpec{
        .{ .host = "https://github.com", .login = "alice" },
        .{ .host = "https://github.com", .login = "carol" },
    };
    _ = try applyImportMergeMutation(a, &live_root, .{
        .accounts = &imported_accounts,
        .last_user = null,
        .expected_tokens = &expected,
    });

    const remaining_tokens = live_root.get("copilotTokens").?.object;
    try std.testing.expectEqual(@as(usize, 1), remaining_tokens.count());
    try std.testing.expectEqualStrings(
        "gho_concurrently_refreshed",
        remaining_tokens.get("https://github.com:alice").?.string,
    );
    try std.testing.expect(remaining_tokens.get("https://github.com:carol") == null);
}

test "null_backend (--disable) returns exit 4 across token, import, logout, and login without modifying config.json" {
    const gpa = std.testing.allocator;
    const prev_backend = keyring_zig.currentBackend();
    defer keyring_zig.setDefaultBackend(prev_backend) catch {};
    try keyring_zig.setDefaultBackend(.null_backend);

    try std.testing.expect(!isDefaultNativeStoreActive());

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root_path = try testTmpDirPath(&tmp, gpa);
    defer gpa.free(root_path);
    const copilot_dir = try std.fs.path.join(gpa, &.{ root_path, "copilot-home" });
    defer gpa.free(copilot_dir);
    const config_path = try std.fs.path.join(gpa, &.{ copilot_dir, config_filename });
    defer gpa.free(config_path);

    setTestOverrides(null, copilot_dir, testNoColorEnv);
    defer setTestOverrides(null, null, null);

    const initial_config =
        \\// User settings belong in settings.json.
        \\{
        \\  "loggedInUsers": [
        \\    { "host": "https://github.com", "login": "alice" }
        \\  ],
        \\  "lastLoggedInUser": { "host": "https://github.com", "login": "alice" },
        \\  "copilotTokens": {
        \\    "https://github.com:alice": "gho_preserve_under_disable"
        \\  }
        \\}
    ;
    try registry_auth.writeProtectedFileAtomic(gpa, config_path, initial_config);

    var empty_in = Io.Reader.fixed("");
    var out = Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    var err_out = Io.Writer.Allocating.init(gpa);
    defer err_out.deinit();

    for ([_]Subcommand{
        .{ .token = .{} },
        .{ .import_cmd = .{ .source = null } },
        .{ .logout = .{ .all = true } },
        .{ .login = .{} },
    }) |subcmd| {
        out.clearRetainingCapacity();
        err_out.clearRetainingCapacity();
        try std.testing.expectEqual(@as(u8, 4), try run(gpa, subcmd, &empty_in, &out.writer, &err_out.writer));
    }

    const after = (try registry_auth.readFileIfExists(gpa, config_path)).?;
    defer gpa.free(after);
    try std.testing.expectEqualStrings(initial_config, after);
}

test "first-time login, login -f, token, and env without config.json surface Locked and NoStorageAccess before OAuth" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root_path = try testTmpDirPath(&tmp, gpa);
    defer gpa.free(root_path);
    const copilot_dir = try std.fs.path.join(gpa, &.{ root_path, "empty-copilot-home" });
    defer gpa.free(copilot_dir);

    MockStoreState.reset(gpa);
    defer MockStoreState.deinit();
    setTestOverrides(MockStoreState.store, copilot_dir, testNoColorEnv);
    defer setTestOverrides(null, null, null);

    var empty_in = Io.Reader.fixed("");
    var out = Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    var err_out = Io.Writer.Allocating.init(gpa);
    defer err_out.deinit();

    MockStoreState.mode = .locked;
    for ([_]Subcommand{
        .{ .login = .{} },
        .{ .login = .{ .force = true } },
        .{ .token = .{} },
        .{ .env = .{ .shell = .sh } },
    }) |subcmd| {
        out.clearRetainingCapacity();
        err_out.clearRetainingCapacity();
        try std.testing.expectEqual(@as(u8, 1), try run(gpa, subcmd, &empty_in, &out.writer, &err_out.writer));
    }

    MockStoreState.mode = .no_access;
    for ([_]Subcommand{
        .{ .login = .{} },
        .{ .login = .{ .force = true } },
        .{ .token = .{} },
        .{ .env = .{ .shell = .sh } },
    }) |subcmd| {
        out.clearRetainingCapacity();
        err_out.clearRetainingCapacity();
        try std.testing.expectEqual(@as(u8, 4), try run(gpa, subcmd, &empty_in, &out.writer, &err_out.writer));
    }
}

test "NUL and control bytes are rejected in account keys, config objects, and CLI flags" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    try std.testing.expect(parseAccountKey("https://github.com\x00:alice") == null);
    try std.testing.expect(parseAccountKey("https://github.com:alice\x00evil") == null);
    try std.testing.expect(parseAccountKey("https://github.com\x1b[2J:alice") == null);
    try std.testing.expect(parseAccountKey("https://github.com:alice\x7f") == null);
    try std.testing.expect(parseAccountKey("https://github.com :alice") == null);
    try std.testing.expect(parseAccountKey("https://github.com: alice") == null);

    try std.testing.expect(parseArgs(&.{ "login", "-u", "alice\x00evil" }) == null);
    try std.testing.expect(parseArgs(&.{ "login", "-h", "github.com\x00evil" }) == null);
    try std.testing.expect(parseArgs(&.{ "token", "-u", "alice\x1b" }) == null);
    try std.testing.expect(parseArgs(&.{ "logout", "--user=alice\x7f" }) == null);
    try std.testing.expect(parseArgs(&.{ "env", "--hostname=github.com\n" }) == null);

    // Direct Subcommand structs with control bytes also fail closed with exit 2 without echoing control bytes.
    var empty_in = Io.Reader.fixed("");
    var out = Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    var err_out = Io.Writer.Allocating.init(gpa);
    defer err_out.deinit();

    try std.testing.expectEqual(
        @as(u8, 2),
        try run(gpa, .{ .token = .{ .username = "alice\x00evil" } }, &empty_in, &out.writer, &err_out.writer),
    );
    try std.testing.expectEqual(
        @as(u8, 2),
        try run(gpa, .{ .token = .{ .hostname = "github.com\x1b[31m" } }, &empty_in, &out.writer, &err_out.writer),
    );
    try std.testing.expect(std.mem.indexOfScalar(u8, err_out.written(), 0x1b) == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, err_out.written(), 0x00) == null);

    // Malicious JSON config entries containing \u0000 / \u001b / \u007f are skipped and never emitted by status/diagnose.
    const malicious_json =
        \\{
        \\  "loggedInUsers": [
        \\    { "host": "https://github.com\u0000evil", "login": "alice" },
        \\    { "host": "https://github.com", "login": "bob\u001b[2J" },
        \\    { "host": "https://github.com", "login": "carol\u007f" },
        \\    { "host": "https://github.com", "login": "gooduser" }
        \\  ],
        \\  "lastLoggedInUser": { "host": "https://github.com", "login": "bad\u0000user" }
        \\}
    ;
    const root = try parseJsoncObjectLeaky(a, malicious_json);
    const snap = try readConfigSnapshotLeaky(a, root);
    defer zeroSnapshotSecrets(&snap);
    try std.testing.expect(snap.last_user == null);
    try std.testing.expectEqual(@as(usize, 1), snap.users.items.len);
    try std.testing.expectEqualStrings("gooduser", snap.users.items[0].login);
}

test "import scrubs all case and host duplicate copilotTokens, export validates lastLoggedInUser, and host logout scrubs copilotTokens" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root_path = try testTmpDirPath(&tmp, gpa);
    defer gpa.free(root_path);
    const copilot_dir = try std.fs.path.join(gpa, &.{ root_path, "copilot-home" });
    defer gpa.free(copilot_dir);
    const export_dir = try std.fs.path.join(gpa, &.{ root_path, "exported" });
    defer gpa.free(export_dir);
    const config_path = try std.fs.path.join(gpa, &.{ copilot_dir, config_filename });
    defer gpa.free(config_path);

    MockStoreState.reset(gpa);
    defer MockStoreState.deinit();
    setTestOverrides(MockStoreState.store, copilot_dir, testNoColorEnv);
    defer setTestOverrides(null, null, null);

    // 1. Case & host-alias duplicate copilotTokens entries (both copilotTokens and copilot_tokens) are all scrubbed on import!
    const multi_variant_json =
        \\{
        \\  "loggedInUsers": [
        \\    { "host": "https://github.com", "login": "Alice" },
        \\    { "host": "https://github.com", "login": "ghost" }
        \\  ],
        \\  "lastLoggedInUser": { "host": "https://github.com", "login": "ghost" },
        \\  "copilotTokens": {
        \\    "https://github.com:Alice": "gho_variant_1",
        \\    "https://GITHUB.COM:alice": "gho_variant_2",
        \\    "github.com:alice": "gho_variant_3"
        \\  },
        \\  "copilot_tokens": {
        \\    "https://api.github.com:ALICE": "gho_variant_4"
        \\  }
        \\}
    ;
    try registry_auth.writeProtectedFileAtomic(gpa, config_path, multi_variant_json);

    var empty_in = Io.Reader.fixed("");
    var out = Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    var err_out = Io.Writer.Allocating.init(gpa);
    defer err_out.deinit();

    try std.testing.expectEqual(
        @as(u8, 0),
        try run(gpa, .{ .import_cmd = .{ .source = null } }, &empty_in, &out.writer, &err_out.writer),
    );

    const scrubbed = (try registry_auth.readFileIfExists(gpa, config_path)).?;
    defer gpa.free(scrubbed);
    for ([_][]const u8{ "gho_variant_1", "gho_variant_2", "gho_variant_3", "gho_variant_4", "copilotTokens", "copilot_tokens" }) |secret_frag| {
        try std.testing.expect(std.mem.indexOf(u8, scrubbed, secret_frag) == null);
    }

    // 2. `export` falls back to exported_users[0] ("Alice") when `lastLoggedInUser` ("ghost") has no token!
    out.clearRetainingCapacity();
    try std.testing.expectEqual(
        @as(u8, 0),
        try run(gpa, .{ .export_cmd = .{ .dir = export_dir } }, &empty_in, &out.writer, &err_out.writer),
    );
    const exported_cfg_path = try std.fs.path.join(gpa, &.{ export_dir, config_filename });
    defer gpa.free(exported_cfg_path);
    const exported_bytes = (try registry_auth.readFileIfExists(gpa, exported_cfg_path)).?;
    defer gpa.free(exported_bytes);
    try std.testing.expect(std.mem.indexOf(u8, exported_bytes, "\"ghost\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported_bytes, "\"login\": \"Alice\"") != null);

    // 3. Long RFC-1035 hostname (~240 chars) works cleanly in `sameHost`.
    const seg_a = &@as([60]u8, @splat('a'));
    const seg_b = &@as([60]u8, @splat('b'));
    const seg_c = &@as([60]u8, @splat('c'));
    const seg_ua = &@as([60]u8, @splat('A'));
    const seg_ub = &@as([60]u8, @splat('B'));
    const seg_uc = &@as([60]u8, @splat('C'));
    const long_host_a = "https://" ++ seg_a ++ "." ++ seg_b ++ "." ++ seg_c ++ ".ghe.com";
    const long_host_b = "HTTPS://api." ++ seg_ua ++ "." ++ seg_ub ++ "." ++ seg_uc ++ ".ghe.com/";
    try std.testing.expect(sameHost(long_host_a, long_host_b));

    // 4. Host-wide logout (`logout -h tenant.ghe.com`, `target_user == null`) scrubs all matching `copilotTokens` entries!
    const host_logout_json =
        \\{
        \\  "loggedInUsers": [
        \\    { "host": "https://github.com", "login": "Alice" }
        \\  ],
        \\  "copilotTokens": {
        \\    "https://tenant.ghe.com:orphan": "   ",
        \\    "https://TENANT.ghe.com:second": "gho_ghe_tok",
        \\    "https://github.com:Alice": "gho_keep_dotcom"
        \\  }
        \\}
    ;
    try registry_auth.writeProtectedFileAtomic(gpa, config_path, host_logout_json);
    out.clearRetainingCapacity();
    try std.testing.expectEqual(
        @as(u8, 0),
        try run(gpa, .{ .logout = .{ .hostname = "tenant.ghe.com" } }, &empty_in, &out.writer, &err_out.writer),
    );
    const after_host_logout = (try registry_auth.readFileIfExists(gpa, config_path)).?;
    defer gpa.free(after_host_logout);
    try std.testing.expect(std.mem.indexOf(u8, after_host_logout, "tenant.ghe.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, after_host_logout, "TENANT.ghe.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, after_host_logout, "gho_keep_dotcom") != null);
}

test "unconfigured file backend fails closed with exit 4 before interactive OAuth" {
    if (!@hasField(keyring_zig.Backend, "file")) return;
    const gpa = std.testing.allocator;

    const prev_backend = keyring_zig.currentBackend();
    defer keyring_zig.setDefaultBackend(prev_backend) catch {};
    const prev_env = stored_provider.env_override_fn;
    defer stored_provider.env_override_fn = prev_env;
    const prev_disallowed = stored_provider.is_app_backend_disallowed_fn;
    defer stored_provider.is_app_backend_disallowed_fn = prev_disallowed;

    const EmptyEnv = struct {
        fn get(_: []const u8) ?[]const u8 {
            return null;
        }
    };
    stored_provider.env_override_fn = EmptyEnv.get;
    stored_provider.is_app_backend_disallowed_fn = null;
    try keyring_zig.setDefaultBackend(.file);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try testTmpDirPath(&tmp, gpa);
    defer gpa.free(root_path);
    const copilot_dir = try std.fs.path.join(gpa, &.{ root_path, "copilot-home" });
    defer gpa.free(copilot_dir);

    setTestOverrides(null, copilot_dir, testNoColorEnv);
    defer setTestOverrides(null, null, null);

    var empty_in = Io.Reader.fixed("");
    var out = Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    var err_out = Io.Writer.Allocating.init(gpa);
    defer err_out.deinit();

    for ([_]Subcommand{
        .{ .login = .{} },
        .{ .login = .{ .force = true } },
        .{ .logout = .{ .all = true } },
        .{ .token = .{} },
        .{ .env = .{ .shell = .sh } },
    }) |subcmd| {
        out.clearRetainingCapacity();
        err_out.clearRetainingCapacity();
        try std.testing.expectEqual(@as(u8, 4), try run(gpa, subcmd, &empty_in, &out.writer, &err_out.writer));
    }
}
