const std = @import("std");
const builtin = @import("builtin");
const keyring_zig = @import("keyring_zig");
const ado = @import("ado.zig");
const msal_cache = @import("msal_cache.zig");
const az_export = @import("az_export.zig");
const devops_npm = @import("devops_npm.zig");
const gh = @import("gh.zig");
const git_credential = @import("git_credential.zig");
const color = @import("color.zig");
const term = @import("term.zig");
const vault = @import("vault.zig");
const webauthn = @import("webauthn.zig");
const tunnel_http = @import("tunnel_http.zig");
const service = @import("service.zig");

test {
    _ = gh;
    _ = git_credential;
    _ = vault;
    _ = webauthn;
    _ = tunnel_http;
    _ = service;
}

var runtime_env_map: ?*std.process.Environ.Map = null;
var app_backend_override: ?Backend = null;
var app_env_backend_checked = false;
var app_env_backend: ?Backend = null;

const version = @import("app_build_options").version;
const usage =
    \\usage: keyring [--disable] [-b <backend>] <command> [args]
    \\
    \\Commands:
    \\  --help, -h, help              Show this help.
    \\  version                       Show version.
    \\  --list-backends               List available backends.
    \\  diagnose                      Show backend diagnostics.
    \\  service [options]             Run the built-in Secret Service daemon.
    \\  enroll [options]              Enroll, list, or revoke security keys.
    \\  unlock [options]              Unlock the built-in service.
    \\  lock                           Lock the built-in service immediately.
    \\  --disable                     Use the null backend for this process.
    \\  -b <backend>                  Use a backend for this process.
    \\  set <service> <user>          Store a password from stdin.
    \\  get <service> <user>          Read a password to stdout.
    \\  del <service> <user>          Delete a password.
    \\  az export <dir>               Export Azure CLI token cache to a directory.
    \\  gh login [options]            Authenticate with a GitHub host (github.com, *.ghe.com, GHES).
    \\  gh export <dir>               Export GitHub CLI credentials to <dir>/hosts.yml.
    \\  gh import [<dir-or-file>]     Import GitHub CLI credentials into the keyring.
    \\  git-credential <op>           Git credential helper protocol (get, store, erase).
    \\  git setup [options]           Configure Git to use keyring as its credential helper.
    \\  devops-npm [options]          Authenticate Azure DevOps npm feeds in .npmrc.
    \\
    \\Backends: secret_service, keychain, win_credential, file, ado, null_backend (or null)
    \\
    \\Environment:
    \\  KEYRING_BACKEND               Override backend: secret_service | keychain | win_credential | file | ado | null
    \\  KEYRING_PROPERTY_<NAME>       Backend-specific properties (e.g. KEYRING_PROPERTY_KEYCHAIN, KEYRING_PROPERTY_COLLECTION, KEYRING_PROPERTY_APPID)
    \\  NO_COLOR                      Disable ANSI colors in diagnostic output
    \\  CLICOLOR_FORCE                Force ANSI colors even when stdout is not a TTY
    \\  KEYRING_VAULT_PATH            Override the WebAuthn vault.json path
    \\
;

pub const ServiceArgs = struct {
    replace: bool = false,
    lock_timeout_seconds: ?u32 = null,
};

pub const EnrollArgs = struct {
    add_key: bool = false,
    list: bool = false,
    revoke: ?[]const u8 = null,
    force: bool = false,
    recover: bool = false,
    label: []const u8 = "security-key",
    port: u16 = 0,
    timeout_seconds: u32 = 120,
};

pub const UnlockArgs = struct {
    port: u16 = 0,
    timeout_seconds: u32 = 120,
    recover: bool = false,
};

pub const Command = union(enum) {
    help,
    version,
    list_backends,
    diagnose,
    service: ServiceArgs,
    enroll: EnrollArgs,
    unlock: UnlockArgs,
    lock,
    disabled_no_op,
    set: struct { service: []const u8, user: []const u8 },
    get: struct { service: []const u8, user: []const u8 },
    del: struct { service: []const u8, user: []const u8 },
    az_export: struct { dir: []const u8 },
    gh_login: gh.LoginOptions,
    gh_export: struct { dir: []const u8 },
    gh_import: struct { source: ?[]const u8 },
    git_credential: git_credential.Operation,
    git_setup: git_credential.SetupOptions,
    devops_npm: devops_npm.Options,
    usage_error: []const u8,
};

pub const ParsedArgs = struct {
    command: Command,
    backend: ?Backend = null,
    disable: bool = false,
};

pub const Backend = union(enum) {
    keyring: keyring_zig.Backend,
    ado,
};

fn backendEql(a: Backend, b: Backend) bool {
    return switch (a) {
        .ado => b == .ado,
        .keyring => |ak| switch (b) {
            .keyring => |bk| ak == bk,
            .ado => false,
        },
    };
}

pub fn main(init: std.process.Init) !void {
    runtime_env_map = init.environ_map;

    const arena = init.arena.allocator();
    const raw_args = try init.minimal.args.toSlice(arena);
    const args = try arena.alloc([]const u8, raw_args.len);
    for (raw_args, args) |raw, *arg| {
        arg.* = raw;
    }

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(init.io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    var stderr_buffer: [4096]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(init.io, &stderr_buffer);
    const stderr = &stderr_writer.interface;

    const parsed = parseArgs(args);
    if (parsed.backend) |backend| {
        switch (backend) {
            .ado => app_backend_override = .ado,
            .keyring => |keyring_backend| {
                keyring_zig.setDefaultBackend(keyring_backend) catch |err| switch (err) {
                    error.BackendUnavailable => {
                        try stderr.print("keyring: backend '{s}' not available on this platform\n", .{backendName(backend)});
                        try stderr.flush();
                        std.process.exit(4);
                    },
                };
                app_backend_override = backend;
            },
        }
    }
    if (parsed.disable) {
        keyring_zig.setDefaultBackend(.null_backend) catch {
            try stderr.writeAll("keyring: backend 'null_backend' not available on this platform\n");
            try stderr.flush();
            std.process.exit(4);
        };
        app_backend_override = .{ .keyring = .null_backend };
    }

    const exit_code = try runCommand(parsed.command, arena, init.io, stdout, stderr);
    std.process.exit(exit_code);
}

fn runCommand(command: Command, arena: std.mem.Allocator, io: std.Io, stdout: *std.Io.Writer, stderr: *std.Io.Writer) !u8 {
    return switch (command) {
        .help => code: {
            try stdout.writeAll(usage);
            try stdout.flush();
            break :code 0;
        },
        .version => code: {
            try stdout.print("keyring {s}\n", .{version});
            try stdout.flush();
            break :code 0;
        },
        .list_backends => code: {
            try listBackends(stdout);
            break :code 0;
        },
        .diagnose => code: {
            try diagnose(arena, stdout);
            break :code 0;
        },
        .service => |args| code: {
            _ = args.lock_timeout_seconds;
            service.runDaemon(arena, args.replace) catch |err| {
                try printAppError(stderr, normalizeServiceError(err), null, null);
                break :code 1;
            };
            break :code 0;
        },
        .enroll => |args| code: {
            runEnroll(arena, io, args, stdout, stderr) catch |err| {
                try printAppError(stderr, normalizeCeremonyError(err), null, null);
                break :code exitCodeFor(err);
            };
            break :code 0;
        },
        .unlock => |args| code: {
            runUnlock(arena, io, args, stderr) catch |err| {
                try printAppError(stderr, normalizeCeremonyError(err), null, null);
                break :code exitCodeFor(err);
            };
            break :code 0;
        },
        .lock => code: {
            if (builtin.os.tag != .linux) {
                try printAppError(stderr, error.Unsupported, null, null);
                break :code 1;
            }
            service.clientLockAll(arena) catch {
                try printAppError(stderr, error.ServiceNotRunning, null, null);
                break :code 1;
            };
            break :code 0;
        },
        .disabled_no_op => code: {
            try stderr.writeAll("disabled (no items will be stored or retrieved)\n");
            try stderr.flush();
            break :code 0;
        },
        .set => |cmd| code: {
            const password = term.readPassword(arena, io, stderr, cmd.service, cmd.user) catch {
                try stderr.writeAll("keyring: failed to read password\n");
                try stderr.flush();
                break :code 1;
            };
            setPassword(arena, cmd.service, cmd.user, password) catch |err| {
                try printAppError(stderr, err, cmd.service, cmd.user);
                break :code exitCodeFor(err);
            };
            break :code 0;
        },
        .get => |cmd| code: {
            const password = getPassword(arena, stderr, cmd.service, cmd.user) catch |err| {
                try printAppError(stderr, err, cmd.service, cmd.user);
                break :code exitCodeFor(err);
            };
            try stdout.writeAll(password);
            try stdout.flush();
            break :code 0;
        },
        .del => |cmd| code: {
            deletePassword(arena, cmd.service, cmd.user) catch |err| {
                try printAppError(stderr, err, cmd.service, cmd.user);
                break :code exitCodeFor(err);
            };
            break :code 0;
        },
        .az_export => |cmd| code: {
            break :code try az_export.run(arena, cmd.dir, stdout, stderr);
        },
        .gh_login => |opts| code: {
            break :code try gh.runLogin(arena, opts, stdout, stderr);
        },
        .gh_export => |cmd| code: {
            break :code try gh.runExport(arena, cmd.dir, stdout, stderr);
        },
        .gh_import => |cmd| code: {
            var stdin_buffer: [4096]u8 = undefined;
            var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buffer);
            break :code try gh.runImport(arena, cmd.source, &stdin_reader.interface, stdout, stderr);
        },
        .git_credential => |op| code: {
            var stdin_buffer: [4096]u8 = undefined;
            var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buffer);
            break :code try git_credential.runCredential(arena, op, &stdin_reader.interface, stdout, stderr);
        },
        .git_setup => |opts| code: {
            break :code try git_credential.runSetup(arena, opts, stdout, stderr);
        },
        .devops_npm => |opts| code: {
            break :code try devops_npm.run(arena, io, opts, stdout, stderr);
        },
        .usage_error => |message| code: {
            try stderr.print("keyring: {s}\n{s}", .{ message, usage });
            try stderr.flush();
            break :code 2;
        },
    };
}

pub fn parseArgs(args: []const []const u8) ParsedArgs {
    var parsed = ParsedArgs{ .command = .help };
    if (args.len >= 1 and git_credential.isGitCredentialArgv0(args[0])) {
        if (args.len == 2) {
            if (git_credential.Operation.fromString(args[1])) |op| {
                parsed.command = .{ .git_credential = op };
                return parsed;
            }
        }
        parsed.command = .{ .usage_error = "usage: git-credential-keyring <get|store|erase>" };
        return parsed;
    }
    if (args.len < 2) return parsed;

    var i: usize = 1;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--disable")) {
            parsed.disable = true;
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "-b")) {
            if (i + 1 >= args.len) return usageError("missing backend after -b", parsed);
            parsed.backend = parseBackendArg(args[i + 1]) orelse return usageError("unknown backend name", parsed);
            i += 2;
            continue;
        }
        break;
    }

    if (i >= args.len) {
        parsed.command = if (parsed.disable) .disabled_no_op else .help;
        return parsed;
    }

    const command = args[i];
    const rest = args[i + 1 ..];
    if (std.mem.eql(u8, command, "--help") or
        std.mem.eql(u8, command, "-h") or
        std.mem.eql(u8, command, "help"))
    {
        parsed.command = if (rest.len == 0) .help else .{ .usage_error = "wrong number of arguments" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "version")) {
        parsed.command = if (rest.len == 0) .version else .{ .usage_error = "wrong number of arguments" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "--list-backends")) {
        parsed.command = if (rest.len == 0) .list_backends else .{ .usage_error = "wrong number of arguments" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "diagnose")) {
        parsed.command = if (rest.len == 0) .diagnose else .{ .usage_error = "wrong number of arguments" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "service")) {
        parsed.command = parseServiceArgs(rest) orelse .{ .usage_error = "usage: keyring service [--replace] [--lock-timeout <seconds>]" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "enroll")) {
        parsed.command = parseEnrollArgs(rest) orelse .{ .usage_error = "usage: keyring enroll [--add-key|--list|--revoke <id>] [--force] [--recover] [--label <name>] [--port <u16>] [--timeout <seconds>]" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "unlock")) {
        parsed.command = parseUnlockArgs(rest) orelse .{ .usage_error = "usage: keyring unlock [--recover] [--port <u16>] [--timeout <seconds>]" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "lock")) {
        parsed.command = if (rest.len == 0) .lock else .{ .usage_error = "wrong number of arguments" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "set")) {
        parsed.command = if (rest.len == 2) .{ .set = .{ .service = rest[0], .user = rest[1] } } else .{ .usage_error = "wrong number of arguments" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "get")) {
        parsed.command = if (rest.len == 2) .{ .get = .{ .service = rest[0], .user = rest[1] } } else .{ .usage_error = "wrong number of arguments" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "del")) {
        parsed.command = if (rest.len == 2) .{ .del = .{ .service = rest[0], .user = rest[1] } } else .{ .usage_error = "wrong number of arguments" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "az")) {
        parsed.command = if (rest.len == 2 and std.mem.eql(u8, rest[0], "export"))
            .{ .az_export = .{ .dir = rest[1] } }
        else
            .{ .usage_error = "usage: keyring az export <dir>" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "gh")) {
        if (rest.len >= 1 and std.mem.eql(u8, rest[0], "login")) {
            parsed.command = if (gh.parseLoginArgs(rest[1..])) |opts|
                .{ .gh_login = opts }
            else
                .{ .usage_error = "usage: keyring gh login [--hostname <host>] [--scopes <scopes>] [--web|--device]" };
        } else if (rest.len == 2 and std.mem.eql(u8, rest[0], "export") and rest[1].len > 0) {
            parsed.command = .{ .gh_export = .{ .dir = rest[1] } };
        } else if (rest.len == 1 and std.mem.eql(u8, rest[0], "import")) {
            parsed.command = .{ .gh_import = .{ .source = null } };
        } else if (rest.len == 2 and std.mem.eql(u8, rest[0], "import") and rest[1].len > 0) {
            parsed.command = .{ .gh_import = .{ .source = rest[1] } };
        } else {
            parsed.command = .{ .usage_error = "usage: keyring gh <login [options] | export <dir> | import [<dir-or-file>]>" };
        }
        return parsed;
    }

    if (std.mem.eql(u8, command, "git-credential")) {
        if (rest.len == 1) {
            if (git_credential.Operation.fromString(rest[0])) |op| {
                parsed.command = .{ .git_credential = op };
                return parsed;
            }
        }
        parsed.command = .{ .usage_error = "usage: keyring git-credential <get|store|erase>" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "git")) {
        if (rest.len >= 1 and std.mem.eql(u8, rest[0], "setup")) {
            parsed.command = if (git_credential.parseSetupArgs(rest[1..])) |opts|
                .{ .git_setup = opts }
            else
                .{ .usage_error = "usage: keyring git setup [--hostname <host>] [--global|--local]" };
        } else {
            parsed.command = .{ .usage_error = "usage: keyring git setup [--hostname <host>] [--global|--local]" };
        }
        return parsed;
    }

    if (std.mem.eql(u8, command, "devops-npm")) {
        parsed.command = if (devops_npm.parseArgs(rest)) |opts|
            .{ .devops_npm = opts }
        else
            .{ .usage_error = "usage: keyring devops-npm [-c <path>] [-f|--force] [--validate-only]" };
        return parsed;
    }

    parsed.command = if (std.mem.startsWith(u8, command, "-")) .{ .usage_error = "unknown flag" } else .{ .usage_error = "unknown command" };
    return parsed;
}

fn parseServiceArgs(args: []const []const u8) ?Command {
    var result: ServiceArgs = .{};
    var index: usize = 0;
    while (index < args.len) {
        if (std.mem.eql(u8, args[index], "--replace")) {
            result.replace = true;
            index += 1;
        } else if (std.mem.eql(u8, args[index], "--lock-timeout")) {
            if (index + 1 >= args.len) return null;
            result.lock_timeout_seconds = parsePositiveU32(args[index + 1]) orelse return null;
            index += 2;
        } else return null;
    }
    return .{ .service = result };
}

fn parseEnrollArgs(args: []const []const u8) ?Command {
    var result: EnrollArgs = .{};
    var action_count: u8 = 0;
    var index: usize = 0;
    while (index < args.len) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--add-key")) {
            result.add_key = true;
            action_count += 1;
            index += 1;
        } else if (std.mem.eql(u8, arg, "--list")) {
            result.list = true;
            action_count += 1;
            index += 1;
        } else if (std.mem.eql(u8, arg, "--revoke")) {
            if (index + 1 >= args.len) return null;
            result.revoke = args[index + 1];
            action_count += 1;
            index += 2;
        } else if (std.mem.eql(u8, arg, "--force")) {
            result.force = true;
            index += 1;
        } else if (std.mem.eql(u8, arg, "--recover")) {
            result.recover = true;
            index += 1;
        } else if (std.mem.eql(u8, arg, "--label")) {
            if (index + 1 >= args.len or args[index + 1].len == 0) return null;
            result.label = args[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, arg, "--port")) {
            if (index + 1 >= args.len) return null;
            result.port = std.fmt.parseInt(u16, args[index + 1], 10) catch return null;
            index += 2;
        } else if (std.mem.eql(u8, arg, "--timeout")) {
            if (index + 1 >= args.len) return null;
            result.timeout_seconds = parsePositiveU32(args[index + 1]) orelse return null;
            index += 2;
        } else return null;
    }
    if (action_count > 1) return null;
    if (result.force and result.revoke == null) return null;
    return .{ .enroll = result };
}

fn parseUnlockArgs(args: []const []const u8) ?Command {
    var result: UnlockArgs = .{};
    var index: usize = 0;
    while (index < args.len) {
        if (std.mem.eql(u8, args[index], "--recover")) {
            result.recover = true;
            index += 1;
        } else if (std.mem.eql(u8, args[index], "--port")) {
            if (index + 1 >= args.len) return null;
            result.port = std.fmt.parseInt(u16, args[index + 1], 10) catch return null;
            index += 2;
        } else if (std.mem.eql(u8, args[index], "--timeout")) {
            if (index + 1 >= args.len) return null;
            result.timeout_seconds = parsePositiveU32(args[index + 1]) orelse return null;
            index += 2;
        } else return null;
    }
    return .{ .unlock = result };
}

fn parsePositiveU32(value: []const u8) ?u32 {
    const parsed = std.fmt.parseInt(u32, value, 10) catch return null;
    return if (parsed == 0) null else parsed;
}

fn usageError(message: []const u8, parsed: ParsedArgs) ParsedArgs {
    var result = parsed;
    result.command = .{ .usage_error = message };
    return result;
}

fn parseBackendArg(name: []const u8) ?Backend {
    if (std.mem.eql(u8, name, "secret_service")) return .{ .keyring = .secret_service };
    if (std.mem.eql(u8, name, "keychain")) return .{ .keyring = .keychain };
    if (std.mem.eql(u8, name, "win_credential")) return .{ .keyring = .win_credential };
    if (std.mem.eql(u8, name, "file")) return .{ .keyring = .file };
    if (std.mem.eql(u8, name, "ado") or std.mem.eql(u8, name, "azure_devops")) return .ado;
    if (std.mem.eql(u8, name, "null") or std.mem.eql(u8, name, "null_backend")) return .{ .keyring = .null_backend };
    return null;
}

fn listBackends(stdout: *std.Io.Writer) !void {
    const colors = color.Color.detect(getEnvVar, term.isStdoutTty());
    var buffer: [5]keyring_zig.Backend = undefined;
    const available = keyring_zig.availableBackends(&buffer);
    const current = currentBackend();
    for (available) |backend| {
        const app_backend = Backend{ .keyring = backend };
        if (backendEql(app_backend, current)) {
            try stdout.print("{s}*{s}{s} {s}(default){s}\n", .{ colors.green(), colors.reset(), backendName(app_backend), colors.green(), colors.reset() });
        } else {
            try stdout.print("{s}\n", .{backendName(app_backend)});
        }
    }
    if (backendEql(.ado, current)) {
        try stdout.print("{s}*{s}ado {s}(default){s}\n", .{ colors.green(), colors.reset(), colors.green(), colors.reset() });
    } else {
        try stdout.writeAll("ado\n");
    }
    try stdout.flush();
}

fn runEnroll(
    arena: std.mem.Allocator,
    io: std.Io,
    args: EnrollArgs,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) !void {
    if (builtin.os.tag != .linux) return error.Unsupported;

    if (args.list) {
        var document = try loadEnrolledVault(arena);
        defer document.deinit();
        for (document.value.prf_slots) |slot| {
            try stdout.print(
                "id={s}\tlabel={s}\tcose_alg={d}\tcreated_at={d}\tlast_used_at={s}\n",
                .{
                    slot.id,
                    slot.label,
                    slot.cose_alg,
                    slot.created_at,
                    if (slot.last_used_at) |value|
                        try std.fmt.allocPrint(arena, "{d}", .{value})
                    else
                        "never",
                },
            );
        }
        try stdout.flush();
        return;
    }

    if (args.revoke) |slot_id| {
        var document = try loadEnrolledVault(arena);
        defer document.deinit();
        try authorizeRevocation(arena, io, &document, args, stderr);
        try revokePrfSlot(&document, slot_id, args.force);
        try vault.saveVaultEnvelope(arena, &document.value);
        try stdout.print("Revoked security key {s}.\n", .{slot_id});
        try stdout.flush();
        return;
    }

    const existing = vault.loadVaultEnvelope(arena);
    if (existing) |document_value| {
        var document = document_value;
        defer document.deinit();
        if (!args.add_key and !args.recover) return error.VaultAlreadyEnrolled;

        var dek = try authorizeVault(arena, io, &document, args.recover, args.port, args.timeout_seconds, stderr);
        defer std.crypto.secureZero(u8, &dek);
        var prf_salt: [vault.prf_salt_len]u8 = undefined;
        secureRandom(io, &prf_salt);
        var registration = try runRegistration(
            arena,
            io,
            try storeIdFromHex(document.value.store_id_hex),
            prf_salt,
            args.port,
            args.timeout_seconds,
            stderr,
        );
        defer registration.deinit(arena);
        try vault.addPrfSlot(&document, io, dek, .{
            .label = args.label,
            .credential_id = registration.credential_id,
            .cose_alg = registration.cose_alg,
            .public_key = registration.public_key,
            .sign_count = registration.sign_count,
            .prf_output = registration.prf_output,
            .prf_salt = prf_salt,
            .created_at = unixNow(),
        });
        try vault.saveVaultEnvelope(arena, &document.value);
        try unlockRunningService(arena, dek, true);
        try stdout.print("Enrolled security key '{s}'.\n", .{args.label});
        try stdout.flush();
        return;
    } else |err| switch (err) {
        error.VaultNotFound => {},
        else => return err,
    }

    if (args.add_key or args.recover) return error.VaultNotFound;

    var store_id: [vault.store_id_len]u8 = undefined;
    var prf_salt: [vault.prf_salt_len]u8 = undefined;
    secureRandom(io, &store_id);
    secureRandom(io, &prf_salt);
    var registration = try runRegistration(
        arena,
        io,
        store_id,
        prf_salt,
        args.port,
        args.timeout_seconds,
        stderr,
    );
    defer registration.deinit(arena);
    var enrolled = try vault.enrollInitialVault(arena, io, .{
        .label = args.label,
        .credential_id = registration.credential_id,
        .cose_alg = registration.cose_alg,
        .public_key = registration.public_key,
        .sign_count = registration.sign_count,
        .prf_output = registration.prf_output,
        .prf_salt = prf_salt,
        .created_at = unixNow(),
    }, .{
        .store_id = store_id,
        .prf_salt = prf_salt,
    });
    defer enrolled.deinit();
    try vault.saveVaultEnvelope(arena, &enrolled.document.value);
    try stdout.print(
        "\nRECOVERY KEY (store this once in a safe place):\n{s}\n\n",
        .{enrolled.recovery_key},
    );
    try stdout.flush();
    try unlockRunningService(arena, enrolled.dek, true);
}

fn runUnlock(
    arena: std.mem.Allocator,
    io: std.Io,
    args: UnlockArgs,
    stderr: *std.Io.Writer,
) !void {
    if (builtin.os.tag != .linux) return error.Unsupported;
    var document = try loadEnrolledVault(arena);
    defer document.deinit();
    var status = service.clientGetStatus(arena) catch return error.ServiceNotRunning;
    defer status.deinit(arena);

    var dek: [vault.dek_len]u8 = if (args.recover)
        try unwrapWithRecoveryPrompt(arena, io, &document, stderr)
    else
        try runUnlockCeremony(arena, io, &document, args.port, args.timeout_seconds, stderr, true);
    defer std.crypto.secureZero(u8, &dek);
    const unlocked = service.clientUnlockWithMasterKey(arena, dek) catch return error.ServiceUnlockFailed;
    if (!unlocked) return error.ServiceUnlockFailed;
}

fn runRegistration(
    arena: std.mem.Allocator,
    io: std.Io,
    store_id: [vault.store_id_len]u8,
    prf_salt: [vault.prf_salt_len]u8,
    port: u16,
    timeout_seconds: u32,
    stderr: *std.Io.Writer,
) !webauthn.VerifiedRegistration {
    const store_id_b64 = try base64UrlAlloc(arena, &store_id);
    const prf_salt_b64 = try base64UrlAlloc(arena, &prf_salt);
    var server = try tunnel_http.Server.init(arena, io, .{
        .mode = .enroll,
        .port = port,
        .timeout_ms = try timeoutMilliseconds(timeout_seconds),
        .store_id_b64 = store_id_b64,
        .enrollment_prf_salt_b64 = prf_salt_b64,
    });
    defer server.deinit();
    try server.writeInstructions(stderr, try sshTarget(arena));
    const result = try server.run();
    return result.enroll;
}

fn runUnlockCeremony(
    arena: std.mem.Allocator,
    io: std.Io,
    document: *vault.VaultDocument,
    port: u16,
    timeout_seconds: u32,
    stderr: *std.Io.Writer,
    persist_counter: bool,
) ![vault.dek_len]u8 {
    const credentials = try arena.alloc(tunnel_http.Credential, document.value.prf_slots.len);
    for (document.value.prf_slots, credentials) |slot, *credential| {
        credential.* = .{
            .credential_id_b64 = slot.credential_id_b64,
            .cose_alg = slot.cose_alg,
            .public_key_b64 = slot.public_key_b64,
            .sign_count = slot.sign_count,
            .prf_salt_b64 = slot.prf_salt_b64,
        };
    }
    const store_id = try storeIdFromHex(document.value.store_id_hex);
    const store_id_b64 = try base64UrlAlloc(arena, &store_id);
    var server = try tunnel_http.Server.init(arena, io, .{
        .mode = .unlock,
        .port = port,
        .timeout_ms = try timeoutMilliseconds(timeout_seconds),
        .store_id_b64 = store_id_b64,
        .credentials = credentials,
    });
    defer server.deinit();
    try server.writeInstructions(stderr, try sshTarget(arena));
    var result = try server.run();
    defer result.deinit(arena);
    const credential_id_b64 = try base64UrlAlloc(arena, result.unlock.credential_id);
    const slot = for (document.value.prf_slots) |*candidate| {
        if (std.mem.eql(u8, candidate.credential_id_b64, credential_id_b64)) break candidate;
    } else return error.AuthenticationFailed;

    var dek = try vault.unwrapDekWithPrf(arena, result.unlock.prf_output, store_id, slot);
    errdefer std.crypto.secureZero(u8, &dek);
    if (persist_counter) {
        vault.updateSlotSignCount(
            &document.value,
            slot.id,
            result.unlock.new_sign_count,
            unixNow(),
        ) catch |err| switch (err) {
            error.InvalidSignCount => return error.ClonedAuthenticator,
            else => return err,
        };
        try vault.saveVaultEnvelope(arena, &document.value);
    }
    return dek;
}

fn authorizeVault(
    arena: std.mem.Allocator,
    io: std.Io,
    document: *vault.VaultDocument,
    recover: bool,
    port: u16,
    timeout_seconds: u32,
    stderr: *std.Io.Writer,
) ![vault.dek_len]u8 {
    if (recover) return unwrapWithRecoveryPrompt(arena, io, document, stderr);
    return runUnlockCeremony(arena, io, document, port, timeout_seconds, stderr, false);
}

fn authorizeRevocation(
    arena: std.mem.Allocator,
    io: std.Io,
    document: *vault.VaultDocument,
    args: EnrollArgs,
    stderr: *std.Io.Writer,
) !void {
    if (!args.recover) {
        if (service.clientGetStatus(arena)) |status_value| {
            var status = status_value;
            defer status.deinit(arena);
            if (!status.locked) return;
        } else |_| {}
    }
    var dek = try authorizeVault(arena, io, document, args.recover, args.port, args.timeout_seconds, stderr);
    std.crypto.secureZero(u8, &dek);
}

fn unwrapWithRecoveryPrompt(
    arena: std.mem.Allocator,
    io: std.Io,
    document: *vault.VaultDocument,
    stderr: *std.Io.Writer,
) ![vault.dek_len]u8 {
    const input = try term.readPassword(arena, io, stderr, "keyring vault", "Recovery Key");
    defer std.crypto.secureZero(u8, input);
    var normalized = try vault.normalizeRecoveryKey(input);
    defer std.crypto.secureZero(u8, &normalized);
    return vault.unwrapDekWithRecovery(
        arena,
        &normalized,
        try storeIdFromHex(document.value.store_id_hex),
        &document.value.recovery_slot,
    );
}

fn loadEnrolledVault(arena: std.mem.Allocator) !vault.VaultDocument {
    return vault.loadVaultEnvelope(arena) catch |err| switch (err) {
        error.VaultNotFound => return error.VaultNotFound,
        else => return err,
    };
}

fn revokePrfSlot(document: *vault.VaultDocument, id: []const u8, force: bool) !void {
    if (!force) return vault.revokePrfSlot(document, id);
    const old = document.value.prf_slots;
    var remove_index: ?usize = null;
    for (old, 0..) |slot, index| {
        if (std.mem.eql(u8, slot.id, id)) {
            remove_index = index;
            break;
        }
    }
    const index = remove_index orelse return error.SlotNotFound;
    const slots = try document.allocator().alloc(vault.PrfKeySlot, old.len - 1);
    @memcpy(slots[0..index], old[0..index]);
    @memcpy(slots[index..], old[index + 1 ..]);
    document.value.prf_slots = slots;
}

fn unlockRunningService(arena: std.mem.Allocator, dek: [vault.dek_len]u8, ignore_not_running: bool) !void {
    var status = service.clientGetStatus(arena) catch {
        if (ignore_not_running) return;
        return error.ServiceNotRunning;
    };
    defer status.deinit(arena);
    const unlocked = service.clientUnlockWithMasterKey(arena, dek) catch return error.ServiceUnlockFailed;
    if (!unlocked) return error.ServiceUnlockFailed;
}

fn storeIdFromHex(encoded: []const u8) ![vault.store_id_len]u8 {
    if (encoded.len != vault.store_id_len * 2) return error.InvalidVault;
    var result: [vault.store_id_len]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch return error.InvalidVault;
    return result;
}

fn base64UrlAlloc(arena: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const output = try arena.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(bytes.len));
    _ = std.base64.url_safe_no_pad.Encoder.encode(output, bytes);
    return output;
}

fn timeoutMilliseconds(seconds: u32) !u32 {
    return std.math.mul(u32, seconds, 1000) catch error.InvalidTimeout;
}

fn secureRandom(io: std.Io, bytes: []u8) void {
    io.randomSecure(bytes) catch io.random(bytes);
}

fn unixNow() i64 {
    return std.Io.Clock.real.now(std.Io.Threaded.global_single_threaded.io()).toSeconds();
}

fn sshTarget(arena: std.mem.Allocator) ![]const u8 {
    const user = getEnvVar("USER") orelse "user";
    const host = getEnvVar("HOSTNAME") orelse "remote-host";
    return std.fmt.allocPrint(arena, "{s}@{s}", .{ user, host });
}

fn normalizeCeremonyError(err: anyerror) anyerror {
    return switch (err) {
        error.PrfUnsupported,
        error.DecryptionFailed,
        error.ServiceNotRunning,
        error.ServiceUnlockFailed,
        error.ClonedAuthenticator,
        error.Timeout,
        error.VaultNotFound,
        error.VaultAlreadyEnrolled,
        error.LastPrfSlot,
        error.SlotNotFound,
        => err,
        error.SignatureInvalid,
        error.InvalidAttestationObject,
        error.InvalidAuthenticatorData,
        error.InvalidClientData,
        error.ChallengeMismatch,
        error.OriginMismatch,
        error.RpIdMismatch,
        error.UserNotPresent,
        error.AttestedCredentialDataMissing,
        error.InvalidCoseKey,
        error.UnsupportedAlgorithm,
        error.InvalidRequest,
        error.ChallengeConsumed,
        => error.AuthenticationFailed,
        else => err,
    };
}

fn normalizeServiceError(err: anyerror) anyerror {
    return switch (err) {
        error.NameAlreadyOwned => error.ServiceAlreadyRunning,
        else => err,
    };
}

fn diagnose(arena: std.mem.Allocator, stdout: *std.Io.Writer) !void {
    const colors = color.Color.detect(getEnvVar, term.isStdoutTty());
    const current = currentBackend();
    var buffer: [5]keyring_zig.Backend = undefined;
    const available = keyring_zig.availableBackends(&buffer);

    try stdout.print("current backend: {s}{s}{s}\n", .{ colors.green(), backendName(current), colors.reset() });
    try stdout.writeAll("available backends: ");
    for (available, 0..) |backend, index| {
        if (index != 0) try stdout.writeAll(", ");
        const app_backend = Backend{ .keyring = backend };
        if (backendEql(app_backend, current)) {
            try stdout.print("{s}{s}{s}{s}", .{ colors.bold(), colors.green(), backendName(app_backend), colors.reset() });
        } else {
            try stdout.writeAll(backendName(app_backend));
        }
    }
    if (available.len != 0) try stdout.writeAll(", ");
    if (backendEql(.ado, current)) {
        try stdout.print("{s}{s}ado{s}", .{ colors.bold(), colors.green(), colors.reset() });
    } else {
        try stdout.writeAll("ado");
    }
    try stdout.writeByte('\n');

    if (try getEnvVarOwned(arena, "KEYRING_BACKEND")) |value| {
        try stdout.print("KEYRING_BACKEND env: {s}{s}{s}\n", .{ colors.bold(), value, colors.reset() });
    } else {
        try stdout.writeAll("KEYRING_BACKEND env: unset\n");
    }
    try diagnoseProperties(arena, stdout);

    if (builtin.os.tag == .linux) {
        if (vault.loadVaultEnvelope(arena)) |document_value| {
            var document = document_value;
            defer document.deinit();
            try stdout.print("vault status: enrolled ({d} keys)\n", .{document.value.prf_slots.len});
        } else |err| switch (err) {
            error.VaultNotFound => try stdout.writeAll("vault status: not enrolled\n"),
            else => try stdout.print("vault status: unavailable ({s})\n", .{@errorName(err)}),
        }
        if (service.clientGetStatus(arena)) |status_value| {
            var status = status_value;
            defer status.deinit(arena);
            try stdout.print("keyring service: running ({s})\n", .{if (status.locked) "locked" else "unlocked"});
        } else |_| {
            try stdout.writeAll("keyring service: not running\n");
        }

        const probe_service = "keyring-cli-diagnose-service-that-should-not-exist";
        const user = "keyring-cli-diagnose-user-that-should-not-exist";
        if (getPassword(arena, stdout, probe_service, user)) |password| {
            _ = password;
        } else |err| switch (err) {
            error.NoStorageAccess => try printLinuxNoStorageAccessHint(stdout, colors),
            else => {},
        }
    } else {
        const probe_service = "keyring-cli-diagnose-service-that-should-not-exist";
        const user = "keyring-cli-diagnose-user-that-should-not-exist";
        if (getPassword(arena, stdout, probe_service, user)) |password| {
            _ = password;
            try stdout.writeAll("backend reachable: yes\n");
        } else |err| switch (err) {
            error.EntryNotFound => try stdout.writeAll("backend reachable: yes\n"),
            else => try stdout.print("backend reachable: no ({s})\n", .{@errorName(err)}),
        }
    }
    msal_cache.diagnose(arena, stdout) catch {};
    ado.diagnoseCache(arena, stdout) catch {};
    gh.diagnoseHosts(arena, stdout) catch {};
    try stdout.flush();
}

fn printLinuxNoStorageAccessHint(stdout: *std.Io.Writer, colors: color.Color) !void {
    try stdout.print("{s}note:{s} no Secret Service daemon detected.\n", .{ colors.yellow(), colors.reset() });
    try stdout.print("{s}note:{s} start the built-in provider with 'keyring service', initialize it with 'keyring enroll', then use 'keyring unlock'.\n", .{ colors.yellow(), colors.reset() });
    try stdout.print("{s}note:{s} install oo7-daemon (pure Rust, MIT, headless-friendly): https://github.com/linux-credentials/oo7\n", .{ colors.yellow(), colors.reset() });
    try stdout.print("{s}note:{s} or start GNOME Secrets with gnome-keyring-daemon --unlock --components=secrets under dbus-run-session.\n", .{ colors.yellow(), colors.reset() });
    try stdout.print("{s}note:{s} or use KEYRING_BACKEND=file for encrypted on-disk credentials.\n", .{ colors.yellow(), colors.reset() });
}

fn diagnoseProperties(arena: std.mem.Allocator, stdout: *std.Io.Writer) !void {
    const properties = [_]struct {
        name: []const u8,
        env_name: []const u8,
    }{
        .{ .name = "keychain", .env_name = "KEYRING_PROPERTY_KEYCHAIN" },
        .{ .name = "collection", .env_name = "KEYRING_PROPERTY_COLLECTION" },
        .{ .name = "appid", .env_name = "KEYRING_PROPERTY_APPID" },
        .{ .name = "file_path", .env_name = "KEYRING_PROPERTY_FILE_PATH" },
    };

    var any_set = false;
    for (properties) |property| {
        if (try keyring_zig.getProperty(arena, property.name)) |value| {
            try stdout.print("{s}: {s}\n", .{ property.env_name, value });
            any_set = true;
        }
    }
    if (!any_set) try stdout.writeAll("KEYRING_PROPERTY_*: none set\n");
}

fn getEnvVar(name: []const u8) ?[]const u8 {
    if (runtime_env_map) |env_map| return env_map.get(name);
    if (builtin.os.tag == .wasi or builtin.os.tag == .windows) return null;

    var i: usize = 0;
    while (std.c.environ[i]) |entry| : (i += 1) {
        const item = std.mem.span(entry);
        if (item.len >= name.len + 1 and item[name.len] == '=' and std.mem.eql(u8, item[0..name.len], name)) {
            return item[name.len + 1 ..];
        }
    }
    return null;
}

fn getEnvVarOwned(gpa: std.mem.Allocator, name: []const u8) !?[]u8 {
    if (builtin.os.tag == .wasi) return null;

    if (builtin.os.tag == .windows) {
        var map = std.process.Environ.createMap(.{ .block = .global }, gpa) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        };
        defer map.deinit();
        if (map.get(name)) |value| return try gpa.dupe(u8, value);
        return null;
    }

    var i: usize = 0;
    while (std.c.environ[i]) |entry| : (i += 1) {
        const item = std.mem.span(entry);
        if (item.len > name.len and item[name.len] == '=' and std.mem.eql(u8, item[0..name.len], name)) {
            return try gpa.dupe(u8, item[name.len + 1 ..]);
        }
    }
    return null;
}

fn currentBackend() Backend {
    return effectiveBackend(null);
}

/// Pick the backend for an operation. When the caller did not pick a backend
/// explicitly (no `-b`, no `--disable`, no `KEYRING_BACKEND` env var) and the
/// service string looks like an Azure DevOps URL, route to the `ado` backend
/// so tools like uv "just work" against ADO package feeds.
fn effectiveBackend(service_name: ?[]const u8) Backend {
    if (app_backend_override) |backend| return backend;
    if (!app_env_backend_checked) {
        app_env_backend = readAppEnvBackend();
        app_env_backend_checked = true;
    }
    if (app_env_backend) |backend| return backend;
    if (service_name) |s| {
        if (ado.isDevOpsUrl(s)) return .ado;
    }
    return .{ .keyring = keyring_zig.currentBackend() };
}

fn readAppEnvBackend() ?Backend {
    const value = getEnvVar("KEYRING_BACKEND") orelse return null;
    if (std.mem.eql(u8, value, "ado") or std.mem.eql(u8, value, "azure_devops")) return .ado;
    return null;
}

fn backendName(backend: Backend) []const u8 {
    return switch (backend) {
        .ado => "ado",
        .keyring => |keyring_backend| switch (keyring_backend) {
            .secret_service => "secret_service",
            .keychain => "keychain",
            .win_credential => "win_credential",
            .file => "file",
            .null_backend => "null_backend",
        },
    };
}

fn getPassword(arena: std.mem.Allocator, stderr: *std.Io.Writer, service_name: []const u8, user: []const u8) (keyring_zig.Error || ado.Error)![]u8 {
    return switch (effectiveBackend(service_name)) {
        .ado => ado.getPassword(arena, stderr, service_name, user),
        .keyring => keyring_zig.getAlloc(arena, service_name, user),
    };
}

fn setPassword(arena: std.mem.Allocator, service_name: []const u8, user: []const u8, password: []const u8) (keyring_zig.Error || ado.Error)!void {
    return switch (effectiveBackend(service_name)) {
        .ado => ado.setPassword(arena, service_name, user, password),
        .keyring => keyring_zig.setAlloc(arena, service_name, user, password),
    };
}

fn deletePassword(arena: std.mem.Allocator, service_name: []const u8, user: []const u8) (keyring_zig.Error || ado.Error)!void {
    return switch (effectiveBackend(service_name)) {
        .ado => ado.deletePassword(arena),
        .keyring => keyring_zig.deleteAlloc(arena, service_name, user),
    };
}

pub fn exitCodeFor(err: anyerror) u8 {
    return switch (err) {
        error.EntryNotFound => 3,
        error.NoStorageAccess => 4,
        // A bad KEYRING_ADO_STORE value is a configuration mistake, not a
        // storage failure: report it like other invalid usage.
        error.InvalidStoreSelector => 2,
        error.Locked,
        error.PlatformFailure,
        error.Ambiguous,
        error.OutOfMemory,
        error.InputTooLong,
        error.BufferTooSmall,
        error.InvalidUtf8,
        error.Unsupported,
        error.AuthenticationFailed,
        error.NetworkFailure,
        error.CacheFailure,
        => 1,
        else => 1,
    };
}

fn printAppError(stderr: *std.Io.Writer, err: anyerror, service_name: ?[]const u8, user: ?[]const u8) !void {
    const msg = errorMessage(err);
    if (entryErrorContext(err) and service_name != null and user != null) {
        try stderr.print("keyring: error: {s}: service='{s}' user='{s}'\n", .{ msg, service_name.?, user.? });
    } else {
        try stderr.print("keyring: error: {s}\n", .{msg});
    }
    try stderr.flush();
}

fn entryErrorContext(err: anyerror) bool {
    return switch (err) {
        error.EntryNotFound,
        error.Locked,
        error.Ambiguous,
        error.AuthenticationFailed,
        error.Unsupported,
        => true,
        else => false,
    };
}

fn errorMessage(err: anyerror) []const u8 {
    return switch (err) {
        error.EntryNotFound => "entry not found",
        error.NoStorageAccess => "no storage access",
        error.Locked => "locked",
        error.PlatformFailure => "platform failure",
        error.Ambiguous => "ambiguous",
        error.OutOfMemory => "out of memory",
        error.InputTooLong => "input too long",
        error.BufferTooSmall => "buffer too small",
        error.InvalidUtf8 => "invalid utf8",
        error.Unsupported => "operation unsupported by backend",
        error.AuthenticationFailed => "WebAuthn authentication failed",
        error.PrfUnsupported => "security key or browser does not support the WebAuthn PRF (hmac-secret) extension required for key derivation",
        error.DecryptionFailed => "failed to unwrap vault key (decryption failed)",
        error.ServiceNotRunning => "keyring service is not running on the D-Bus session bus (start it with 'keyring service')",
        error.ServiceUnlockFailed => "failed to unlock Secret Service provider",
        error.ClonedAuthenticator => "security key signature counter did not increase (possible cloned authenticator)",
        error.Timeout => "timed out waiting for browser WebAuthn approval",
        error.VaultNotFound => "vault is not enrolled (run 'keyring enroll')",
        error.VaultAlreadyEnrolled => "vault is already enrolled (use 'keyring enroll --add-key')",
        error.LastPrfSlot => "refusing to revoke the last security key (use --force to rely on the Recovery Key)",
        error.SlotNotFound => "security key enrollment not found",
        error.ServiceAlreadyRunning => "Secret Service name is already owned (use 'keyring service --replace' to replace it)",
        error.InvalidTimeout => "timeout is too large",
        error.NetworkFailure => "network failure",
        error.CacheFailure => "cache failure",
        error.InvalidStoreSelector => "invalid KEYRING_ADO_STORE value: expected 'file' or 'secret'",
        else => "platform failure",
    };
}

fn expectCommandTag(expected: std.meta.Tag(Command), parsed: ParsedArgs) !void {
    try std.testing.expectEqual(expected, std.meta.activeTag(parsed.command));
}

fn expectUsage(parsed: ParsedArgs) !void {
    try expectCommandTag(.usage_error, parsed);
}

test "parseArgs recognizes simple commands" {
    try expectCommandTag(.help, parseArgs(&.{"keyring"}));
    try expectCommandTag(.help, parseArgs(&.{ "keyring", "--help" }));
    try expectCommandTag(.help, parseArgs(&.{ "keyring", "-h" }));
    try expectCommandTag(.help, parseArgs(&.{ "keyring", "help" }));
    try expectCommandTag(.version, parseArgs(&.{ "keyring", "version" }));
    try expectCommandTag(.list_backends, parseArgs(&.{ "keyring", "--list-backends" }));
    try expectCommandTag(.diagnose, parseArgs(&.{ "keyring", "diagnose" }));
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, haystack, needle) != null);
}

test "runCommand dispatches help list-backends diagnose" {
    try keyring_zig.setDefaultBackend(.null_backend);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var stdout = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer stdout.deinit();
    var stderr = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer stderr.deinit();

    try std.testing.expectEqual(@as(u8, 0), try runCommand(.help, allocator, undefined, &stdout.writer, &stderr.writer));
    const help_output = try stdout.toOwnedSlice();
    defer std.testing.allocator.free(help_output);
    try expectContains(help_output, "usage: keyring");

    try std.testing.expectEqual(@as(u8, 0), try runCommand(.list_backends, allocator, undefined, &stdout.writer, &stderr.writer));
    const backends_output = try stdout.toOwnedSlice();
    defer std.testing.allocator.free(backends_output);
    try expectContains(backends_output, "null_backend");
    try expectContains(backends_output, "ado");

    try std.testing.expectEqual(@as(u8, 0), try runCommand(.diagnose, allocator, undefined, &stdout.writer, &stderr.writer));
    const diagnose_output = try stdout.toOwnedSlice();
    defer std.testing.allocator.free(diagnose_output);
    try expectContains(diagnose_output, "current backend: null_backend");
    try expectContains(diagnose_output, "KEYRING_BACKEND env:");
}

test "parseArgs recognizes set get del" {
    const set = parseArgs(&.{ "keyring", "set", "svc", "user" });
    try expectCommandTag(.set, set);
    try std.testing.expectEqualStrings("svc", set.command.set.service);
    try std.testing.expectEqualStrings("user", set.command.set.user);

    const get = parseArgs(&.{ "keyring", "get", "svc", "user" });
    try expectCommandTag(.get, get);
    try std.testing.expectEqualStrings("svc", get.command.get.service);
    try std.testing.expectEqualStrings("user", get.command.get.user);

    const del = parseArgs(&.{ "keyring", "del", "svc", "user" });
    try expectCommandTag(.del, del);
    try std.testing.expectEqualStrings("svc", del.command.del.service);
    try std.testing.expectEqualStrings("user", del.command.del.user);
}

test "parseArgs recognizes service enroll unlock and lock" {
    const service_command = parseArgs(&.{ "keyring", "service", "--replace", "--lock-timeout", "600" });
    try expectCommandTag(.service, service_command);
    try std.testing.expect(service_command.command.service.replace);
    try std.testing.expectEqual(@as(?u32, 600), service_command.command.service.lock_timeout_seconds);

    const enroll = parseArgs(&.{
        "keyring", "enroll", "--add-key", "--recover", "--label", "backup",
        "--port",  "8123",   "--timeout", "45",
    });
    try expectCommandTag(.enroll, enroll);
    try std.testing.expect(enroll.command.enroll.add_key);
    try std.testing.expect(enroll.command.enroll.recover);
    try std.testing.expectEqualStrings("backup", enroll.command.enroll.label);
    try std.testing.expectEqual(@as(u16, 8123), enroll.command.enroll.port);
    try std.testing.expectEqual(@as(u32, 45), enroll.command.enroll.timeout_seconds);

    const list = parseArgs(&.{ "keyring", "enroll", "--list" });
    try expectCommandTag(.enroll, list);
    try std.testing.expect(list.command.enroll.list);

    const revoke = parseArgs(&.{ "keyring", "enroll", "--revoke", "deadbeef", "--force" });
    try expectCommandTag(.enroll, revoke);
    try std.testing.expectEqualStrings("deadbeef", revoke.command.enroll.revoke.?);
    try std.testing.expect(revoke.command.enroll.force);

    const recover_enroll = parseArgs(&.{ "keyring", "enroll", "--recover" });
    try expectCommandTag(.enroll, recover_enroll);
    try std.testing.expect(recover_enroll.command.enroll.recover);

    const unlock = parseArgs(&.{ "keyring", "unlock", "--port", "9123", "--timeout", "30", "--recover" });
    try expectCommandTag(.unlock, unlock);
    try std.testing.expectEqual(@as(u16, 9123), unlock.command.unlock.port);
    try std.testing.expectEqual(@as(u32, 30), unlock.command.unlock.timeout_seconds);
    try std.testing.expect(unlock.command.unlock.recover);

    try expectCommandTag(.lock, parseArgs(&.{ "keyring", "lock" }));
}

test "parseArgs rejects invalid service enroll and unlock options" {
    try expectUsage(parseArgs(&.{ "keyring", "service", "--lock-timeout", "0" }));
    try expectUsage(parseArgs(&.{ "keyring", "enroll", "--add-key", "--list" }));
    try expectUsage(parseArgs(&.{ "keyring", "enroll", "--force" }));
    try expectUsage(parseArgs(&.{ "keyring", "unlock", "--port", "70000" }));
    try expectUsage(parseArgs(&.{ "keyring", "lock", "extra" }));
}

test "parseArgs recognizes az export" {
    const parsed = parseArgs(&.{ "keyring", "az", "export", "/tmp/out" });
    try expectCommandTag(.az_export, parsed);
    try std.testing.expectEqualStrings("/tmp/out", parsed.command.az_export.dir);

    try expectUsage(parseArgs(&.{ "keyring", "az", "export" }));
    try expectUsage(parseArgs(&.{ "keyring", "az", "bogus", "/tmp/out" }));
    try expectUsage(parseArgs(&.{ "keyring", "az" }));
}

test "parseArgs recognizes gh login, export, and import" {
    const login_default = parseArgs(&.{ "keyring", "gh", "login" });
    try expectCommandTag(.gh_login, login_default);
    try std.testing.expectEqualStrings("github.com", login_default.command.gh_login.hostname);
    try std.testing.expectEqual(gh.LoginMode.auto, login_default.command.gh_login.mode);

    const login_ghe = parseArgs(&.{ "keyring", "gh", "login", "--hostname", "example.ghe.com", "--device" });
    try expectCommandTag(.gh_login, login_ghe);
    try std.testing.expectEqualStrings("example.ghe.com", login_ghe.command.gh_login.hostname);
    try std.testing.expectEqual(gh.LoginMode.device, login_ghe.command.gh_login.mode);

    const exp = parseArgs(&.{ "keyring", "gh", "export", "/tmp/gh-out" });
    try expectCommandTag(.gh_export, exp);
    try std.testing.expectEqualStrings("/tmp/gh-out", exp.command.gh_export.dir);

    const imp_local = parseArgs(&.{ "keyring", "gh", "import" });
    try expectCommandTag(.gh_import, imp_local);
    try std.testing.expect(imp_local.command.gh_import.source == null);

    const imp_dir = parseArgs(&.{ "keyring", "gh", "import", "/tmp/gh-out" });
    try expectCommandTag(.gh_import, imp_dir);
    try std.testing.expectEqualStrings("/tmp/gh-out", imp_dir.command.gh_import.source.?);

    try expectUsage(parseArgs(&.{ "keyring", "gh" }));
    try expectUsage(parseArgs(&.{ "keyring", "gh", "login", "--web", "--device" }));
    try expectUsage(parseArgs(&.{ "keyring", "gh", "export" }));
    try expectUsage(parseArgs(&.{ "keyring", "gh", "export", "/tmp/a", "extra" }));
    try expectUsage(parseArgs(&.{ "keyring", "gh", "import", "/tmp/a", "extra" }));
    try expectUsage(parseArgs(&.{ "keyring", "gh", "bogus" }));
}

test "parseArgs recognizes git-credential, git-credential-keyring argv0, and git setup" {
    const gc_get = parseArgs(&.{ "keyring", "git-credential", "get" });
    try expectCommandTag(.git_credential, gc_get);
    try std.testing.expectEqual(git_credential.Operation.get, gc_get.command.git_credential);

    const argv0_erase = parseArgs(&.{ "/usr/local/bin/git-credential-keyring", "erase" });
    try expectCommandTag(.git_credential, argv0_erase);
    try std.testing.expectEqual(git_credential.Operation.erase, argv0_erase.command.git_credential);

    const setup_all = parseArgs(&.{ "keyring", "git", "setup" });
    try expectCommandTag(.git_setup, setup_all);
    try std.testing.expect(setup_all.command.git_setup.hostname == null);
    try std.testing.expect(setup_all.command.git_setup.global);

    const setup_host = parseArgs(&.{ "keyring", "git", "setup", "--hostname", "example.ghe.com", "--local" });
    try expectCommandTag(.git_setup, setup_host);
    try std.testing.expectEqualStrings("example.ghe.com", setup_host.command.git_setup.hostname.?);
    try std.testing.expect(!setup_host.command.git_setup.global);

    try expectUsage(parseArgs(&.{ "keyring", "git-credential", "bogus" }));
    try expectUsage(parseArgs(&.{ "git-credential-keyring", "bogus" }));
    try expectUsage(parseArgs(&.{ "keyring", "git", "bogus" }));
}

test "parseArgs recognizes devops-npm" {
    const bare = parseArgs(&.{ "keyring", "devops-npm" });
    try expectCommandTag(.devops_npm, bare);
    try std.testing.expect(!bare.command.devops_npm.force);
    try std.testing.expect(!bare.command.devops_npm.validate_only);
    try std.testing.expect(bare.command.devops_npm.config_file == null);

    const flags = parseArgs(&.{ "keyring", "devops-npm", "-c", "sub/.npmrc", "-f", "--validate-only" });
    try expectCommandTag(.devops_npm, flags);
    try std.testing.expect(flags.command.devops_npm.force);
    try std.testing.expect(flags.command.devops_npm.validate_only);
    try std.testing.expectEqualStrings("sub/.npmrc", flags.command.devops_npm.config_file.?);

    try expectUsage(parseArgs(&.{ "keyring", "devops-npm", "--bogus" }));
    try expectUsage(parseArgs(&.{ "keyring", "devops-npm", "-c" }));
}

test "parseArgs recognizes backend flag" {
    const parsed = parseArgs(&.{ "keyring", "-b", "null", "get", "svc", "user" });
    try std.testing.expect(backendEql(.{ .keyring = .null_backend }, parsed.backend.?));
    try expectCommandTag(.get, parsed);

    const parsed_long = parseArgs(&.{ "keyring", "-b", "secret_service", "set", "svc", "user" });
    try std.testing.expect(backendEql(.{ .keyring = .secret_service }, parsed_long.backend.?));
    try expectCommandTag(.set, parsed_long);

    const parsed_file = parseArgs(&.{ "keyring", "-b", "file", "get", "svc", "user" });
    try std.testing.expect(backendEql(.{ .keyring = .file }, parsed_file.backend.?));
    try expectCommandTag(.get, parsed_file);

    const parsed_ado = parseArgs(&.{ "keyring", "-b", "ado", "get", "https://pkgs.dev.azure.com/org/_packaging/feed/pypi/simple/", "VssSessionToken" });
    try std.testing.expect(backendEql(.ado, parsed_ado.backend.?));
    try expectCommandTag(.get, parsed_ado);
}

test "parseArgs recognizes disable" {
    const only = parseArgs(&.{ "keyring", "--disable" });
    try std.testing.expect(only.disable);
    try expectCommandTag(.disabled_no_op, only);

    const parsed = parseArgs(&.{ "keyring", "--disable", "get", "svc", "user" });
    try std.testing.expect(parsed.disable);
    try expectCommandTag(.get, parsed);
}

test "parseArgs rejects bad input" {
    try expectUsage(parseArgs(&.{ "keyring", "set", "svc" }));
    try expectUsage(parseArgs(&.{ "keyring", "get", "svc", "user", "extra" }));
    try expectUsage(parseArgs(&.{ "keyring", "del" }));
    try expectUsage(parseArgs(&.{ "keyring", "unknown" }));
    try expectUsage(parseArgs(&.{ "keyring", "--wat" }));
    try expectUsage(parseArgs(&.{ "keyring", "-b" }));
    try expectUsage(parseArgs(&.{ "keyring", "-b", "missing", "get", "svc", "user" }));
}

test "exit code mapping" {
    try std.testing.expectEqual(@as(u8, 3), exitCodeFor(error.EntryNotFound));
    try std.testing.expectEqual(@as(u8, 4), exitCodeFor(error.NoStorageAccess));
    try std.testing.expectEqual(@as(u8, 1), exitCodeFor(error.Locked));
    try std.testing.expectEqual(@as(u8, 1), exitCodeFor(error.PlatformFailure));
    try std.testing.expectEqual(@as(u8, 1), exitCodeFor(error.Ambiguous));
    try std.testing.expectEqual(@as(u8, 1), exitCodeFor(error.OutOfMemory));
    try std.testing.expectEqual(@as(u8, 1), exitCodeFor(error.InputTooLong));
    try std.testing.expectEqual(@as(u8, 1), exitCodeFor(error.BufferTooSmall));
    try std.testing.expectEqual(@as(u8, 1), exitCodeFor(error.InvalidUtf8));
}

const ColorTestEnv = struct {
    fn none(_: []const u8) ?[]const u8 {
        return null;
    }

    fn noColorEmpty(name: []const u8) ?[]const u8 {
        if (std.mem.eql(u8, name, "NO_COLOR")) return "";
        return null;
    }

    fn noColorZero(name: []const u8) ?[]const u8 {
        if (std.mem.eql(u8, name, "NO_COLOR")) return "0";
        return null;
    }

    fn forceOne(name: []const u8) ?[]const u8 {
        if (std.mem.eql(u8, name, "CLICOLOR_FORCE")) return "1";
        return null;
    }

    fn forceZero(name: []const u8) ?[]const u8 {
        if (std.mem.eql(u8, name, "CLICOLOR_FORCE")) return "0";
        return null;
    }
};

test "Color.detect honors color environment" {
    try std.testing.expect(!color.Color.detect(ColorTestEnv.noColorEmpty, true).enabled);
    try std.testing.expect(!color.Color.detect(ColorTestEnv.noColorZero, true).enabled);
    try std.testing.expect(color.Color.detect(ColorTestEnv.forceOne, false).enabled);
    try std.testing.expect(!color.Color.detect(ColorTestEnv.forceZero, false).enabled);
    try std.testing.expect(color.Color.detect(ColorTestEnv.none, true).enabled);
    try std.testing.expect(!color.Color.detect(ColorTestEnv.none, false).enabled);
}

test "disabled Color methods are empty" {
    const disabled = color.Color{ .enabled = false };
    try std.testing.expectEqualStrings("", disabled.green());
    try std.testing.expectEqualStrings("", disabled.yellow());
    try std.testing.expectEqualStrings("", disabled.red());
    try std.testing.expectEqualStrings("", disabled.bold());
    try std.testing.expectEqualStrings("", disabled.reset());
}

test {
    _ = az_export;
    _ = devops_npm;
    _ = gh;
}

test {
    _ = @import("webauthn.zig");
    _ = @import("tunnel_http.zig");
}
