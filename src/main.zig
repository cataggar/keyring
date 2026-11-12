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
const registry_auth = @import("registry_auth.zig");
const podman = @import("podman.zig");
const wslc = @import("wslc.zig");
const copilot = @import("copilot.zig");
const credential_provider = @import("credential_provider.zig");
const stored_provider = @import("stored_provider.zig");
const credential_provider_test = @import("credential_provider_test.zig");

test {
    _ = ado;
    _ = msal_cache;
    _ = az_export;
    _ = devops_npm;
    _ = gh;
    _ = git_credential;
    _ = color;
    _ = term;
    _ = vault;
    _ = webauthn;
    _ = tunnel_http;
    _ = service;
    _ = registry_auth;
    _ = podman;
    _ = wslc;
    _ = copilot;
    _ = credential_provider;
    _ = stored_provider;
    _ = credential_provider_test;
    _ = @import("dpapi.zig");
    _ = @import("keychain.zig");
    _ = @import("wincred.zig");
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
    \\  --help, help                  Show this help.
    \\  version                       Show version.
    \\  --list-backends               List available backends.
    \\  diagnose                      Show backend diagnostics.
    \\  service [options]             Run the built-in Secret Service daemon, or install|uninstall|status.
    \\  enroll [options]              Enroll, list, or revoke security keys.
    \\  unlock [options]              Unlock the built-in service.
    \\  lock                          Lock the built-in service immediately.
    \\  --disable                     Use the null backend for this process.
    \\  -b <backend>                  Use a backend for this process.
    \\  set <service> <user>          Store a password from stdin.
    \\  get <service> <user>          Read a password to stdout.
    \\  del <service> <user>          Delete a password.
    \\  az export <dir>               Export Azure CLI token cache to a directory.
    \\  ado login --hostname <host>   Authenticate and verify access to an Azure DevOps organization.
    \\  gh login [options]            Authenticate with a GitHub host (github.com, *.ghe.com, GHES).
    \\  gh export <dir>               Export GitHub CLI credentials to <dir>/hosts.yml.
    \\  gh import [<dir-or-file>]     Import GitHub CLI credentials into the keyring.
    \\  git credential <op>           Git credential helper protocol (get, store, erase).
    \\  git config [options]          Configure Git to use keyring as its credential helper.
    \\  devops-npm [options]          Authenticate Azure DevOps npm feeds in .npmrc.
    \\  podman login [options] [<srv>] Authenticate container registries for Podman Desktop and Podman.
    \\  podman config <server>...     Configure Podman credHelpers without writing secrets to auth.json.
    \\  podman logout [<srv>...|--all] Remove registry credentials from Podman auth.json and keyring.
    \\  podman status                 Show Podman auth.json, helper PATH, and registry status.
    \\  podman credential <op>        Docker/Podman credential helper protocol (get, store, erase, list, version).
    \\  wslc login [options] [<srv>]  Authenticate container registries for wslc (GHCR, ACR, generic).
    \\  wslc logout <server>...       Remove registry credentials from wslc storage.
    \\  wslc status                   Show wslc credential store status and configured registries.
    \\  wslc credential <op>          Credential helper protocol for wslc (get, store, erase).
    \\  copilot login [options]       Authenticate GitHub Copilot CLI and store token in keyring.
    \\  copilot logout [options]      Remove Copilot CLI credentials from keyring and config.json.
    \\  copilot status                Show Copilot CLI config.json and keyring vault status.
    \\  copilot token [options]       Read the stored Copilot CLI token to stdout.
    \\  copilot env [options]         Print shell export for COPILOT_GITHUB_TOKEN.
    \\  copilot import [<src>]        Migrate plaintext copilotTokens or import into keyring.
    \\  copilot export <dir>          Export Copilot CLI credentials to <dir>/config.json.
    \\
    \\Backends: secret_service, keychain, win_credential, file, ado, null_backend (or null)
    \\
    \\Environment:
    \\  KEYRING_BACKEND               Override backend: secret_service | keychain | win_credential | file | ado | null
    \\  KEYRING_PROPERTY_<NAME>       Backend-specific properties (e.g. KEYRING_PROPERTY_KEYCHAIN, KEYRING_PROPERTY_COLLECTION, KEYRING_PROPERTY_APPID)
    \\  NO_COLOR                      Disable ANSI colors in diagnostic output
    \\  CLICOLOR_FORCE                Force ANSI colors even when stdout is not a TTY
    \\  KEYRING_VAULT_PATH            Override the WebAuthn vault.json path
    \\  COPILOT_HOME                  Override the Copilot CLI config directory (~/.copilot)
    \\
;

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
    service: service.Action,
    enroll: EnrollArgs,
    unlock: UnlockArgs,
    lock,
    disabled_no_op,
    set: struct { service: []const u8, user: []const u8 },
    get: struct { service: []const u8, user: []const u8 },
    del: struct { service: []const u8, user: []const u8 },
    az_export: struct { dir: []const u8 },
    ado_login: ado.LoginOptions,
    gh_login: gh.LoginOptions,
    gh_export: struct { dir: []const u8 },
    gh_import: struct { source: ?[]const u8 },
    git_credential: git_credential.Operation,
    git_config: git_credential.ConfigOptions,
    devops_npm: devops_npm.Options,
    podman: podman.Subcommand,
    wslc: wslc.Subcommand,
    copilot: copilot.Subcommand,
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
    stored_provider.is_app_backend_disallowed_fn = isDisallowedProviderAppBackend;

    const exit_code = try runCommand(parsed.command, arena, init.io, stdout, stderr);
    std.process.exit(exit_code);
}

fn isDisallowedProviderAppBackend() bool {
    if (app_backend_override) |b| return b == .ado;
    if (!app_env_backend_checked) {
        app_env_backend = readAppEnvBackend();
        app_env_backend_checked = true;
    }
    if (app_env_backend) |b| return b == .ado;
    return false;
}

fn rejectAdoBackend(stderr: *std.Io.Writer, comptime cmd_name: []const u8) !bool {
    if (!backendEql(currentBackend(), .ado)) return false;
    try stderr.writeAll("keyring: backend 'ado' does not support '" ++ cmd_name ++ "' commands\n");
    try stderr.flush();
    return true;
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
        .service => |action| code: {
            switch (action) {
                .run => |args| {
                    service.runDaemon(arena, args.replace, args.lock_timeout_seconds) catch |err| {
                        try printAppError(stderr, normalizeServiceError(err), null, null);
                        break :code 1;
                    };
                    break :code 0;
                },
                .install => |opts| break :code try service.runInstall(arena, opts, stdout, stderr),
                .uninstall => |opts| break :code try service.runUninstall(arena, opts, stdout, stderr),
                .status => break :code try service.runStatus(arena, stdout, stderr),
            }
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
            if (try rejectAdoBackend(stderr, "gh")) break :code 4;
            break :code try gh.runLogin(arena, opts, stdout, stderr);
        },
        .ado_login => |opts| code: {
            const org_url = ado.loginOrgUrl(arena, opts.hostname) catch |err| {
                if (err == error.InvalidHostname) {
                    try stderr.writeAll("keyring: expected <org>.visualstudio.com or https://dev.azure.com/<org>\n");
                    try stderr.flush();
                    break :code 2;
                }
                return err;
            };
            defer arena.free(org_url);
            ado.login(arena, stderr, org_url) catch |err| {
                try stderr.print("keyring: Azure DevOps login failed ({s})\n", .{@errorName(err)});
                if (err == error.NoStorageAccess) {
                    try stderr.writeAll("Allow interactive authentication and browser access, and check the token store with 'keyring diagnose'.\n");
                }
                try stderr.flush();
                break :code exitCodeFor(err);
            };
            try stdout.print("Authenticated to {s}; organization access verified.\n", .{org_url});
            try stdout.flush();
            break :code 0;
        },
        .gh_export => |cmd| code: {
            if (try rejectAdoBackend(stderr, "gh")) break :code 4;
            break :code try gh.runExport(arena, cmd.dir, stdout, stderr);
        },
        .gh_import => |cmd| code: {
            if (try rejectAdoBackend(stderr, "gh")) break :code 4;
            var stdin_buffer: [4096]u8 = undefined;
            var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buffer);
            break :code try gh.runImport(arena, cmd.source, &stdin_reader.interface, stdout, stderr);
        },
        .git_credential => |op| code: {
            var stdin_buffer: [4096]u8 = undefined;
            var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buffer);
            break :code try git_credential.runCredential(arena, op, &stdin_reader.interface, stdout, stderr);
        },
        .git_config => |opts| code: {
            break :code try git_credential.runConfig(arena, opts, stdout, stderr);
        },
        .devops_npm => |opts| code: {
            break :code try devops_npm.run(arena, io, opts, stdout, stderr);
        },
        .podman => |subcmd| code: {
            if (try rejectAdoBackend(stderr, "podman")) break :code 4;
            var stdin_buffer: [4096]u8 = undefined;
            defer std.crypto.secureZero(u8, &stdin_buffer);
            var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buffer);
            break :code try podman.run(arena, subcmd, &stdin_reader.interface, stdout, stderr);
        },
        .wslc => |subcmd| code: {
            if (try rejectAdoBackend(stderr, "wslc")) break :code 4;
            var stdin_buffer: [4096]u8 = undefined;
            defer std.crypto.secureZero(u8, &stdin_buffer);
            var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buffer);
            break :code try wslc.run(arena, subcmd, &stdin_reader.interface, stdout, stderr);
        },
        .copilot => |subcmd| code: {
            if (try rejectAdoBackend(stderr, "copilot")) break :code 4;
            var stdin_buffer: [4096]u8 = undefined;
            defer std.crypto.secureZero(u8, &stdin_buffer);
            var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buffer);
            break :code try copilot.run(arena, subcmd, &stdin_reader.interface, stdout, stderr);
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
    if (args.len >= 1 and podman.isDockerCredentialArgv0(args[0])) {
        if (args.len == 2) {
            if (registry_auth.HelperOperation.fromString(args[1])) |op| {
                parsed.command = .{ .podman = .{ .credential = op } };
                return parsed;
            }
        }
        parsed.command = .{ .usage_error = "usage: docker-credential-keyring <get|store|erase|list|version>" };
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
        parsed.command = if (service.parseArgs(rest)) |act|
            .{ .service = act }
        else
            .{ .usage_error = "usage: keyring service [--replace] [--lock-timeout <seconds>] | install [--force] | uninstall [--force] | status" };
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

    if (std.mem.eql(u8, command, "ado")) {
        parsed.command = if (rest.len >= 1 and std.mem.eql(u8, rest[0], "login"))
            if (ado.parseLoginArgs(rest[1..])) |opts|
                .{ .ado_login = opts }
            else
                .{ .usage_error = "usage: keyring ado login -h|--hostname <org>.visualstudio.com|https://dev.azure.com/<org>" }
        else
            .{ .usage_error = "usage: keyring ado login --hostname <organization-host-or-url>" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "gh")) {
        if (rest.len >= 1 and std.mem.eql(u8, rest[0], "login")) {
            parsed.command = if (gh.parseLoginArgs(rest[1..])) |opts|
                .{ .gh_login = opts }
            else
                .{ .usage_error = "usage: keyring gh login [-h|--hostname <host>] [-s|--scopes <scopes>] [-w|--web|--device]" };
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

    if (std.mem.eql(u8, command, "git")) {
        if (rest.len >= 1 and std.mem.eql(u8, rest[0], "credential")) {
            if (rest.len == 2) {
                if (git_credential.Operation.fromString(rest[1])) |op| {
                    parsed.command = .{ .git_credential = op };
                    return parsed;
                }
            }
            parsed.command = .{ .usage_error = "usage: keyring git credential <get|store|erase>" };
        } else if (rest.len >= 1 and std.mem.eql(u8, rest[0], "config")) {
            parsed.command = if (git_credential.parseConfigArgs(rest[1..])) |opts|
                .{ .git_config = opts }
            else
                .{ .usage_error = "usage: keyring git config [-h|--hostname <host>] [-g|--global|--local]" };
        } else {
            parsed.command = .{ .usage_error = "usage: keyring git <credential <get|store|erase> | config [-h|--hostname <host>] [-g|--global|--local]>" };
        }
        return parsed;
    }

    if (std.mem.eql(u8, command, "devops-npm")) {
        parsed.command = if (devops_npm.parseArgs(rest)) |opts|
            .{ .devops_npm = opts }
        else
            .{ .usage_error = "usage: keyring devops-npm [-c|--config-file <path>] [-f|--force] [--validate-only]" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "podman")) {
        parsed.command = if (podman.parseArgs(rest)) |subcmd|
            .{ .podman = subcmd }
        else
            .{ .usage_error = "usage: keyring podman <login [<server>...] [-u <user>] [--password-stdin] [-f|--force] [--helper-only|--auths-only] [--authfile <path>] | config <server>... [--authfile <path>] | logout [<server>...|--all] [--authfile <path>] | status [--authfile <path>] | credential <get|store|erase|list|version>>" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "wslc")) {
        parsed.command = if (wslc.parseArgs(rest)) |subcmd|
            .{ .wslc = subcmd }
        else
            .{ .usage_error = "usage: keyring wslc <login [<server>...] [-u <user>] [--password-stdin] [-f|--force] | logout <server>... | status | credential <get|store|erase>>" };
        return parsed;
    }

    if (std.mem.eql(u8, command, "copilot")) {
        parsed.command = if (copilot.parseArgs(rest)) |subcmd|
            .{ .copilot = subcmd }
        else
            .{ .usage_error = "usage: keyring copilot <login [-h <host>] [-u <user>] [--web|--device] [-f|--force] | logout [-h <host>] [-u <user>|--all] | status | token [-h <host>] [-u <user>] | env [-h <host>] [-u <user>] [--shell <sh|pwsh|cmd|fish>] | import [<dir-or-file>] | export <dir>>" };
        return parsed;
    }

    parsed.command = if (std.mem.startsWith(u8, command, "-")) .{ .usage_error = "unknown flag" } else .{ .usage_error = "unknown command" };
    return parsed;
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
            error.NoStorageAccess, error.PlatformFailure => if (backendEql(current, .{ .keyring = .secret_service })) {
                try printLinuxNoStorageAccessHint(stdout, colors);
            },
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
    podman.diagnose(arena, stdout) catch {};
    wslc.diagnose(arena, stdout) catch {};
    if (!backendEql(current, .ado)) {
        copilot.diagnose(arena, stdout) catch {};
    }
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
    const trimmed = std.mem.trim(u8, value, &std.ascii.whitespace);
    if (std.ascii.eqlIgnoreCase(trimmed, "ado") or
        std.ascii.eqlIgnoreCase(trimmed, "azure_devops"))
    {
        return .ado;
    }
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
    try expectUsage(parseArgs(&.{ "keyring", "-h" }));
    try expectCommandTag(.help, parseArgs(&.{ "keyring", "help" }));
    try expectCommandTag(.version, parseArgs(&.{ "keyring", "version" }));
    try expectCommandTag(.list_backends, parseArgs(&.{ "keyring", "--list-backends" }));
    try expectCommandTag(.diagnose, parseArgs(&.{ "keyring", "diagnose" }));
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, haystack, needle) != null);
}

test "runCommand dispatches help list-backends diagnose" {
    const prev_backend = keyring_zig.currentBackend();
    defer keyring_zig.setDefaultBackend(prev_backend) catch {};
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

test "runCommand rejects unsupported subcommands when backend is ado" {
    const prev_override = app_backend_override;
    const prev_env_checked = app_env_backend_checked;
    const prev_env_backend = app_env_backend;
    const prev_env_map = runtime_env_map;
    defer {
        app_backend_override = prev_override;
        app_env_backend_checked = prev_env_checked;
        app_env_backend = prev_env_backend;
        runtime_env_map = prev_env_map;
    }

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const io = std.Io.Threaded.global_single_threaded.io();

    const cases = [_]struct {
        cmd: Command,
        expected_stderr: []const u8,
    }{
        .{
            .cmd = .{ .copilot = .{ .token = .{} } },
            .expected_stderr = "keyring: backend 'ado' does not support 'copilot' commands\n",
        },
        .{
            .cmd = .{ .podman = .{ .status = .{} } },
            .expected_stderr = "keyring: backend 'ado' does not support 'podman' commands\n",
        },
        .{
            .cmd = .{ .wslc = .status },
            .expected_stderr = "keyring: backend 'ado' does not support 'wslc' commands\n",
        },
        .{
            .cmd = .{ .gh_login = .{} },
            .expected_stderr = "keyring: backend 'ado' does not support 'gh' commands\n",
        },
        .{
            .cmd = .{ .gh_export = .{ .dir = "./gh-out" } },
            .expected_stderr = "keyring: backend 'ado' does not support 'gh' commands\n",
        },
        .{
            .cmd = .{ .gh_import = .{ .source = null } },
            .expected_stderr = "keyring: backend 'ado' does not support 'gh' commands\n",
        },
    };

    app_backend_override = .ado;
    for (cases) |tc| {
        var stdout = std.Io.Writer.Allocating.init(std.testing.allocator);
        defer stdout.deinit();
        var stderr = std.Io.Writer.Allocating.init(std.testing.allocator);
        defer stderr.deinit();

        const rc = try runCommand(tc.cmd, arena.allocator(), io, &stdout.writer, &stderr.writer);
        try std.testing.expectEqual(@as(u8, 4), rc);
        try std.testing.expectEqualStrings(tc.expected_stderr, stderr.written());
    }

    app_backend_override = null;
    var env_map = try std.process.Environ.createMap(.empty, std.testing.allocator);
    defer env_map.deinit();
    runtime_env_map = &env_map;

    for ([_][]const u8{ "  ADO \t", "Azure_DevOps\n" }) |env_val| {
        try env_map.put("KEYRING_BACKEND", env_val);
        app_env_backend_checked = false;
        app_env_backend = null;
        try std.testing.expectEqual(@as(?Backend, .ado), readAppEnvBackend());

        for (cases) |tc| {
            var stdout = std.Io.Writer.Allocating.init(std.testing.allocator);
            defer stdout.deinit();
            var stderr = std.Io.Writer.Allocating.init(std.testing.allocator);
            defer stderr.deinit();

            const rc = try runCommand(tc.cmd, arena.allocator(), io, &stdout.writer, &stderr.writer);
            try std.testing.expectEqual(@as(u8, 4), rc);
            try std.testing.expectEqualStrings(tc.expected_stderr, stderr.written());
        }
    }
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
    const bare_service = parseArgs(&.{ "keyring", "service" });
    try expectCommandTag(.service, bare_service);
    try std.testing.expect(!bare_service.command.service.run.replace);
    try std.testing.expectEqual(@as(?u32, null), bare_service.command.service.run.lock_timeout_seconds);

    const service_command = parseArgs(&.{ "keyring", "service", "--replace", "--lock-timeout", "600" });
    try expectCommandTag(.service, service_command);
    try std.testing.expect(service_command.command.service.run.replace);
    try std.testing.expectEqual(@as(?u32, 600), service_command.command.service.run.lock_timeout_seconds);

    const service_install = parseArgs(&.{ "keyring", "service", "install" });
    try expectCommandTag(.service, service_install);
    try std.testing.expect(!service_install.command.service.install.force);

    const service_uninstall = parseArgs(&.{ "keyring", "service", "uninstall", "--force" });
    try expectCommandTag(.service, service_uninstall);
    try std.testing.expect(service_uninstall.command.service.uninstall.force);

    const service_status = parseArgs(&.{ "keyring", "service", "status" });
    try expectCommandTag(.service, service_status);
    try std.testing.expectEqual(std.meta.Tag(service.Action).status, std.meta.activeTag(service_status.command.service));

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
    try expectUsage(parseArgs(&.{ "keyring", "service", "install", "--bogus" }));
    try expectUsage(parseArgs(&.{ "keyring", "service", "status", "extra" }));
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

test "parseArgs recognizes explicit ado login and rejects malformed options" {
    const parsed = parseArgs(&.{ "keyring", "ado", "login", "--hostname", "example.visualstudio.com" });
    try expectCommandTag(.ado_login, parsed);
    try std.testing.expectEqualStrings("example.visualstudio.com", parsed.command.ado_login.hostname);
    const short = parseArgs(&.{ "keyring", "ado", "login", "-h", "https://dev.azure.com/example" });
    try expectCommandTag(.ado_login, short);
    try std.testing.expectEqualStrings("https://dev.azure.com/example", short.command.ado_login.hostname);
    try expectUsage(parseArgs(&.{ "keyring", "ado" }));
    try expectUsage(parseArgs(&.{ "keyring", "ado", "login" }));
    try expectUsage(parseArgs(&.{ "keyring", "ado", "login", "--hostname" }));
    try expectUsage(parseArgs(&.{ "keyring", "ado", "login", "--hostname", "" }));
    try expectUsage(parseArgs(&.{ "keyring", "ado", "login", "--hostname", "--device" }));
    try expectUsage(parseArgs(&.{ "keyring", "ado", "login", "--hostname", "example.visualstudio.com", "--device" }));
    try expectUsage(parseArgs(&.{ "keyring", "ado", "logout" }));
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

    const login_short_h = parseArgs(&.{ "keyring", "gh", "login", "-h", "microsoft.ghe.com", "-s", "repo,read:packages", "-w" });
    try expectCommandTag(.gh_login, login_short_h);
    try std.testing.expectEqualStrings("microsoft.ghe.com", login_short_h.command.gh_login.hostname);
    try std.testing.expectEqualStrings("repo,read:packages", login_short_h.command.gh_login.scopes);
    try std.testing.expectEqual(gh.LoginMode.web, login_short_h.command.gh_login.mode);

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
    const bad_gh_login = parseArgs(&.{ "keyring", "gh", "login", "--web", "--device" });
    try expectUsage(bad_gh_login);
    try expectContains(bad_gh_login.command.usage_error, "-s|--scopes");
    try expectContains(bad_gh_login.command.usage_error, "-w|--web");
    try expectUsage(parseArgs(&.{ "keyring", "gh", "export" }));
    try expectUsage(parseArgs(&.{ "keyring", "gh", "export", "/tmp/a", "extra" }));
    try expectUsage(parseArgs(&.{ "keyring", "gh", "import", "/tmp/a", "extra" }));
    try expectUsage(parseArgs(&.{ "keyring", "gh", "bogus" }));
}

test "parseArgs recognizes git credential, git-credential-keyring argv0, and git config" {
    const gc_get = parseArgs(&.{ "keyring", "git", "credential", "get" });
    try expectCommandTag(.git_credential, gc_get);
    try std.testing.expectEqual(git_credential.Operation.get, gc_get.command.git_credential);

    const argv0_erase = parseArgs(&.{ "/usr/local/bin/git-credential-keyring", "erase" });
    try expectCommandTag(.git_credential, argv0_erase);
    try std.testing.expectEqual(git_credential.Operation.erase, argv0_erase.command.git_credential);

    const cfg_all = parseArgs(&.{ "keyring", "git", "config" });
    try expectCommandTag(.git_config, cfg_all);
    try std.testing.expect(cfg_all.command.git_config.hostname == null);
    try std.testing.expect(cfg_all.command.git_config.global);

    const cfg_host = parseArgs(&.{ "keyring", "git", "config", "--hostname", "example.ghe.com", "--local" });
    try expectCommandTag(.git_config, cfg_host);
    try std.testing.expectEqualStrings("example.ghe.com", cfg_host.command.git_config.hostname.?);
    try std.testing.expect(!cfg_host.command.git_config.global);

    const cfg_short_h = parseArgs(&.{ "keyring", "git", "config", "-h", "microsoft.ghe.com" });
    try expectCommandTag(.git_config, cfg_short_h);
    try std.testing.expectEqualStrings("microsoft.ghe.com", cfg_short_h.command.git_config.hostname.?);
    try std.testing.expect(cfg_short_h.command.git_config.global);

    const cfg_short_g = parseArgs(&.{ "keyring", "git", "config", "-h", "example.ghe.com", "-g" });
    try expectCommandTag(.git_config, cfg_short_g);
    try std.testing.expect(cfg_short_g.command.git_config.global);

    const cfg_global_last = parseArgs(&.{ "keyring", "git", "config", "--local", "-g" });
    try expectCommandTag(.git_config, cfg_global_last);
    try std.testing.expect(cfg_global_last.command.git_config.global);

    const cfg_local_last = parseArgs(&.{ "keyring", "git", "config", "-g", "--local" });
    try expectCommandTag(.git_config, cfg_local_last);
    try std.testing.expect(!cfg_local_last.command.git_config.global);

    try expectUsage(parseArgs(&.{ "keyring", "git", "credential", "bogus" }));
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

    const long_cfg = parseArgs(&.{ "keyring", "devops-npm", "--config-file", "other/.npmrc" });
    try expectCommandTag(.devops_npm, long_cfg);
    try std.testing.expectEqualStrings("other/.npmrc", long_cfg.command.devops_npm.config_file.?);

    const bad_npm = parseArgs(&.{ "keyring", "devops-npm", "--bogus" });
    try expectUsage(bad_npm);
    try expectContains(bad_npm.command.usage_error, "-c|--config-file <path>");
    try expectUsage(parseArgs(&.{ "keyring", "devops-npm", "-c" }));
}

test "parseArgs recognizes docker-credential-keyring argv0 and podman subcommands" {
    const argv0_get = parseArgs(&.{ "docker-credential-keyring", "get" });
    try expectCommandTag(.podman, argv0_get);
    try std.testing.expectEqual(registry_auth.HelperOperation.get, argv0_get.command.podman.credential);

    const argv0_store = parseArgs(&.{ "/usr/local/bin/docker-credential-keyring", "store" });
    try expectCommandTag(.podman, argv0_store);
    try std.testing.expectEqual(registry_auth.HelperOperation.store, argv0_store.command.podman.credential);

    const argv0_win_erase = parseArgs(&.{ "C:\\bin\\docker-credential-keyring.exe", "erase" });
    try expectCommandTag(.podman, argv0_win_erase);
    try std.testing.expectEqual(registry_auth.HelperOperation.erase, argv0_win_erase.command.podman.credential);

    const argv0_win_list = parseArgs(&.{ "C:\\bin\\docker-credential-keyring.exe", "list" });
    try expectCommandTag(.podman, argv0_win_list);
    try std.testing.expectEqual(registry_auth.HelperOperation.list, argv0_win_list.command.podman.credential);

    const argv0_win_ver = parseArgs(&.{ "C:\\bin\\DOCKER-CREDENTIAL-KEYRING.EXE", "version" });
    try expectCommandTag(.podman, argv0_win_ver);
    try std.testing.expectEqual(registry_auth.HelperOperation.version, argv0_win_ver.command.podman.credential);

    try expectUsage(parseArgs(&.{"docker-credential-keyring"}));
    try expectUsage(parseArgs(&.{ "docker-credential-keyring", "bogus" }));
    try expectUsage(parseArgs(&.{ "C:\\bin\\docker-credential-keyring.exe", "get", "extra" }));

    const login_cmd = parseArgs(&.{ "keyring", "podman", "login", "ghcr.io", "myacr.azurecr.io", "-f", "--helper-only", "--authfile", "./auth.json" });
    try expectCommandTag(.podman, login_cmd);
    try std.testing.expectEqual(@as(usize, 2), login_cmd.command.podman.login.server_count);
    try std.testing.expect(login_cmd.command.podman.login.force);
    try std.testing.expectEqual(podman.LoginMode.helper_only, login_cmd.command.podman.login.mode);
    try std.testing.expectEqualStrings("./auth.json", login_cmd.command.podman.login.authfile.?);

    const login_stdin = parseArgs(&.{ "keyring", "podman", "login", "-u", "alice", "--password-stdin", "registry.example.com" });
    try expectCommandTag(.podman, login_stdin);
    try std.testing.expect(login_stdin.command.podman.login.password_stdin);
    try std.testing.expectEqualStrings("alice", login_stdin.command.podman.login.username.?);

    const config_cmd = parseArgs(&.{ "keyring", "podman", "config", "ghcr.io", "myacr.azurecr.io", "--authfile", "./auth.json" });
    try expectCommandTag(.podman, config_cmd);
    try std.testing.expectEqual(@as(usize, 2), config_cmd.command.podman.config.server_count);
    try std.testing.expectEqualStrings("./auth.json", config_cmd.command.podman.config.authfile.?);

    const logout_all = parseArgs(&.{ "keyring", "podman", "logout", "--all" });
    try expectCommandTag(.podman, logout_all);
    try std.testing.expect(logout_all.command.podman.logout.all);

    const status_cmd = parseArgs(&.{ "keyring", "podman", "status", "--authfile", "./auth.json" });
    try expectCommandTag(.podman, status_cmd);
    try std.testing.expectEqualStrings("./auth.json", status_cmd.command.podman.status.authfile.?);

    const cred_ver = parseArgs(&.{ "keyring", "podman", "credential", "version" });
    try expectCommandTag(.podman, cred_ver);
    try std.testing.expectEqual(registry_auth.HelperOperation.version, cred_ver.command.podman.credential);

    try expectUsage(parseArgs(&.{ "keyring", "podman" }));
    try expectUsage(parseArgs(&.{ "keyring", "podman", "bogus" }));
    try expectUsage(parseArgs(&.{ "keyring", "podman", "config" }));
    try expectUsage(parseArgs(&.{ "keyring", "podman", "logout" }));
    try expectUsage(parseArgs(&.{ "keyring", "podman", "logout", "--all", "ghcr.io" }));
    try expectUsage(parseArgs(&.{ "keyring", "podman", "login", "--helper-only", "--auths-only", "ghcr.io" }));
    try expectUsage(parseArgs(&.{ "keyring", "podman", "login", "--password-stdin", "ghcr.io" }));
    try expectUsage(parseArgs(&.{ "keyring", "podman", "credential" }));
    try expectUsage(parseArgs(&.{ "keyring", "podman", "credential", "bogus" }));
}

test "parseArgs recognizes wslc subcommands" {
    const login_srv = parseArgs(&.{ "keyring", "wslc", "login", "ghcr.io", "myacr.azurecr.io", "-f" });
    try expectCommandTag(.wslc, login_srv);
    try std.testing.expectEqual(@as(usize, 2), login_srv.command.wslc.login.server_count);
    try std.testing.expect(login_srv.command.wslc.login.force);

    const login_interspersed = parseArgs(&.{ "keyring", "wslc", "login", "ghcr.io", "-f", "myacr.azurecr.io" });
    try expectCommandTag(.wslc, login_interspersed);
    try std.testing.expectEqual(@as(usize, 2), login_interspersed.command.wslc.login.server_count);
    try std.testing.expect(login_interspersed.command.wslc.login.force);

    const login_stdin = parseArgs(&.{ "keyring", "wslc", "login", "-u", "alice", "--password-stdin", "registry.example.com" });
    try expectCommandTag(.wslc, login_stdin);
    try std.testing.expect(login_stdin.command.wslc.login.password_stdin);
    try std.testing.expectEqualStrings("alice", login_stdin.command.wslc.login.username.?);

    const logout_cmd = parseArgs(&.{ "keyring", "wslc", "logout", "ghcr.io" });
    try expectCommandTag(.wslc, logout_cmd);
    try std.testing.expectEqual(@as(usize, 1), logout_cmd.command.wslc.logout.servers.len);

    const status_cmd = parseArgs(&.{ "keyring", "wslc", "status" });
    try expectCommandTag(.wslc, status_cmd);
    try std.testing.expectEqual(std.meta.Tag(wslc.Subcommand).status, std.meta.activeTag(status_cmd.command.wslc));

    const cred_get = parseArgs(&.{ "keyring", "wslc", "credential", "get" });
    try expectCommandTag(.wslc, cred_get);
    try std.testing.expectEqual(wslc.Operation.get, cred_get.command.wslc.credential);

    try expectUsage(parseArgs(&.{ "keyring", "wslc" }));
    try expectUsage(parseArgs(&.{ "keyring", "wslc", "logout" }));
    try expectUsage(parseArgs(&.{ "keyring", "wslc", "login", "--password-stdin", "ghcr.io" }));
    try expectUsage(parseArgs(&.{ "keyring", "wslc", "credential", "bogus" }));
}

test "parseArgs recognizes copilot subcommands" {
    const login_cmd = parseArgs(&.{ "keyring", "copilot", "login", "-h", "example.ghe.com", "-u", "alice", "--device", "-f" });
    try expectCommandTag(.copilot, login_cmd);
    try std.testing.expectEqualStrings("example.ghe.com", login_cmd.command.copilot.login.hostname);
    try std.testing.expectEqualStrings("alice", login_cmd.command.copilot.login.username.?);
    try std.testing.expectEqual(gh.LoginMode.device, login_cmd.command.copilot.login.mode);
    try std.testing.expect(login_cmd.command.copilot.login.force);

    const logout_all = parseArgs(&.{ "keyring", "copilot", "logout", "--all" });
    try expectCommandTag(.copilot, logout_all);
    try std.testing.expect(logout_all.command.copilot.logout.all);

    const status_cmd = parseArgs(&.{ "keyring", "copilot", "status" });
    try expectCommandTag(.copilot, status_cmd);
    try std.testing.expectEqual(std.meta.Tag(copilot.Subcommand).status, std.meta.activeTag(status_cmd.command.copilot));

    const token_cmd = parseArgs(&.{ "keyring", "copilot", "token", "-h", "github.com", "-u", "alice" });
    try expectCommandTag(.copilot, token_cmd);
    try std.testing.expectEqualStrings("github.com", token_cmd.command.copilot.token.hostname.?);
    try std.testing.expectEqualStrings("alice", token_cmd.command.copilot.token.username.?);

    const env_cmd = parseArgs(&.{ "keyring", "copilot", "env", "--shell", "sh" });
    try expectCommandTag(.copilot, env_cmd);
    try std.testing.expectEqual(copilot.ShellKind.sh, env_cmd.command.copilot.env.shell.?);

    const imp_local = parseArgs(&.{ "keyring", "copilot", "import" });
    try expectCommandTag(.copilot, imp_local);
    try std.testing.expect(imp_local.command.copilot.import_cmd.source == null);

    const imp_src = parseArgs(&.{ "keyring", "copilot", "import", "./copilot-bundle" });
    try expectCommandTag(.copilot, imp_src);
    try std.testing.expectEqualStrings("./copilot-bundle", imp_src.command.copilot.import_cmd.source.?);

    const exp_cmd = parseArgs(&.{ "keyring", "copilot", "export", "./copilot-bundle" });
    try expectCommandTag(.copilot, exp_cmd);
    try std.testing.expectEqualStrings("./copilot-bundle", exp_cmd.command.copilot.export_cmd.dir);

    try expectUsage(parseArgs(&.{ "keyring", "copilot" }));
    try expectUsage(parseArgs(&.{ "keyring", "copilot", "bogus" }));
    try expectUsage(parseArgs(&.{ "keyring", "copilot", "login", "--web", "--device" }));
    try expectUsage(parseArgs(&.{ "keyring", "copilot", "logout", "--all", "-u", "alice" }));
    try expectUsage(parseArgs(&.{ "keyring", "copilot", "status", "extra" }));
    try expectUsage(parseArgs(&.{ "keyring", "copilot", "env", "--shell", "bogus" }));
    try expectUsage(parseArgs(&.{ "keyring", "copilot", "export" }));
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

    const parsed_null_backend = parseArgs(&.{ "keyring", "-b", "null_backend", "get", "svc", "user" });
    try std.testing.expect(backendEql(.{ .keyring = .null_backend }, parsed_null_backend.backend.?));
    try expectCommandTag(.get, parsed_null_backend);

    const parsed_ado = parseArgs(&.{ "keyring", "-b", "ado", "get", "https://pkgs.dev.azure.com/org/_packaging/feed/pypi/simple/", "VssSessionToken" });
    try std.testing.expect(backendEql(.ado, parsed_ado.backend.?));
    try expectCommandTag(.get, parsed_ado);

    const parsed_azure_devops = parseArgs(&.{ "keyring", "-b", "azure_devops", "get", "https://pkgs.dev.azure.com/org/_packaging/feed/pypi/simple/", "VssSessionToken" });
    try std.testing.expect(backendEql(.ado, parsed_azure_devops.backend.?));
    try expectCommandTag(.get, parsed_azure_devops);
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
    try std.testing.expectEqual(@as(u8, 2), exitCodeFor(error.InvalidStoreSelector));
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

test "isDisallowedProviderAppBackend fails closed when app backend is ado" {
    const prev_keyring_backend = keyring_zig.currentBackend();
    const prev_override = app_backend_override;
    const prev_env_checked = app_env_backend_checked;
    const prev_env_backend = app_env_backend;
    const prev_hook = stored_provider.is_app_backend_disallowed_fn;
    defer {
        keyring_zig.setDefaultBackend(prev_keyring_backend) catch {};
        app_backend_override = prev_override;
        app_env_backend_checked = prev_env_checked;
        app_env_backend = prev_env_backend;
        stored_provider.is_app_backend_disallowed_fn = prev_hook;
    }

    var avail_buf: [5]keyring_zig.Backend = undefined;
    for (keyring_zig.availableBackends(&avail_buf)) |candidate| {
        if (candidate != .null_backend and (!@hasField(keyring_zig.Backend, "file") or candidate != .file)) {
            try keyring_zig.setDefaultBackend(candidate);
            break;
        }
    }

    stored_provider.is_app_backend_disallowed_fn = isDisallowedProviderAppBackend;
    app_backend_override = .ado;
    try std.testing.expect(isDisallowedProviderAppBackend());
    try std.testing.expectError(
        error.StorageUnavailable,
        stored_provider.checkSecureBackendAvailable(std.testing.allocator),
    );

    app_backend_override = null;
    app_env_backend_checked = true;
    app_env_backend = .ado;
    try std.testing.expect(isDisallowedProviderAppBackend());
    try std.testing.expectError(
        error.StorageUnavailable,
        stored_provider.checkSecureBackendAvailable(std.testing.allocator),
    );

    app_env_backend = null;
    try std.testing.expect(!isDisallowedProviderAppBackend());
    try stored_provider.checkSecureBackendAvailable(std.testing.allocator);
}
