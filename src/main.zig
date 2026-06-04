const std = @import("std");
const builtin = @import("builtin");
const keyring_zig = @import("keyring_zig");
const ado = @import("ado.zig");
const color = @import("color.zig");
const term = @import("term.zig");

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
    \\  --disable                     Use the null backend for this process.
    \\  -b <backend>                  Use a backend for this process.
    \\  set <service> <user>          Store a password from stdin.
    \\  get <service> <user>          Read a password to stdout.
    \\  del <service> <user>          Delete a password.
    \\
    \\Backends: secret_service, keychain, win_credential, file, ado, null_backend (or null)
    \\
    \\Environment:
    \\  KEYRING_BACKEND               Override backend: secret_service | keychain | win_credential | file | ado | null
    \\  KEYRING_PROPERTY_<NAME>       Backend-specific properties (e.g. KEYRING_PROPERTY_KEYCHAIN, KEYRING_PROPERTY_COLLECTION, KEYRING_PROPERTY_APPID)
    \\  NO_COLOR                      Disable ANSI colors in diagnostic output
    \\  CLICOLOR_FORCE                Force ANSI colors even when stdout is not a TTY
    \\
;

pub const Command = union(enum) {
    help,
    version,
    list_backends,
    diagnose,
    disabled_no_op,
    set: struct { service: []const u8, user: []const u8 },
    get: struct { service: []const u8, user: []const u8 },
    del: struct { service: []const u8, user: []const u8 },
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
        .usage_error => |message| code: {
            try stderr.print("keyring: {s}\n{s}", .{ message, usage });
            try stderr.flush();
            break :code 2;
        },
    };
}

pub fn parseArgs(args: []const []const u8) ParsedArgs {
    var parsed = ParsedArgs{ .command = .help };
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

    parsed.command = if (std.mem.startsWith(u8, command, "-")) .{ .usage_error = "unknown flag" } else .{ .usage_error = "unknown command" };
    return parsed;
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
        const service = "keyring-cli-diagnose-service-that-should-not-exist";
        const user = "keyring-cli-diagnose-user-that-should-not-exist";
        if (getPassword(arena, stdout, service, user)) |password| {
            _ = password;
        } else |err| switch (err) {
            error.NoStorageAccess => try printLinuxNoStorageAccessHint(stdout, colors),
            else => {},
        }
    } else {
        const service = "keyring-cli-diagnose-service-that-should-not-exist";
        const user = "keyring-cli-diagnose-user-that-should-not-exist";
        if (getPassword(arena, stdout, service, user)) |password| {
            _ = password;
            try stdout.writeAll("backend reachable: yes\n");
        } else |err| switch (err) {
            error.EntryNotFound => try stdout.writeAll("backend reachable: yes\n"),
            else => try stdout.print("backend reachable: no ({s})\n", .{@errorName(err)}),
        }
    }
    try stdout.flush();
}

fn printLinuxNoStorageAccessHint(stdout: *std.Io.Writer, colors: color.Color) !void {
    try stdout.print("{s}note:{s} no Secret Service daemon detected.\n", .{ colors.yellow(), colors.reset() });
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
fn effectiveBackend(service: ?[]const u8) Backend {
    if (app_backend_override) |backend| return backend;
    if (!app_env_backend_checked) {
        app_env_backend = readAppEnvBackend();
        app_env_backend_checked = true;
    }
    if (app_env_backend) |backend| return backend;
    if (service) |s| {
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

fn getPassword(arena: std.mem.Allocator, stderr: *std.Io.Writer, service: []const u8, user: []const u8) (keyring_zig.Error || ado.Error)![]u8 {
    return switch (effectiveBackend(service)) {
        .ado => ado.getPassword(arena, stderr, service, user),
        .keyring => keyring_zig.getAlloc(arena, service, user),
    };
}

fn setPassword(arena: std.mem.Allocator, service: []const u8, user: []const u8, password: []const u8) (keyring_zig.Error || ado.Error)!void {
    return switch (effectiveBackend(service)) {
        .ado => ado.setPassword(arena, service, user, password),
        .keyring => keyring_zig.setAlloc(arena, service, user, password),
    };
}

fn deletePassword(arena: std.mem.Allocator, service: []const u8, user: []const u8) (keyring_zig.Error || ado.Error)!void {
    return switch (effectiveBackend(service)) {
        .ado => ado.deletePassword(arena),
        .keyring => keyring_zig.deleteAlloc(arena, service, user),
    };
}

pub fn exitCodeFor(err: anyerror) u8 {
    return switch (err) {
        error.EntryNotFound => 3,
        error.NoStorageAccess => 4,
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

fn printAppError(stderr: *std.Io.Writer, err: anyerror, service: ?[]const u8, user: ?[]const u8) !void {
    const msg = errorMessage(err);
    if (entryErrorContext(err) and service != null and user != null) {
        try stderr.print("keyring: {s}: service='{s}' user='{s}'\n", .{ msg, service.?, user.? });
    } else {
        try stderr.print("keyring: {s}\n", .{msg});
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
        error.AuthenticationFailed => "authentication failed",
        error.NetworkFailure => "network failure",
        error.CacheFailure => "cache failure",
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
