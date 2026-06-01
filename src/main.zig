const std = @import("std");
const builtin = @import("builtin");
const keyring_zig = @import("keyring_zig");
const term = @import("term.zig");

const version = "0.0.0";
const usage =
    \\usage: keyring [--disable] [-b <backend>] <command> [args]
    \\
    \\Commands:
    \\  --help, -h, help              Show this help.
    \\  --version, -v                 Show version.
    \\  --list-backends               List available backends.
    \\  diagnose                      Show backend diagnostics.
    \\  --disable                     Use the null backend for this process.
    \\  -b <backend>                  Use a backend for this process.
    \\  set <service> <user>          Store a password from stdin.
    \\  get <service> <user>          Read a password to stdout.
    \\  del <service> <user>          Delete a password.
    \\
    \\Backends: secret_service, keychain, win_credential, null_backend (or null)
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
    backend: ?keyring_zig.Backend = null,
    disable: bool = false,
};

pub fn main(init: std.process.Init) !void {
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
        keyring_zig.setDefaultBackend(backend) catch |err| switch (err) {
            error.BackendUnavailable => {
                try stderr.print("keyring: backend '{s}' not available on this platform\n", .{backendName(backend)});
                try stderr.flush();
                std.process.exit(4);
            },
        };
    }
    if (parsed.disable) {
        keyring_zig.setDefaultBackend(.null_backend) catch {
            try stderr.writeAll("keyring: backend 'null_backend' not available on this platform\n");
            try stderr.flush();
            std.process.exit(4);
        };
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
            keyring_zig.setAlloc(arena, cmd.service, cmd.user, password) catch |err| {
                try printKeyringError(stderr, err);
                break :code exitCodeFor(err);
            };
            break :code 0;
        },
        .get => |cmd| code: {
            const password = keyring_zig.getAlloc(arena, cmd.service, cmd.user) catch |err| {
                try printKeyringError(stderr, err);
                break :code exitCodeFor(err);
            };
            try stdout.writeAll(password);
            try stdout.flush();
            break :code 0;
        },
        .del => |cmd| code: {
            keyring_zig.deleteAlloc(arena, cmd.service, cmd.user) catch |err| {
                try printKeyringError(stderr, err);
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

    if (std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "-v")) {
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

fn parseBackendArg(name: []const u8) ?keyring_zig.Backend {
    if (std.mem.eql(u8, name, "secret_service")) return .secret_service;
    if (std.mem.eql(u8, name, "keychain")) return .keychain;
    if (std.mem.eql(u8, name, "win_credential")) return .win_credential;
    if (std.mem.eql(u8, name, "null") or std.mem.eql(u8, name, "null_backend")) return .null_backend;
    return null;
}

fn listBackends(stdout: *std.Io.Writer) !void {
    var buffer: [4]keyring_zig.Backend = undefined;
    const available = keyring_zig.availableBackends(&buffer);
    const current = keyring_zig.currentBackend();
    for (available) |backend| {
        if (backend == current) {
            try stdout.print("*{s} (default)\n", .{backendName(backend)});
        } else {
            try stdout.print("{s}\n", .{backendName(backend)});
        }
    }
    try stdout.flush();
}

fn diagnose(arena: std.mem.Allocator, stdout: *std.Io.Writer) !void {
    const current = keyring_zig.currentBackend();
    var buffer: [4]keyring_zig.Backend = undefined;
    const available = keyring_zig.availableBackends(&buffer);

    try stdout.print("current backend: {s}\n", .{backendName(current)});
    try stdout.writeAll("available backends: ");
    for (available, 0..) |backend, index| {
        if (index != 0) try stdout.writeAll(", ");
        try stdout.writeAll(backendName(backend));
    }
    try stdout.writeByte('\n');

    if (try getEnvVarOwned(arena, "KEYRING_BACKEND")) |value| {
        try stdout.print("KEYRING_BACKEND env: {s}\n", .{value});
    } else {
        try stdout.writeAll("KEYRING_BACKEND env: unset\n");
    }

    if (builtin.os.tag == .linux) {
        const service = "keyring-cli-diagnose-service-that-should-not-exist";
        const user = "keyring-cli-diagnose-user-that-should-not-exist";
        if (keyring_zig.getAlloc(arena, service, user)) |password| {
            _ = password;
        } else |err| switch (err) {
            error.NoStorageAccess => try stdout.writeAll("note: no Secret Service daemon detected. Try installing oo7-daemon (https://github.com/linux-credentials/oo7) or run dbus-run-session with gnome-keyring-daemon.\n"),
            else => {},
        }
    } else {
        try stdout.print("native backend: {s}\n", .{backendName(nativeBackend())});
    }
    try stdout.flush();
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

fn nativeBackend() keyring_zig.Backend {
    return switch (builtin.os.tag) {
        .linux => .secret_service,
        .macos => .keychain,
        .windows => .win_credential,
        else => .null_backend,
    };
}

fn backendName(backend: keyring_zig.Backend) []const u8 {
    return switch (backend) {
        .secret_service => "secret_service",
        .keychain => "keychain",
        .win_credential => "win_credential",
        .null_backend => "null_backend",
    };
}

pub fn exitCodeFor(err: keyring_zig.Error) u8 {
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
        => 1,
    };
}

fn printKeyringError(stderr: *std.Io.Writer, err: keyring_zig.Error) !void {
    try stderr.print("keyring: {s}\n", .{errorMessage(err)});
    try stderr.flush();
}

fn errorMessage(err: keyring_zig.Error) []const u8 {
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
    try expectCommandTag(.version, parseArgs(&.{ "keyring", "--version" }));
    try expectCommandTag(.version, parseArgs(&.{ "keyring", "-v" }));
    try expectCommandTag(.list_backends, parseArgs(&.{ "keyring", "--list-backends" }));
    try expectCommandTag(.diagnose, parseArgs(&.{ "keyring", "diagnose" }));
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
    try std.testing.expectEqual(keyring_zig.Backend.null_backend, parsed.backend.?);
    try expectCommandTag(.get, parsed);

    const parsed_long = parseArgs(&.{ "keyring", "-b", "secret_service", "set", "svc", "user" });
    try std.testing.expectEqual(keyring_zig.Backend.secret_service, parsed_long.backend.?);
    try expectCommandTag(.set, parsed_long);
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
