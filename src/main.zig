const std = @import("std");
const builtin = @import("builtin");
const keyring_zig = @import("keyring_zig");

const version = "0.0.0";
const usage =
    \\usage: keyring <command> [args]
    \\
    \\Commands:
    \\  --help, -h, help              Show this help.
    \\  --version, -v                 Show version.
    \\  --list-backends               List available backends.
    \\  set <service> <user>          Store a password (not yet implemented).
    \\  get <service> <user>          Read a password (not yet implemented).
    \\  del <service> <user>          Delete a password (not yet implemented).
    \\
;

const Dispatch = enum {
    help,
    version,
    list_backends,
    not_implemented,
    usage_error,
};

comptime {
    _ = keyring_zig.get;
    _ = keyring_zig.getAlloc;
    _ = keyring_zig.set;
    _ = keyring_zig.delete;
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const raw_args = try init.minimal.args.toSlice(arena);
    const args = try arena.alloc([]const u8, raw_args.len);
    for (raw_args, args) |raw, *arg| {
        arg.* = raw;
    }

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(init.io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(init.io, &stderr_buffer);
    const stderr = &stderr_writer.interface;

    const exit_code: u8 = switch (parseArgs(args)) {
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
            try stdout.print("{s}\nnull\n", .{nativeBackendName()});
            try stdout.flush();
            break :code 0;
        },
        .not_implemented => code: {
            try stderr.writeAll("not yet implemented\n");
            try stderr.flush();
            break :code 1;
        },
        .usage_error => code: {
            try stderr.writeAll(usage);
            try stderr.flush();
            break :code 2;
        },
    };

    std.process.exit(exit_code);
}

pub fn parseArgs(args: []const []const u8) Dispatch {
    if (args.len < 2) return .help;

    const command = args[1];
    if (std.mem.eql(u8, command, "--help") or
        std.mem.eql(u8, command, "-h") or
        std.mem.eql(u8, command, "help"))
    {
        return if (args.len == 2) .help else .usage_error;
    }

    if (std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "-v")) {
        return if (args.len == 2) .version else .usage_error;
    }

    if (std.mem.eql(u8, command, "--list-backends")) {
        return if (args.len == 2) .list_backends else .usage_error;
    }

    if (std.mem.eql(u8, command, "set") or
        std.mem.eql(u8, command, "get") or
        std.mem.eql(u8, command, "del"))
    {
        return if (args.len == 4) .not_implemented else .usage_error;
    }

    return .usage_error;
}

fn nativeBackendName() []const u8 {
    return switch (builtin.os.tag) {
        .linux => "secret_service",
        .macos => "keychain",
        .windows => "win_credential",
        else => "null",
    };
}

test "argv parsing" {
    const args = &[_][]const u8{ "keyring", "--help" };
    try std.testing.expectEqual(Dispatch.help, parseArgs(args));
}
