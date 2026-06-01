const std = @import("std");
const builtin = @import("builtin");

const EchoState = union(enum) {
    posix: std.posix.termios,
    windows: std.os.windows.DWORD,
    none,
};

const windows_api = if (builtin.os.tag == .windows) struct {
    const ENABLE_ECHO_INPUT: std.os.windows.DWORD = 0x0004;

    extern "kernel32" fn GetConsoleMode(
        hConsoleHandle: std.os.windows.HANDLE,
        lpMode: *std.os.windows.DWORD,
    ) callconv(.winapi) std.os.windows.BOOL;

    extern "kernel32" fn SetConsoleMode(
        hConsoleHandle: std.os.windows.HANDLE,
        dwMode: std.os.windows.DWORD,
    ) callconv(.winapi) std.os.windows.BOOL;
} else struct {};

pub fn readPassword(
    gpa: std.mem.Allocator,
    io: std.Io,
    stderr: *std.Io.Writer,
    service: []const u8,
    user: []const u8,
) ![]u8 {
    const stdin = std.Io.File.stdin();
    const is_tty = stdin.isTty(io) catch false;
    if (!is_tty) return readPipedPassword(gpa, io);

    try stderr.print("Password for '{s}' on '{s}': ", .{ user, service });
    try stderr.flush();

    const echo_state = try disableStdinEcho();
    defer restoreStdinEcho(echo_state);
    defer {
        stderr.writeByte('\n') catch {};
        stderr.flush() catch {};
    }

    var stdin_buffer: [4096]u8 = undefined;
    var reader = stdin.reader(io, &stdin_buffer);
    var password: std.ArrayList(u8) = .empty;
    defer password.deinit(gpa);

    var chunk: [256]u8 = undefined;
    while (true) {
        const n = try reader.interface.readSliceShort(&chunk);
        if (n == 0) break;
        const bytes = chunk[0..n];
        if (std.mem.indexOfScalar(u8, bytes, '\n')) |newline| {
            try password.appendSlice(gpa, bytes[0..newline]);
            break;
        }
        try password.appendSlice(gpa, bytes);
    }

    const owned = try password.toOwnedSlice(gpa);
    return stripTrailingCr(owned);
}

fn readPipedPassword(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
    const stdin = std.Io.File.stdin();
    var stdin_buffer: [4096]u8 = undefined;
    var reader = stdin.reader(io, &stdin_buffer);
    const bytes = try reader.interface.allocRemaining(gpa, .unlimited);
    return stripSingleTrailingLineEnding(bytes);
}

fn disableStdinEcho() !EchoState {
    return switch (builtin.os.tag) {
        .windows => disableWindowsEcho(),
        .linux, .macos => disablePosixEcho(),
        else => .none,
    };
}

fn restoreStdinEcho(state: EchoState) void {
    switch (state) {
        .posix => |original| {
            if (builtin.os.tag != .windows) restorePosixEcho(original);
        },
        .windows => |mode| {
            if (builtin.os.tag == .windows) restoreWindowsEcho(mode);
        },
        .none => {},
    }
}

fn disablePosixEcho() !EchoState {
    const original = try std.posix.tcgetattr(std.posix.STDIN_FILENO);
    var no_echo = original;
    no_echo.lflag.ECHO = false;
    try std.posix.tcsetattr(std.posix.STDIN_FILENO, .NOW, no_echo);
    return .{ .posix = original };
}

fn restorePosixEcho(original: std.posix.termios) void {
    std.posix.tcsetattr(std.posix.STDIN_FILENO, .NOW, original) catch {};
}

fn disableWindowsEcho() !EchoState {
    const stdin = std.Io.File.stdin();
    var mode: std.os.windows.DWORD = 0;
    if (!windows_api.GetConsoleMode(stdin.handle, &mode).toBool()) return .none;
    const no_echo = mode & ~windows_api.ENABLE_ECHO_INPUT;
    if (!windows_api.SetConsoleMode(stdin.handle, no_echo).toBool()) return .none;
    return .{ .windows = mode };
}

fn restoreWindowsEcho(mode: std.os.windows.DWORD) void {
    const stdin = std.Io.File.stdin();
    _ = windows_api.SetConsoleMode(stdin.handle, mode);
}

fn stripSingleTrailingLineEnding(bytes: []u8) []u8 {
    if (bytes.len >= 2 and bytes[bytes.len - 2] == '\r' and bytes[bytes.len - 1] == '\n') return bytes[0 .. bytes.len - 2];
    if (bytes.len > 0 and bytes[bytes.len - 1] == '\n') return bytes[0 .. bytes.len - 1];
    return bytes;
}

fn stripTrailingCr(bytes: []u8) []u8 {
    if (bytes.len > 0 and bytes[bytes.len - 1] == '\r') return bytes[0 .. bytes.len - 1];
    return bytes;
}
