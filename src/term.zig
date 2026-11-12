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

pub fn isStdoutTty() bool {
    return switch (builtin.os.tag) {
        .linux, .macos => std.c.isatty(1) != 0,
        .windows => false,
        else => false,
    };
}

const max_password_bytes: usize = 64 * 1024;

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
    defer std.crypto.secureZero(u8, &stdin_buffer);
    var reader = stdin.reader(io, &stdin_buffer);
    var password: std.ArrayList(u8) = .empty;
    defer {
        if (password.capacity > 0) std.crypto.secureZero(u8, password.allocatedSlice());
        password.deinit(gpa);
    }

    var chunk: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &chunk);
    while (true) {
        const n = try reader.interface.readSliceShort(&chunk);
        if (n == 0) break;
        const bytes = chunk[0..n];
        if (std.mem.indexOfScalar(u8, bytes, '\n')) |newline| {
            if (newline > max_password_bytes - password.items.len) return error.StreamTooLong;
            try password.appendSlice(gpa, bytes[0..newline]);
            break;
        }
        if (bytes.len > max_password_bytes - password.items.len) return error.StreamTooLong;
        try password.appendSlice(gpa, bytes);
    }

    const owned = try takeOwnedZeroing(gpa, &password);
    return stripTrailingCr(gpa, owned);
}

fn readPipedPassword(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
    const stdin = std.Io.File.stdin();
    var stdin_buffer: [4096]u8 = undefined;
    defer std.crypto.secureZero(u8, &stdin_buffer);
    var reader = stdin.reader(io, &stdin_buffer);
    return readBoundedPiped(&reader.interface, gpa, max_password_bytes);
}

fn readBoundedPiped(reader: *std.Io.Reader, gpa: std.mem.Allocator, limit: usize) ![]u8 {
    var password: std.ArrayList(u8) = .empty;
    defer {
        if (password.capacity > 0) std.crypto.secureZero(u8, password.allocatedSlice());
        password.deinit(gpa);
    }
    var chunk: [1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &chunk);
    while (true) {
        const n = try reader.readSliceShort(&chunk);
        if (n == 0) break;
        if (n > limit - password.items.len) return error.StreamTooLong;
        try password.appendSlice(gpa, chunk[0..n]);
    }
    const owned = try takeOwnedZeroing(gpa, &password);
    return stripSingleTrailingLineEnding(gpa, owned);
}

fn takeOwnedZeroing(gpa: std.mem.Allocator, list: *std.ArrayList(u8)) std.mem.Allocator.Error![]u8 {
    if (list.capacity == 0) {
        list.* = .empty;
        return gpa.alloc(u8, 0);
    }
    if (list.capacity == list.items.len) {
        const slice = list.items;
        list.* = .empty;
        return slice;
    }
    const full = list.allocatedSlice();
    std.crypto.secureZero(u8, full[list.items.len..]);
    if (gpa.resize(full, list.items.len)) {
        const slice = full[0..list.items.len];
        list.* = .empty;
        return slice;
    }
    const copy = try gpa.dupe(u8, list.items);
    std.crypto.secureZero(u8, full);
    list.deinit(gpa);
    list.* = .empty;
    return copy;
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

fn shrinkAndZeroTail(gpa: std.mem.Allocator, bytes: []u8, new_len: usize) std.mem.Allocator.Error![]u8 {
    if (new_len == bytes.len) return bytes;
    std.crypto.secureZero(u8, bytes[new_len..]);
    if (gpa.resize(bytes, new_len)) return bytes[0..new_len];
    const trimmed = gpa.dupe(u8, bytes[0..new_len]) catch |err| {
        std.crypto.secureZero(u8, bytes);
        gpa.free(bytes);
        return err;
    };
    std.crypto.secureZero(u8, bytes);
    gpa.free(bytes);
    return trimmed;
}

fn stripSingleTrailingLineEnding(gpa: std.mem.Allocator, bytes: []u8) std.mem.Allocator.Error![]u8 {
    const trimmed_len = if (bytes.len >= 2 and bytes[bytes.len - 2] == '\r' and bytes[bytes.len - 1] == '\n')
        bytes.len - 2
    else if (bytes.len > 0 and bytes[bytes.len - 1] == '\n')
        bytes.len - 1
    else
        bytes.len;
    return shrinkAndZeroTail(gpa, bytes, trimmed_len);
}

fn stripTrailingCr(gpa: std.mem.Allocator, bytes: []u8) std.mem.Allocator.Error![]u8 {
    const trimmed_len = if (bytes.len > 0 and bytes[bytes.len - 1] == '\r')
        bytes.len - 1
    else
        bytes.len;
    return shrinkAndZeroTail(gpa, bytes, trimmed_len);
}

test "stripping trailing LF and CRLF preserves sized Allocator.free" {
    const gpa = std.testing.allocator;

    const with_lf = try stripSingleTrailingLineEnding(gpa, try gpa.dupe(u8, "hunter2\n"));
    defer gpa.free(with_lf);
    try std.testing.expectEqualStrings("hunter2", with_lf);

    const with_crlf = try stripSingleTrailingLineEnding(gpa, try gpa.dupe(u8, "hunter2\r\n"));
    defer gpa.free(with_crlf);
    try std.testing.expectEqualStrings("hunter2", with_crlf);

    const double_lf = try stripSingleTrailingLineEnding(gpa, try gpa.dupe(u8, "hunter2\n\n"));
    defer gpa.free(double_lf);
    try std.testing.expectEqualStrings("hunter2\n", double_lf);

    const with_cr = try stripTrailingCr(gpa, try gpa.dupe(u8, "hunter2\r"));
    defer gpa.free(with_cr);
    try std.testing.expectEqualStrings("hunter2", with_cr);

    const plain = try stripSingleTrailingLineEnding(gpa, try gpa.dupe(u8, "hunter2"));
    defer gpa.free(plain);
    try std.testing.expectEqualStrings("hunter2", plain);
}

test "non-resizing allocator fallback and bounded piped reader free cleanly" {
    const NoResizeAllocator = struct {
        backing: std.mem.Allocator,

        fn allocator(self: *@This()) std.mem.Allocator {
            return .{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = std.mem.Allocator.noResize,
                    .remap = std.mem.Allocator.noRemap,
                    .free = free,
                },
            };
        }

        fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return self.backing.rawAlloc(len, alignment, ret_addr);
        }

        fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.backing.rawFree(memory, alignment, ret_addr);
        }
    };

    var wrapper: NoResizeAllocator = .{ .backing = std.testing.allocator };
    const no_resize = wrapper.allocator();

    const lf = try stripSingleTrailingLineEnding(no_resize, try no_resize.dupe(u8, "secret\n"));
    defer no_resize.free(lf);
    try std.testing.expectEqualStrings("secret", lf);

    const crlf = try stripSingleTrailingLineEnding(no_resize, try no_resize.dupe(u8, "secret\r\n"));
    defer no_resize.free(crlf);
    try std.testing.expectEqualStrings("secret", crlf);

    var r1 = std.Io.Reader.fixed("piped-secret\r\n");
    const piped = try readBoundedPiped(&r1, std.testing.allocator, 64);
    defer std.testing.allocator.free(piped);
    try std.testing.expectEqualStrings("piped-secret", piped);

    var r2 = std.Io.Reader.fixed("0123456789");
    try std.testing.expectError(error.StreamTooLong, readBoundedPiped(&r2, std.testing.allocator, 5));
}
