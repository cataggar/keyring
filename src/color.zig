const std = @import("std");

pub const Color = struct {
    enabled: bool,

    pub fn detect(env_get: fn ([]const u8) ?[]const u8, is_tty: bool) Color {
        if (env_get("NO_COLOR") != null) return .{ .enabled = false };
        if (env_get("CLICOLOR_FORCE")) |value| {
            if (!std.mem.eql(u8, value, "0")) return .{ .enabled = true };
        }
        return .{ .enabled = is_tty };
    }

    pub fn green(self: Color) []const u8 {
        return if (self.enabled) "\x1b[32m" else "";
    }

    pub fn yellow(self: Color) []const u8 {
        return if (self.enabled) "\x1b[33m" else "";
    }

    pub fn red(self: Color) []const u8 {
        return if (self.enabled) "\x1b[31m" else "";
    }

    pub fn bold(self: Color) []const u8 {
        return if (self.enabled) "\x1b[1m" else "";
    }

    pub fn reset(self: Color) []const u8 {
        return if (self.enabled) "\x1b[0m" else "";
    }
};
