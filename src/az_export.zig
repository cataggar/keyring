//! `keyring az export <dir>` — one-shot export of the local Azure CLI MSAL
//! token cache and `azureProfile.json`, written as plaintext into `<dir>` so
//! the pair can be copied (e.g. via `scp`) into `~/.azure/` on another machine
//! and picked up by `az account get-access-token` without a second
//! interactive `az login`.
//!
//! azure-cli-core only enables token cache encryption by default on Windows
//! (`should_encrypt_token_cache`'s fallback is `sys.platform.startswith('win32')`
//! in `azure/cli/core/util.py`); on macOS and Linux the cache is plaintext
//! JSON at `~/.azure/msal_token_cache.json` unless the user explicitly ran
//! `az config set core.encrypt_token_cache=true`. In that case,
//! `azure/cli/core/auth/persistence.py` hardcodes the macOS Keychain lookup as
//! service "my_service_name", account "my_account_name" (the on-disk
//! `msal_token_cache.bin` is only a touch file used for mtime tracking) — this
//! module reads that entry via `keychain.zig` as a fallback. The equivalent
//! Linux libsecret and Windows DPAPI encrypted paths are not supported; the
//! caller is told to disable encryption instead.
//!
//! This is read-only against the source cache: nothing under `~/.azure` is
//! ever deleted or modified.
const std = @import("std");
const builtin = @import("builtin");
const keychain = @import("keychain.zig");
const msal_cache = @import("msal_cache.zig");

const Allocator = std.mem.Allocator;

const keychain_service = "my_service_name";
const keychain_account = "my_account_name";

const Resolved = struct {
    content: []u8,
    source_label: []const u8,
};

const ResolveError = error{
    NotFound,
    NoStorageAccess,
    ReadFailure,
    EncryptedUnsupported,
    OutOfMemory,
};

/// Run the export and print a human-readable report. Returns the process exit
/// code (0 success, 1 generic failure, 3 source cache not found, 4 the
/// Keychain entry exists but is locked/inaccessible).
pub fn run(gpa: Allocator, dest_dir: []const u8, stdout: *std.Io.Writer, stderr: *std.Io.Writer) !u8 {
    const home = msal_cache.getHome(gpa) orelse {
        try stderr.writeAll("keyring: az export: could not resolve home directory (HOME not set)\n");
        try stderr.flush();
        return 1;
    };
    defer gpa.free(home);

    const azure_dir = try std.fs.path.join(gpa, &.{ home, ".azure" });
    defer gpa.free(azure_dir);

    const resolved = resolveTokenCache(gpa, azure_dir) catch |err| return reportResolveError(stderr, err);
    defer gpa.free(resolved.content);

    writeFilePlain(gpa, dest_dir, "msal_token_cache.json", resolved.content) catch |err| {
        try stderr.print("keyring: az export: failed to write msal_token_cache.json: {s}\n", .{@errorName(err)});
        try stderr.flush();
        return 1;
    };
    try stdout.print("wrote {s}/msal_token_cache.json (source: {s})\n", .{ dest_dir, resolved.source_label });

    const profile_src = try std.fs.path.join(gpa, &.{ azure_dir, "azureProfile.json" });
    defer gpa.free(profile_src);
    if (readFileIfExists(gpa, profile_src)) |profile_content| {
        defer gpa.free(profile_content);
        writeFilePlain(gpa, dest_dir, "azureProfile.json", profile_content) catch |err| {
            try stderr.print("keyring: az export: failed to write azureProfile.json: {s}\n", .{@errorName(err)});
            try stderr.flush();
            return 1;
        };
        try stdout.print("wrote {s}/azureProfile.json\n", .{dest_dir});
    } else {
        try stdout.writeAll("note: azureProfile.json not found under ~/.azure; az may need it for tenant/subscription context\n");
    }

    try stdout.writeAll("\nnext steps:\n");
    try stdout.print("  scp {s}/msal_token_cache.json {s}/azureProfile.json <host>:~/.azure/\n", .{ dest_dir, dest_dir });
    try stdout.writeAll("  on the destination, only if it has core.encrypt_token_cache=true set: az config set core.encrypt_token_cache=false\n");
    try stdout.writeAll("  then verify: az account get-access-token\n");
    try stdout.flush();
    return 0;
}

/// Find the local az-cli MSAL token cache content, preferring the plaintext
/// file (the default on macOS/Linux) and falling back to the macOS Keychain
/// entry when encryption was explicitly enabled.
fn resolveTokenCache(gpa: Allocator, azure_dir: []const u8) ResolveError!Resolved {
    const json_path = try std.fs.path.join(gpa, &.{ azure_dir, "msal_token_cache.json" });
    defer gpa.free(json_path);
    if (readFileIfExists(gpa, json_path)) |content| {
        return .{ .content = content, .source_label = "plaintext file (msal_token_cache.json)" };
    }

    switch (builtin.os.tag) {
        .macos => {
            if (keychain.get(gpa, keychain_service, keychain_account)) |content| {
                return .{ .content = content, .source_label = "macOS Keychain (service \"" ++ keychain_service ++ "\")" };
            } else |err| switch (err) {
                error.EntryNotFound => {},
                error.NoStorageAccess => return error.NoStorageAccess,
                error.StorageFailure => return error.ReadFailure,
                error.OutOfMemory => return error.OutOfMemory,
            }
        },
        else => {},
    }

    const bin_path = try std.fs.path.join(gpa, &.{ azure_dir, "msal_token_cache.bin" });
    defer gpa.free(bin_path);
    if (fileExists(bin_path)) return error.EncryptedUnsupported;

    return error.NotFound;
}

fn reportResolveError(stderr: *std.Io.Writer, err: ResolveError) !u8 {
    switch (err) {
        error.NotFound => {
            try stderr.writeAll("keyring: az export: no msal_token_cache.json or .bin found under ~/.azure; run `az login` first\n");
            try stderr.flush();
            return 3;
        },
        error.NoStorageAccess => {
            try stderr.writeAll("keyring: az export: the Keychain item is currently locked/inaccessible\n");
            try stderr.flush();
            return 4;
        },
        error.EncryptedUnsupported => {
            try stderr.writeAll(
                "keyring: az export: msal_token_cache.bin is encrypted on this platform and not supported by az export\n" ++
                    "  run `az config set core.encrypt_token_cache=false` then `az login` again, or export from macOS instead\n",
            );
            try stderr.flush();
            return 1;
        },
        error.ReadFailure, error.OutOfMemory => {
            try stderr.print("keyring: az export: failed to read token cache: {s}\n", .{@errorName(err)});
            try stderr.flush();
            return 1;
        },
    }
}

fn readFileIfExists(gpa: Allocator, path: []const u8) ?[]u8 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(8 * 1024 * 1024)) catch null;
}

fn fileExists(path: []const u8) bool {
    const io = std.Io.Threaded.global_single_threaded.io();
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn writeFilePlain(gpa: Allocator, dir: []const u8, name: []const u8, contents: []const u8) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    _ = std.Io.Dir.cwd().createDirPathStatus(io, dir, dirPermissions()) catch return error.WriteFailure;
    const path = try std.fs.path.join(gpa, &.{ dir, name });
    defer gpa.free(path);
    var file = std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true, .permissions = filePermissions() }) catch return error.WriteFailure;
    defer file.close(io);
    file.writeStreamingAll(io, contents) catch return error.WriteFailure;
}

fn dirPermissions() std.Io.File.Permissions {
    return if (builtin.os.tag == .windows) .default_dir else .fromMode(0o700);
}

fn filePermissions() std.Io.File.Permissions {
    return if (builtin.os.tag == .windows) .default_file else .fromMode(0o600);
}

test "resolveTokenCache prefers plaintext json over bin" {
    const gpa = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &buf);
    const dir_path = try gpa.dupe(u8, buf[0..len]);
    defer gpa.free(dir_path);

    try tmp.dir.writeFile(io, .{ .sub_path = "msal_token_cache.json", .data = "{\"RefreshToken\":{}}" });

    const resolved = try resolveTokenCache(gpa, dir_path);
    defer gpa.free(resolved.content);
    try std.testing.expectEqualStrings("{\"RefreshToken\":{}}", resolved.content);
    try std.testing.expectEqualStrings("plaintext file (msal_token_cache.json)", resolved.source_label);
}

test "resolveTokenCache reports NotFound when nothing is present" {
    const gpa = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &buf);
    const dir_path = try gpa.dupe(u8, buf[0..len]);
    defer gpa.free(dir_path);

    try std.testing.expectError(error.NotFound, resolveTokenCache(gpa, dir_path));
}

test "resolveTokenCache reports EncryptedUnsupported when only bin is present on non-macOS" {
    if (builtin.os.tag == .macos) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &buf);
    const dir_path = try gpa.dupe(u8, buf[0..len]);
    defer gpa.free(dir_path);

    try tmp.dir.writeFile(io, .{ .sub_path = "msal_token_cache.bin", .data = "\x01\x02not-json" });

    try std.testing.expectError(error.EncryptedUnsupported, resolveTokenCache(gpa, dir_path));
}
