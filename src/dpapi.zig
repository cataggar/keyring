//! Minimal Windows DPAPI (crypt32) wrapper used by the ADO backend to protect
//! the per-org session token file (`session.dat`) at rest.
//!
//! `protect` wraps `CryptProtectData` and `unprotect` wraps `CryptUnprotectData`
//! in the current-user scope (no `CRYPTPROTECT_LOCAL_MACHINE`) with
//! `CRYPTPROTECT_UI_FORBIDDEN` so the calls never block on a UI prompt. The
//! ciphertext can only be decrypted by the same Windows user on the same
//! machine. A failed `unprotect` (e.g. a corrupt or foreign blob) surfaces as
//! `error.UnprotectFailed`, which the caller treats as a corrupt cache to be
//! rewritten from scratch.
//!
//! These declarations are only referenced under `builtin.os.tag == .windows`
//! branches, so the unreferenced externs are dropped on other targets.
const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;

pub const Error = error{ ProtectFailed, UnprotectFailed, OutOfMemory };

const BOOL = i32;
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

const DATA_BLOB = extern struct {
    cbData: u32,
    pbData: ?[*]u8,
};

extern "crypt32" fn CryptProtectData(
    pDataIn: *DATA_BLOB,
    szDataDescr: ?[*:0]const u16,
    pOptionalEntropy: ?*DATA_BLOB,
    pvReserved: ?*anyopaque,
    pPromptStruct: ?*anyopaque,
    dwFlags: u32,
    pDataOut: *DATA_BLOB,
) callconv(.winapi) BOOL;

extern "crypt32" fn CryptUnprotectData(
    pDataIn: *DATA_BLOB,
    ppszDataDescr: ?*?[*:0]u16,
    pOptionalEntropy: ?*DATA_BLOB,
    pvReserved: ?*anyopaque,
    pPromptStruct: ?*anyopaque,
    dwFlags: u32,
    pDataOut: *DATA_BLOB,
) callconv(.winapi) BOOL;

extern "kernel32" fn LocalFree(hMem: ?*anyopaque) callconv(.winapi) ?*anyopaque;

/// Encrypt `data` with DPAPI (current-user). Caller owns the returned slice.
pub fn protect(gpa: Allocator, data: []const u8) Error![]u8 {
    const cb_in = std.math.cast(u32, data.len) orelse return error.ProtectFailed;
    var empty_byte: u8 = 0;
    var in = DATA_BLOB{
        .cbData = cb_in,
        .pbData = if (data.len == 0) @ptrCast(&empty_byte) else @constCast(data.ptr),
    };
    var out = DATA_BLOB{ .cbData = 0, .pbData = null };
    if (CryptProtectData(&in, null, null, null, null, CRYPTPROTECT_UI_FORBIDDEN, &out) == 0) {
        return error.ProtectFailed;
    }
    defer if (out.pbData) |p| {
        const out_len: usize = @intCast(out.cbData);
        if (out_len > 0) std.crypto.secureZero(u8, p[0..out_len]);
        _ = LocalFree(p);
    };

    const ptr = out.pbData orelse return error.ProtectFailed;
    const len: usize = @intCast(out.cbData);
    if (len == 0) return error.ProtectFailed;
    return gpa.dupe(u8, ptr[0..len]) catch error.OutOfMemory;
}

/// Decrypt a DPAPI blob produced by `protect`. Caller owns the returned slice.
/// Returns `error.UnprotectFailed` for blobs this user/machine cannot decrypt.
pub fn unprotect(gpa: Allocator, data: []const u8) Error![]u8 {
    if (data.len == 0) return error.UnprotectFailed;
    const cb_in = std.math.cast(u32, data.len) orelse return error.UnprotectFailed;

    var in = DATA_BLOB{ .cbData = cb_in, .pbData = @constCast(data.ptr) };
    var out = DATA_BLOB{ .cbData = 0, .pbData = null };
    if (CryptUnprotectData(&in, null, null, null, null, CRYPTPROTECT_UI_FORBIDDEN, &out) == 0) {
        return error.UnprotectFailed;
    }
    defer if (out.pbData) |p| {
        const out_len: usize = @intCast(out.cbData);
        if (out_len > 0) std.crypto.secureZero(u8, p[0..out_len]);
        _ = LocalFree(p);
    };

    const len: usize = @intCast(out.cbData);
    if (len == 0) return gpa.dupe(u8, "") catch error.OutOfMemory;
    const ptr = out.pbData orelse return error.UnprotectFailed;
    return gpa.dupe(u8, ptr[0..len]) catch error.OutOfMemory;
}

test "dpapi unprotect rejects empty input and round-trips on Windows" {
    if (comptime builtin.os.tag != .windows) return;
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.UnprotectFailed, unprotect(gpa, ""));

    const empty_ct = try protect(gpa, "");
    defer gpa.free(empty_ct);
    try std.testing.expect(empty_ct.len > 0);
    const empty_pt = try unprotect(gpa, empty_ct);
    defer gpa.free(empty_pt);
    try std.testing.expectEqualStrings("", empty_pt);

    const ct = try protect(gpa, "dpapi-secret");
    defer gpa.free(ct);
    const pt = try unprotect(gpa, ct);
    defer gpa.free(pt);
    try std.testing.expectEqualStrings("dpapi-secret", pt);
}
