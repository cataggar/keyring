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
    if (data.len == 0) return gpa.dupe(u8, "") catch error.OutOfMemory;

    var in = DATA_BLOB{ .cbData = @intCast(data.len), .pbData = @constCast(data.ptr) };
    var out = DATA_BLOB{ .cbData = 0, .pbData = null };
    if (CryptProtectData(&in, null, null, null, null, CRYPTPROTECT_UI_FORBIDDEN, &out) == 0) {
        return error.ProtectFailed;
    }
    defer _ = LocalFree(out.pbData);

    const ptr = out.pbData orelse return error.ProtectFailed;
    const len: usize = @intCast(out.cbData);
    return gpa.dupe(u8, ptr[0..len]) catch error.OutOfMemory;
}

/// Decrypt a DPAPI blob produced by `protect`. Caller owns the returned slice.
/// Returns `error.UnprotectFailed` for blobs this user/machine cannot decrypt.
pub fn unprotect(gpa: Allocator, data: []const u8) Error![]u8 {
    if (data.len == 0) return gpa.dupe(u8, "") catch error.OutOfMemory;

    var in = DATA_BLOB{ .cbData = @intCast(data.len), .pbData = @constCast(data.ptr) };
    var out = DATA_BLOB{ .cbData = 0, .pbData = null };
    if (CryptUnprotectData(&in, null, null, null, null, CRYPTPROTECT_UI_FORBIDDEN, &out) == 0) {
        return error.UnprotectFailed;
    }
    defer _ = LocalFree(out.pbData);

    const ptr = out.pbData orelse return error.UnprotectFailed;
    const len: usize = @intCast(out.cbData);
    return gpa.dupe(u8, ptr[0..len]) catch error.OutOfMemory;
}
