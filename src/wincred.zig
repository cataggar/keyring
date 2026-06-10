//! Minimal Windows Credential Manager (advapi32) wrapper used by the ADO backend
//! to persist the long-lived OAuth refresh token outside of a cleartext file.
//!
//! The credential is stored as a single GENERIC credential whose TargetName is
//! the service string verbatim (e.g. `ado-keyring`) so it can be inspected and
//! removed with `cmdkey /list:<service>` and `cmdkey /delete:<service>`.
const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;

pub const Error = error{ EntryNotFound, StorageFailure, OutOfMemory, InvalidUtf8 };

const BOOL = i32;
const CRED_TYPE_GENERIC: u32 = 1;
const CRED_PERSIST_LOCAL_MACHINE: u32 = 2;
const ERROR_NOT_FOUND: u32 = 1168;

const FILETIME = extern struct {
    dwLowDateTime: u32,
    dwHighDateTime: u32,
};

const CREDENTIALW = extern struct {
    Flags: u32,
    Type: u32,
    TargetName: ?[*:0]u16,
    Comment: ?[*:0]u16,
    LastWritten: FILETIME,
    CredentialBlobSize: u32,
    CredentialBlob: ?[*]u8,
    Persist: u32,
    AttributeCount: u32,
    Attributes: ?*anyopaque,
    TargetAlias: ?[*:0]u16,
    UserName: ?[*:0]u16,
};

extern "kernel32" fn GetLastError() callconv(.winapi) u32;
extern "advapi32" fn CredReadW(
    TargetName: ?[*:0]const u16,
    Type: u32,
    Flags: u32,
    Credential: ?*?*CREDENTIALW,
) callconv(.winapi) BOOL;
extern "advapi32" fn CredWriteW(Credential: ?*CREDENTIALW, Flags: u32) callconv(.winapi) BOOL;
extern "advapi32" fn CredDeleteW(TargetName: ?[*:0]const u16, Type: u32, Flags: u32) callconv(.winapi) BOOL;
extern "advapi32" fn CredFree(Buffer: ?*anyopaque) callconv(.winapi) void;

fn toUtf16Z(gpa: Allocator, value: []const u8) Error![:0]u16 {
    return std.unicode.utf8ToUtf16LeAllocZ(gpa, value) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidUtf8,
    };
}

/// Read the credential blob stored under `target`. Caller owns the returned slice.
pub fn get(gpa: Allocator, target: []const u8) Error![]u8 {
    const target_w = try toUtf16Z(gpa, target);
    defer gpa.free(target_w);

    var cred: ?*CREDENTIALW = null;
    if (CredReadW(target_w.ptr, CRED_TYPE_GENERIC, 0, &cred) == 0) {
        return switch (GetLastError()) {
            ERROR_NOT_FOUND => error.EntryNotFound,
            else => error.StorageFailure,
        };
    }
    defer if (cred) |ptr| CredFree(ptr);

    const c = cred orelse return error.StorageFailure;
    const len: usize = @intCast(c.CredentialBlobSize);
    const blob = c.CredentialBlob orelse return if (len == 0) gpa.dupe(u8, "") else error.StorageFailure;
    return gpa.dupe(u8, blob[0..len]);
}

/// Store `value` under `target` (current-user, local-machine persisted).
pub fn set(gpa: Allocator, target: []const u8, user: []const u8, value: []const u8) Error!void {
    const target_w = try toUtf16Z(gpa, target);
    defer gpa.free(target_w);
    const user_w = try toUtf16Z(gpa, user);
    defer gpa.free(user_w);

    var cred: CREDENTIALW = .{
        .Flags = 0,
        .Type = CRED_TYPE_GENERIC,
        .TargetName = target_w.ptr,
        .Comment = null,
        .LastWritten = std.mem.zeroes(FILETIME),
        .CredentialBlobSize = @intCast(value.len),
        .CredentialBlob = @constCast(value.ptr),
        .Persist = CRED_PERSIST_LOCAL_MACHINE,
        .AttributeCount = 0,
        .Attributes = null,
        .TargetAlias = null,
        .UserName = user_w.ptr,
    };
    if (CredWriteW(&cred, 0) == 0) return error.StorageFailure;
}

/// Remove the credential under `target`. Returns EntryNotFound if absent.
pub fn delete(gpa: Allocator, target: []const u8) Error!void {
    const target_w = try toUtf16Z(gpa, target);
    defer gpa.free(target_w);
    if (CredDeleteW(target_w.ptr, CRED_TYPE_GENERIC, 0) == 0) {
        return switch (GetLastError()) {
            ERROR_NOT_FOUND => error.EntryNotFound,
            else => error.StorageFailure,
        };
    }
}
