//! Minimal macOS Keychain (Security.framework) wrapper used by the ADO backend
//! to persist the long-lived OAuth refresh token outside of a cleartext file.
//!
//! The credential is stored as a generic password item keyed on the service
//! (e.g. `ado-keyring`) and account (e.g. `refresh-token`) so it can be inspected
//! with `security find-generic-password -s <service>` and removed with
//! `security delete-generic-password -s <service>`.
//!
//! Only the symbols actually used are declared, mirroring the dependency's
//! `keyring-macos.zig`, to stay independent of macOS SDK header churn. The
//! `Security` and `CoreFoundation` frameworks are linked in `build.zig`. All
//! functions here are only ever referenced from a comptime-known
//! `builtin.os.tag == .macos` branch, so this file is not analyzed on other
//! targets and its Apple externs are never linked there.
const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Error = error{ EntryNotFound, NoStorageAccess, StorageFailure, OutOfMemory };

const __CFString = opaque {};
const __CFData = opaque {};
const __CFDictionary = opaque {};
const __CFAllocator = opaque {};
const __CFBoolean = opaque {};

const CFStringRef = ?*const __CFString;
const CFDataRef = ?*const __CFData;
const CFDictionaryRef = ?*const __CFDictionary;
const CFAllocatorRef = ?*const __CFAllocator;
const CFBooleanRef = ?*const __CFBoolean;
const CFTypeRef = ?*const anyopaque;
const CFIndex = c_long;
const Boolean = u8;
const CFStringEncoding = u32;
const UInt8 = u8;

const kCFStringEncodingUTF8: CFStringEncoding = 0x08000100;

const OSStatus = i32;
const errSecSuccess: OSStatus = 0;
const errSecItemNotFound: OSStatus = -25300;
const errSecAuthFailed: OSStatus = -25293;
const errSecInteractionNotAllowed: OSStatus = -25308;
const errSecNoAccessForItem: OSStatus = -25243;
const errSecInvalidOwnerEdit: OSStatus = -25244;

const CFDictionaryKeyCallBacks = opaque {};
const CFDictionaryValueCallBacks = opaque {};

const kCFTypeDictionaryKeyCallBacks: *const CFDictionaryKeyCallBacks =
    @extern(*const CFDictionaryKeyCallBacks, .{ .name = "kCFTypeDictionaryKeyCallBacks" });
const kCFTypeDictionaryValueCallBacks: *const CFDictionaryValueCallBacks =
    @extern(*const CFDictionaryValueCallBacks, .{ .name = "kCFTypeDictionaryValueCallBacks" });

extern "c" const kCFBooleanTrue: CFBooleanRef;

extern "c" const kSecClass: CFStringRef;
extern "c" const kSecClassGenericPassword: CFStringRef;
extern "c" const kSecAttrService: CFStringRef;
extern "c" const kSecAttrAccount: CFStringRef;
extern "c" const kSecMatchLimit: CFStringRef;
extern "c" const kSecMatchLimitOne: CFStringRef;
extern "c" const kSecReturnData: CFStringRef;
extern "c" const kSecValueData: CFStringRef;
extern "c" const kSecAttrAccessible: CFStringRef;
extern "c" const kSecAttrAccessibleAfterFirstUnlock: CFStringRef;

extern "c" fn CFStringCreateWithBytes(
    alloc: CFAllocatorRef,
    bytes: [*]const u8,
    numBytes: CFIndex,
    encoding: CFStringEncoding,
    isExternalRepresentation: Boolean,
) CFStringRef;

extern "c" fn CFDataCreate(
    allocator: CFAllocatorRef,
    bytes: [*]const u8,
    length: CFIndex,
) CFDataRef;

extern "c" fn CFDictionaryCreate(
    allocator: CFAllocatorRef,
    keys: [*]const CFTypeRef,
    values: [*]const CFTypeRef,
    numValues: CFIndex,
    keyCallBacks: ?*const CFDictionaryKeyCallBacks,
    valueCallBacks: ?*const CFDictionaryValueCallBacks,
) CFDictionaryRef;

extern "c" fn CFRelease(cf: CFTypeRef) void;
extern "c" fn CFDataGetLength(data: CFDataRef) CFIndex;
extern "c" fn CFDataGetBytePtr(data: CFDataRef) [*]const UInt8;

extern "c" fn SecItemCopyMatching(query: CFDictionaryRef, result: *CFTypeRef) OSStatus;
extern "c" fn SecItemAdd(attributes: CFDictionaryRef, result: ?*CFTypeRef) OSStatus;
extern "c" fn SecItemUpdate(query: CFDictionaryRef, attributesToUpdate: CFDictionaryRef) OSStatus;
extern "c" fn SecItemDelete(query: CFDictionaryRef) OSStatus;

fn makeCfString(bytes: []const u8) Error!CFStringRef {
    return CFStringCreateWithBytes(null, bytes.ptr, @intCast(bytes.len), kCFStringEncodingUTF8, 0) orelse
        error.StorageFailure;
}

fn makeCfData(bytes: []const u8) Error!CFDataRef {
    return CFDataCreate(null, bytes.ptr, @intCast(bytes.len)) orelse error.StorageFailure;
}

/// Build a generic-password query matching `service`/`account`. When `with_data`
/// is true the query also requests a single matching item's data blob.
fn makeQueryDict(service: CFStringRef, account: CFStringRef, comptime with_data: bool) Error!CFDictionaryRef {
    const len = comptime if (with_data) 5 else 3;
    var keys: [len]CFTypeRef = undefined;
    var values: [len]CFTypeRef = undefined;

    keys[0] = kSecClass;
    values[0] = kSecClassGenericPassword;
    keys[1] = kSecAttrService;
    values[1] = service;
    keys[2] = kSecAttrAccount;
    values[2] = account;
    if (with_data) {
        keys[3] = kSecMatchLimit;
        values[3] = kSecMatchLimitOne;
        keys[4] = kSecReturnData;
        values[4] = kCFBooleanTrue;
    }

    return CFDictionaryCreate(
        null,
        &keys,
        &values,
        len,
        kCFTypeDictionaryKeyCallBacks,
        kCFTypeDictionaryValueCallBacks,
    ) orelse error.StorageFailure;
}

fn mapStatus(status: OSStatus) Error {
    return switch (status) {
        errSecItemNotFound => error.EntryNotFound,
        // A locked keychain, a cancelled unlock prompt, or an item owned by a
        // different application's ACL all surface as a lack of storage access.
        errSecInteractionNotAllowed,
        errSecAuthFailed,
        errSecNoAccessForItem,
        errSecInvalidOwnerEdit,
        => error.NoStorageAccess,
        else => error.StorageFailure,
    };
}

/// Read the generic-password blob stored under `service`/`account`. Caller owns
/// the returned slice.
pub fn get(gpa: Allocator, service: []const u8, account: []const u8) Error![]u8 {
    const cf_service = try makeCfString(service);
    defer CFRelease(cf_service);
    const cf_account = try makeCfString(account);
    defer CFRelease(cf_account);

    const query = try makeQueryDict(cf_service, cf_account, true);
    defer CFRelease(query);

    var out: CFTypeRef = undefined;
    const status = SecItemCopyMatching(query, &out);
    if (status != errSecSuccess) return mapStatus(status);
    defer if (out) |value| CFRelease(value);

    const data: CFDataRef = @ptrCast(out orelse return error.StorageFailure);
    const len: usize = @intCast(CFDataGetLength(data));
    const ptr = CFDataGetBytePtr(data);
    return gpa.dupe(u8, ptr[0..len]);
}

/// Store `value` under `service`/`account`, creating the item or updating it in
/// place. New items are marked `kSecAttrAccessibleAfterFirstUnlock` so they are
/// not readable by other apps without prompting and survive a reboot once the
/// device has been unlocked.
pub fn set(service: []const u8, account: []const u8, value: []const u8) Error!void {
    const cf_service = try makeCfString(service);
    defer CFRelease(cf_service);
    const cf_account = try makeCfString(account);
    defer CFRelease(cf_account);
    const cf_value = try makeCfData(value);
    defer CFRelease(cf_value);

    update(cf_service, cf_account, cf_value) catch |err| switch (err) {
        error.EntryNotFound => return add(cf_service, cf_account, cf_value),
        else => return err,
    };
}

fn update(service: CFStringRef, account: CFStringRef, value: CFDataRef) Error!void {
    const query = try makeQueryDict(service, account, false);
    defer CFRelease(query);

    var keys: [1]CFTypeRef = .{kSecValueData};
    var values: [1]CFTypeRef = .{value};
    const attrs = CFDictionaryCreate(
        null,
        &keys,
        &values,
        1,
        kCFTypeDictionaryKeyCallBacks,
        kCFTypeDictionaryValueCallBacks,
    ) orelse return error.StorageFailure;
    defer CFRelease(attrs);

    const status = SecItemUpdate(query, attrs);
    if (status != errSecSuccess) return mapStatus(status);
}

fn add(service: CFStringRef, account: CFStringRef, value: CFDataRef) Error!void {
    var keys: [5]CFTypeRef = undefined;
    var values: [5]CFTypeRef = undefined;
    keys[0] = kSecClass;
    values[0] = kSecClassGenericPassword;
    keys[1] = kSecAttrService;
    values[1] = service;
    keys[2] = kSecAttrAccount;
    values[2] = account;
    keys[3] = kSecValueData;
    values[3] = value;
    keys[4] = kSecAttrAccessible;
    values[4] = kSecAttrAccessibleAfterFirstUnlock;

    const attrs = CFDictionaryCreate(
        null,
        &keys,
        &values,
        5,
        kCFTypeDictionaryKeyCallBacks,
        kCFTypeDictionaryValueCallBacks,
    ) orelse return error.StorageFailure;
    defer CFRelease(attrs);

    const status = SecItemAdd(attrs, null);
    if (status != errSecSuccess) return mapStatus(status);
}

/// Remove the generic-password item under `service`/`account`. Returns
/// `error.EntryNotFound` if absent.
pub fn delete(service: []const u8, account: []const u8) Error!void {
    const cf_service = try makeCfString(service);
    defer CFRelease(cf_service);
    const cf_account = try makeCfString(account);
    defer CFRelease(cf_account);

    const query = try makeQueryDict(cf_service, cf_account, false);
    defer CFRelease(query);

    const status = SecItemDelete(query);
    if (status != errSecSuccess) return mapStatus(status);
}
