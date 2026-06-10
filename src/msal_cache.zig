//! Read-only consumer of the shared MSAL token cache (issue #19, Phase 1).
//!
//! Microsoft developer tools (Azure CLI, Visual Studio, Azure PowerShell,
//! git-credential-manager) persist OAuth tokens in an MSAL cache. Apps in the
//! Family of Client IDs (FOCI) can redeem each other's refresh tokens, so the
//! ADO backend can read a Family Refresh Token (FRT) out of these caches and
//! redeem it for an Azure DevOps token without prompting the user — sharing an
//! account with `az login`.
//!
//! This module is strictly read-only: it never writes back to the MSAL cache.
//! The rotated refresh token returned by the `/token` endpoint is persisted in
//! keyring's own cache by the caller.
const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;

const opt_out_env = "KEYRING_ADO_MSAL_CACHE";
const location_override_env = "ARTIFACTS_CREDENTIALPROVIDER_MSAL_FILECACHE_LOCATION";

/// A refresh token selected from the MSAL cache. Strings are owned by the
/// allocator passed to `findFociRefreshToken`.
pub const Candidate = struct {
    secret: []const u8,
    home_account_id: []const u8,
};

const CacheFile = struct {
    label: []const u8,
    path: []const u8,
};

/// Aggregate counts for a single parsed cache file.
const Counts = struct {
    foci_rt: usize = 0,
    prt: usize = 0,
};

/// Per-file status used by `diagnose`.
pub const FileReport = struct {
    label: []const u8,
    path: []const u8,
    exists: bool,
    readable: bool,
    foci_rt: usize,
    prt: usize,
    selected: bool,
};

/// Return the best usable FOCI refresh token across all known MSAL caches, or
/// null when disabled, absent, or only unredeemable PRTs are present.
pub fn findFociRefreshToken(gpa: Allocator) ?Candidate {
    if (!isEnabled(gpa)) return null;

    const files = candidateFiles(gpa) catch return null;
    defer freeCandidateFiles(gpa, files);

    var best_secret: ?[]const u8 = null;
    var best_home: []const u8 = "";
    var best_freshness: i64 = -1;

    for (files) |file| {
        const json = readDecoded(gpa, file.path) orelse continue;
        defer gpa.free(json);
        var parsed = std.json.parseFromSlice(std.json.Value, gpa, json, .{}) catch continue;
        defer parsed.deinit();
        selectBest(parsed.value, &best_secret, &best_home, &best_freshness);
    }

    const secret = best_secret orelse return null;
    return .{
        .secret = gpa.dupe(u8, secret) catch return null,
        .home_account_id = gpa.dupe(u8, best_home) catch return null,
    };
}

/// Print a human-readable summary of the MSAL caches for `keyring diagnose`.
pub fn diagnose(gpa: Allocator, writer: *std.Io.Writer) !void {
    try writer.writeAll("MSAL cache (az login SSO):\n");
    if (!isEnabled(gpa)) {
        try writer.print("  disabled via {s}\n", .{opt_out_env});
        return;
    }

    const files = candidateFiles(gpa) catch {
        try writer.writeAll("  could not resolve cache paths\n");
        return;
    };
    defer freeCandidateFiles(gpa, files);

    var best_secret: ?[]const u8 = null;
    var best_home: []const u8 = "";
    var best_freshness: i64 = -1;
    var any = false;

    for (files) |file| {
        const json = readDecoded(gpa, file.path) orelse {
            if (fileExists(gpa, file.path)) {
                any = true;
                try writer.print("  [{s}] {s}\n    status: present, not readable (encrypted or non-plaintext)\n", .{ file.label, file.path });
            }
            continue;
        };
        defer gpa.free(json);
        any = true;
        var counts: Counts = .{};
        var parsed = std.json.parseFromSlice(std.json.Value, gpa, json, .{}) catch {
            try writer.print("  [{s}] {s}\n    status: readable, malformed JSON\n", .{ file.label, file.path });
            continue;
        };
        defer parsed.deinit();
        countAndSelect(parsed.value, &counts, &best_secret, &best_home, &best_freshness);
        try writer.print("  [{s}] {s}\n    status: readable, FOCI RTs: {d}, device-bound PRTs (unredeemable): {d}\n", .{ file.label, file.path, counts.foci_rt, counts.prt });
        if (counts.foci_rt == 0 and counts.prt > 0) {
            try writer.writeAll("    note: only device-bound PRTs present — strict Conditional Access tenants require WAM broker (not supported)\n");
        }
    }

    if (!any) {
        try writer.writeAll("  no MSAL caches found\n");
        return;
    }
    if (best_secret != null and best_home.len != 0) {
        try writer.print("  selected account: {s}\n", .{best_home});
    } else if (best_secret != null) {
        try writer.writeAll("  selected account: (unknown home_account_id)\n");
    } else {
        try writer.writeAll("  selected account: none usable\n");
    }
}

fn isEnabled(gpa: Allocator) bool {
    const value = getEnv(gpa, opt_out_env) orelse return true;
    defer gpa.free(value);
    if (std.ascii.eqlIgnoreCase(value, "false") or std.mem.eql(u8, value, "0")) return false;
    return true;
}

fn candidateFiles(gpa: Allocator) Allocator.Error![]CacheFile {
    var list: std.ArrayList(CacheFile) = .empty;
    errdefer freeCandidateFiles(gpa, list.items);

    if (getEnv(gpa, location_override_env)) |override| {
        try list.append(gpa, .{ .label = try gpa.dupe(u8, "override"), .path = override });
    }

    const home = getHome(gpa);
    defer if (home) |h| gpa.free(h);

    if (builtin.os.tag == .windows) {
        if (getEnv(gpa, "LOCALAPPDATA")) |lad| {
            defer gpa.free(lad);
            try appendJoin(gpa, &list, "vs/gcm", &.{ lad, ".IdentityService", "msal.cache" });
        }
    } else if (home) |h| {
        try appendJoin(gpa, &list, "vs/gcm", &.{ h, ".local", ".IdentityService", "msal.cache" });
    }

    if (home) |h| {
        try appendJoin(gpa, &list, "azcli", &.{ h, ".azure", "msal_token_cache.bin" });
        try appendJoin(gpa, &list, "azcli-legacy", &.{ h, ".azure", "msal_token_cache.json" });
    }

    return list.toOwnedSlice(gpa);
}

fn appendJoin(gpa: Allocator, list: *std.ArrayList(CacheFile), label: []const u8, parts: []const []const u8) Allocator.Error!void {
    const path = try std.fs.path.join(gpa, parts);
    errdefer gpa.free(path);
    const owned_label = try gpa.dupe(u8, label);
    errdefer gpa.free(owned_label);
    try list.append(gpa, .{ .label = owned_label, .path = path });
}

fn freeCandidateFiles(gpa: Allocator, files: []CacheFile) void {
    for (files) |file| {
        gpa.free(file.label);
        gpa.free(file.path);
    }
    gpa.free(files);
}

fn fileExists(gpa: Allocator, path: []const u8) bool {
    const io = std.Io.Threaded.global_single_threaded.io();
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1)) catch |err| switch (err) {
        error.FileNotFound => return false,
        error.StreamTooLong => return true,
        else => return false,
    };
    gpa.free(bytes);
    return true;
}

/// Read a cache file and return decoded JSON bytes (DPAPI-decrypted on Windows
/// when needed). Returns null when the file is missing or not plaintext JSON.
fn readDecoded(gpa: Allocator, path: []const u8) ?[]u8 {
    const io = std.Io.Threaded.global_single_threaded.io();
    const raw = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(8 * 1024 * 1024)) catch return null;
    defer gpa.free(raw);
    if (raw.len == 0) return null;

    if (builtin.os.tag == .windows) {
        if (dpapiUnprotect(gpa, raw)) |decrypted| {
            if (looksLikeJson(decrypted)) return decrypted;
            gpa.free(decrypted);
        }
    }
    if (looksLikeJson(raw)) return gpa.dupe(u8, raw) catch null;
    return null;
}

fn looksLikeJson(bytes: []const u8) bool {
    for (bytes) |c| {
        if (std.ascii.isWhitespace(c)) continue;
        return c == '{';
    }
    return false;
}

/// Walk the parsed cache, counting FOCI RTs and PRTs and tracking the freshest
/// usable FOCI refresh token.
fn countAndSelect(
    root: std.json.Value,
    counts: *Counts,
    best_secret: *?[]const u8,
    best_home: *[]const u8,
    best_freshness: *i64,
) void {
    if (root != .object) return;
    const foci_clients = collectFociClients(root);

    const rts = root.object.get("RefreshToken") orelse return;
    if (rts != .object) return;
    var it = rts.object.iterator();
    while (it.next()) |entry| {
        const rt = entry.value_ptr.*;
        if (rt != .object) continue;
        const secret = getString(rt, "secret") orelse continue;

        if (std.mem.startsWith(u8, secret, "0.")) {
            counts.prt += 1;
            continue;
        }
        if (!isUsableEnvironment(getString(rt, "environment"))) continue;
        if (!isFoci(rt, foci_clients)) continue;

        counts.foci_rt += 1;
        const freshness = entryFreshness(rt);
        if (freshness > best_freshness.*) {
            best_freshness.* = freshness;
            best_secret.* = secret;
            best_home.* = getString(rt, "home_account_id") orelse "";
        }
    }
}

fn selectBest(
    root: std.json.Value,
    best_secret: *?[]const u8,
    best_home: *[]const u8,
    best_freshness: *i64,
) void {
    var counts: Counts = .{};
    countAndSelect(root, &counts, best_secret, best_home, best_freshness);
}

/// Client IDs that advertise FOCI membership via AppMetadata.family_id == "1".
const FociClients = struct {
    root: std.json.Value,

    fn contains(self: FociClients, client_id: []const u8) bool {
        const meta = self.root.object.get("AppMetadata") orelse return false;
        if (meta != .object) return false;
        var it = meta.object.iterator();
        while (it.next()) |entry| {
            const m = entry.value_ptr.*;
            if (m != .object) continue;
            const fid = getString(m, "family_id") orelse continue;
            if (!std.mem.eql(u8, fid, "1")) continue;
            const cid = getString(m, "client_id") orelse continue;
            if (std.mem.eql(u8, cid, client_id)) return true;
        }
        return false;
    }
};

fn collectFociClients(root: std.json.Value) FociClients {
    return .{ .root = root };
}

fn isFoci(rt: std.json.Value, foci_clients: FociClients) bool {
    if (getString(rt, "family_id")) |fid| {
        if (std.mem.eql(u8, fid, "1")) return true;
    }
    const cid = getString(rt, "client_id") orelse return false;
    return foci_clients.contains(cid);
}

fn isUsableEnvironment(environment: ?[]const u8) bool {
    const env = environment orelse return false;
    return std.mem.eql(u8, env, "login.microsoftonline.com") or
        std.mem.eql(u8, env, "login.windows.net");
}

fn entryFreshness(rt: std.json.Value) i64 {
    const a = parseUnix(getString(rt, "last_modification_time"));
    const b = parseUnix(getString(rt, "cached_at"));
    return @max(a, b);
}

fn parseUnix(value: ?[]const u8) i64 {
    const s = value orelse return 0;
    return std.fmt.parseInt(i64, s, 10) catch 0;
}

fn getString(value: std.json.Value, key: []const u8) ?[]const u8 {
    if (value != .object) return null;
    const field = value.object.get(key) orelse return null;
    return switch (field) {
        .string => |s| s,
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Windows DPAPI
// ---------------------------------------------------------------------------

const DATA_BLOB = extern struct {
    cbData: u32,
    pbData: ?[*]u8,
};

const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

extern "crypt32" fn CryptUnprotectData(
    pDataIn: *DATA_BLOB,
    ppszDataDescr: ?*?[*:0]u16,
    pOptionalEntropy: ?*DATA_BLOB,
    pvReserved: ?*anyopaque,
    pPromptStruct: ?*anyopaque,
    dwFlags: u32,
    pDataOut: *DATA_BLOB,
) callconv(.winapi) i32;

extern "kernel32" fn LocalFree(hMem: ?*anyopaque) callconv(.winapi) ?*anyopaque;

fn dpapiUnprotect(gpa: Allocator, raw: []const u8) ?[]u8 {
    var in: DATA_BLOB = .{ .cbData = @intCast(raw.len), .pbData = @constCast(raw.ptr) };
    var out: DATA_BLOB = .{ .cbData = 0, .pbData = null };
    if (CryptUnprotectData(&in, null, null, null, null, CRYPTPROTECT_UI_FORBIDDEN, &out) == 0) return null;
    defer _ = LocalFree(out.pbData);
    const ptr = out.pbData orelse return null;
    const len: usize = @intCast(out.cbData);
    return gpa.dupe(u8, ptr[0..len]) catch null;
}

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

fn getEnv(gpa: Allocator, name: []const u8) ?[]u8 {
    if (builtin.os.tag == .wasi) return null;
    if (builtin.os.tag == .windows) {
        var map = std.process.Environ.createMap(.{ .block = .global }, gpa) catch return null;
        defer map.deinit();
        if (map.get(name)) |value| return gpa.dupe(u8, value) catch null;
        return null;
    }
    var i: usize = 0;
    while (std.c.environ[i]) |entry| : (i += 1) {
        const item = std.mem.span(entry);
        if (item.len > name.len and item[name.len] == '=' and std.mem.eql(u8, item[0..name.len], name)) {
            return gpa.dupe(u8, item[name.len + 1 ..]) catch null;
        }
    }
    return null;
}

fn getHome(gpa: Allocator) ?[]u8 {
    if (builtin.os.tag == .windows) {
        if (getEnv(gpa, "USERPROFILE")) |value| return value;
    }
    return getEnv(gpa, "HOME");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "selects freshest FOCI refresh token and ignores PRTs and stale entries" {
    const json =
        \\{
        \\  "AppMetadata": {
        \\    "appmetadata-login.microsoftonline.com-04b07795-8ddb-461a-bbee-02f9e1bf7b46": {
        \\      "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
        \\      "family_id": "1"
        \\    }
        \\  },
        \\  "RefreshToken": {
        \\    "k1": {
        \\      "credential_type": "RefreshToken",
        \\      "secret": "1.stale-frt",
        \\      "environment": "login.microsoftonline.com",
        \\      "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
        \\      "family_id": "1",
        \\      "home_account_id": "uid.tid",
        \\      "last_modification_time": "1000"
        \\    },
        \\    "k2": {
        \\      "credential_type": "RefreshToken",
        \\      "secret": "1.fresh-frt",
        \\      "environment": "login.microsoftonline.com",
        \\      "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
        \\      "family_id": "1",
        \\      "home_account_id": "uid.tid",
        \\      "last_modification_time": "5000"
        \\    },
        \\    "k3": {
        \\      "credential_type": "RefreshToken",
        \\      "secret": "0.device-bound-prt",
        \\      "environment": "login.microsoftonline.com",
        \\      "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
        \\      "family_id": "1",
        \\      "home_account_id": "uid.tid"
        \\    },
        \\    "k4": {
        \\      "credential_type": "RefreshToken",
        \\      "secret": "1.non-foci",
        \\      "environment": "login.microsoftonline.com",
        \\      "client_id": "deadbeef-0000-0000-0000-000000000000",
        \\      "home_account_id": "uid.tid"
        \\    }
        \\  }
        \\}
    ;
    const gpa = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, json, .{});
    defer parsed.deinit();

    var counts: Counts = .{};
    var best_secret: ?[]const u8 = null;
    var best_home: []const u8 = "";
    var best_freshness: i64 = -1;
    countAndSelect(parsed.value, &counts, &best_secret, &best_home, &best_freshness);

    try std.testing.expectEqual(@as(usize, 2), counts.foci_rt);
    try std.testing.expectEqual(@as(usize, 1), counts.prt);
    try std.testing.expect(best_secret != null);
    try std.testing.expectEqualStrings("1.fresh-frt", best_secret.?);
    try std.testing.expectEqualStrings("uid.tid", best_home);
}

test "non-foci client without family AppMetadata is rejected" {
    const json =
        \\{
        \\  "RefreshToken": {
        \\    "k1": {
        \\      "secret": "1.token",
        \\      "environment": "login.microsoftonline.com",
        \\      "client_id": "deadbeef-0000-0000-0000-000000000000",
        \\      "home_account_id": "uid.tid"
        \\    }
        \\  }
        \\}
    ;
    const gpa = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, json, .{});
    defer parsed.deinit();

    var counts: Counts = .{};
    var best_secret: ?[]const u8 = null;
    var best_home: []const u8 = "";
    var best_freshness: i64 = -1;
    countAndSelect(parsed.value, &counts, &best_secret, &best_home, &best_freshness);

    try std.testing.expectEqual(@as(usize, 0), counts.foci_rt);
    try std.testing.expect(best_secret == null);
}

test "rejects unusable environments" {
    try std.testing.expect(!isUsableEnvironment(null));
    try std.testing.expect(!isUsableEnvironment("login.example.com"));
    try std.testing.expect(isUsableEnvironment("login.microsoftonline.com"));
    try std.testing.expect(isUsableEnvironment("login.windows.net"));
}

test "looksLikeJson skips leading whitespace" {
    try std.testing.expect(looksLikeJson("   \n\t{\"a\":1}"));
    try std.testing.expect(!looksLikeJson("not json"));
    try std.testing.expect(!looksLikeJson(""));
}
