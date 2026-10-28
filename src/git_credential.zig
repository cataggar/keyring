//! Git credential helper (`keyring git credential <get|store|erase>`,
//! `git-credential-keyring` argv[0] dispatch, and `keyring git config`).
//!
//! Routes HTTPS Git credential requests across:
//! 1. GitHub (`github.com`, `gist.github.com`, `<tenant>.ghe.com` data-residency
//!    hosts, and GitHub Enterprise Server hosts in `hosts.yml`) via `src/gh.zig`.
//! 2. Azure DevOps (`dev.azure.com`, `*.visualstudio.com`) via `src/ado.zig`.
//! 3. Generic HTTPS hosts stored in the active `keyring` backend under
//!    `service = "https://<host>"`.
const std = @import("std");
const builtin = @import("builtin");
const keyring_zig = @import("keyring_zig");
const gh = @import("gh.zig");
const ado = @import("ado.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Operation = enum {
    get,
    store,
    erase,

    pub fn fromString(s: []const u8) ?Operation {
        if (std.mem.eql(u8, s, "get")) return .get;
        if (std.mem.eql(u8, s, "store")) return .store;
        if (std.mem.eql(u8, s, "erase")) return .erase;
        return null;
    }
};

pub const ConfigOptions = struct {
    hostname: ?[]const u8 = null,
    global: bool = true,
};

pub const CredentialRequest = struct {
    protocol: ?[]const u8 = null,
    host: ?[]const u8 = null,
    path: ?[]const u8 = null,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    authtype_capability: bool = false,
};

pub const GenericStore = struct {
    get: *const fn (gpa: Allocator, service: []const u8, account: []const u8) keyring_zig.Error![]u8,
    set: *const fn (gpa: Allocator, service: []const u8, account: []const u8, password: []const u8) keyring_zig.Error!void,
    delete: *const fn (gpa: Allocator, service: []const u8, account: []const u8) keyring_zig.Error!void,
};

const live_generic_store: GenericStore = .{
    .get = keyring_zig.getAlloc,
    .set = keyring_zig.setAlloc,
    .delete = keyring_zig.deleteAlloc,
};

var generic_store_override: ?GenericStore = null;
var git_config_global_override: ?[]const u8 = null;

fn activeGenericStore() GenericStore {
    return generic_store_override orelse live_generic_store;
}

/// Return true if `arg0` invokes the binary as `git-credential-keyring` (or
/// `git-credential-keyring.exe`), allowing `git config credential.helper keyring`.
pub fn isGitCredentialArgv0(arg0: []const u8) bool {
    var base = arg0;
    if (std.mem.lastIndexOfAny(u8, base, "/\\")) |sep| {
        base = base[sep + 1 ..];
    }
    if (base.len > 4 and std.ascii.endsWithIgnoreCase(base, ".exe")) {
        base = base[0 .. base.len - 4];
    }
    return std.ascii.eqlIgnoreCase(base, "git-credential-keyring");
}

/// Parse `keyring git config [--hostname <host>] [--global|--local]`.
pub fn parseConfigArgs(args: []const []const u8) ?ConfigOptions {
    var opts: ConfigOptions = .{};
    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--hostname") or std.mem.eql(u8, arg, "-h")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return null;
            opts.hostname = args[i + 1];
            i += 2;
        } else if (std.mem.eql(u8, arg, "--global")) {
            opts.global = true;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--local")) {
            opts.global = false;
            i += 1;
        } else {
            return null;
        }
    }
    return opts;
}

/// Parse Git credential helper protocol lines from `input` up to the first
/// blank line. All returned slices either point into `input` or are allocated
/// from `gpa` (caller should pass an arena allocator).
pub fn parseCredentialInput(gpa: Allocator, input: []const u8) !CredentialRequest {
    var req: CredentialRequest = .{};

    var lines = std.mem.splitScalar(u8, input, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0) break;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = line[0..eq];
        const value = line[eq + 1 ..];

        if (std.mem.eql(u8, key, "url")) {
            try parseUrlIntoRequest(gpa, value, &req);
        } else if (std.mem.eql(u8, key, "protocol")) {
            req.protocol = value;
        } else if (std.mem.eql(u8, key, "host")) {
            req.host = value;
        } else if (std.mem.eql(u8, key, "path")) {
            req.path = std.mem.trimStart(u8, value, "/");
        } else if (std.mem.eql(u8, key, "username")) {
            req.username = value;
        } else if (std.mem.eql(u8, key, "password")) {
            req.password = value;
        } else if (std.mem.eql(u8, key, "capability[]")) {
            if (std.mem.eql(u8, value, "authtype")) {
                req.authtype_capability = true;
            }
        }
    }

    return req;
}

fn parseUrlIntoRequest(gpa: Allocator, raw_url: []const u8, req: *CredentialRequest) !void {
    const scheme_sep = std.mem.indexOf(u8, raw_url, "://") orelse return;
    req.protocol = raw_url[0..scheme_sep];
    const after_scheme = raw_url[scheme_sep + 3 ..];

    var authority_end: usize = after_scheme.len;
    for (after_scheme, 0..) |c, idx| {
        if (c == '/' or c == '?' or c == '#') {
            authority_end = idx;
            break;
        }
    }

    const authority = after_scheme[0..authority_end];
    if (authority_end < after_scheme.len and after_scheme[authority_end] == '/') {
        const raw_path = std.mem.trimStart(u8, after_scheme[authority_end + 1 ..], "/");
        if (raw_path.len > 0) req.path = raw_path;
    }

    if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at_idx| {
        const userinfo = authority[0..at_idx];
        req.host = authority[at_idx + 1 ..];
        if (std.mem.indexOfScalar(u8, userinfo, ':')) |colon_idx| {
            req.username = try percentDecodeSlice(gpa, userinfo[0..colon_idx]);
            req.password = try percentDecodeSlice(gpa, userinfo[colon_idx + 1 ..]);
        } else {
            req.username = try percentDecodeSlice(gpa, userinfo);
        }
    } else {
        req.host = authority;
    }
}

fn percentDecodeSlice(gpa: Allocator, input: []const u8) ![]u8 {
    var out = try std.ArrayList(u8).initCapacity(gpa, input.len);
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        if (input[i] == '%' and i + 2 < input.len) {
            const hi = std.fmt.charToDigit(input[i + 1], 16) catch {
                try out.append(gpa, input[i]);
                continue;
            };
            const lo = std.fmt.charToDigit(input[i + 2], 16) catch {
                try out.append(gpa, input[i]);
                continue;
            };
            try out.append(gpa, @intCast((hi << 4) | lo));
            i += 2;
        } else {
            try out.append(gpa, input[i]);
        }
    }
    return out.toOwnedSlice(gpa);
}

/// Execute `keyring git-credential <get|store|erase>`.
pub fn runCredential(
    gpa: Allocator,
    op: Operation,
    stdin: *Io.Reader,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const input = try readCredentialStdin(a, stdin);
    const req = try parseCredentialInput(a, input);

    const protocol = req.protocol orelse return 0;
    if (!std.ascii.eqlIgnoreCase(protocol, "https")) {
        return 0;
    }

    const host = req.host orelse return 0;
    if (host.len == 0) return 0;

    // 1. GitHub (`github.com`, `gist.github.com`, `*.ghe.com`, or GHES in `hosts.yml`).
    if (gh.isGitHubHost(a, host)) {
        switch (op) {
            .get => {
                const cred = (gh.getOrLoginGitCredential(a, host, req.username, true, stderr) catch {
                    return 0;
                }) orelse return 0;
                try writeCredentialOutput(stdout, host, cred.username, cred.token);
                return 0;
            },
            .store => {
                gh.storeGitCredential(a, host, req.username, req.password) catch {};
                return 0;
            },
            .erase => {
                _ = gh.eraseStoredCredential(a, host, req.username) catch {};
                return 0;
            },
        }
    }

    // 2. Azure DevOps (`dev.azure.com`, `*.visualstudio.com`, `*.codedev.ms`, `*.vsts.me`).
    const full_url = if (req.path) |p|
        if (p.len > 0)
            try std.fmt.allocPrint(a, "https://{s}/{s}", .{ host, p })
        else
            try std.fmt.allocPrint(a, "https://{s}", .{host})
    else
        try std.fmt.allocPrint(a, "https://{s}", .{host});

    if (ado.isDevOpsUrl(full_url)) {
        switch (op) {
            .get => {
                const cred = ado.getGitCredential(a, stderr, full_url) catch return 0;
                const out_user = if (req.username) |u| (if (u.len > 0) u else cred.username) else cred.username;
                try writeCredentialOutput(stdout, host, out_user, cred.password);
                return 0;
            },
            .store => return 0,
            .erase => {
                ado.eraseGitCredential(a, full_url) catch {};
                return 0;
            },
        }
    }

    // 3. Generic HTTPS credential stored in the active `keyring` backend.
    const base_service = try std.fmt.allocPrint(a, "https://{s}", .{host});
    const store = activeGenericStore();
    switch (op) {
        .get => {
            const user = req.username orelse return 0;
            if (user.len == 0) return 0;
            const pass = store.get(a, base_service, user) catch return 0;
            try writeCredentialOutput(stdout, host, user, pass);
            return 0;
        },
        .store => {
            const user = req.username orelse return 0;
            const pass = req.password orelse return 0;
            if (user.len == 0 or pass.len == 0) return 0;
            store.set(a, base_service, user, pass) catch {};
            return 0;
        },
        .erase => {
            const user = req.username orelse return 0;
            if (user.len == 0) return 0;
            store.delete(a, base_service, user) catch {};
            return 0;
        },
    }
}

fn readCredentialStdin(gpa: Allocator, stdin: *Io.Reader) ![]u8 {
    var writer = Io.Writer.Allocating.init(gpa);
    errdefer writer.deinit();
    _ = stdin.streamRemaining(&writer.writer) catch {};
    return writer.toOwnedSlice();
}

fn writeCredentialOutput(
    stdout: *Io.Writer,
    host: []const u8,
    username: []const u8,
    password: []const u8,
) !void {
    if (hasNewlineOrNul(host) or hasNewlineOrNul(username) or hasNewlineOrNul(password)) {
        return;
    }
    try stdout.print(
        "protocol=https\nhost={s}\nusername={s}\npassword={s}\n\n",
        .{ host, username, password },
    );
    try stdout.flush();
}

fn hasNewlineOrNul(s: []const u8) bool {
    return std.mem.indexOfAny(u8, s, "\r\n\x00") != null;
}

/// Build the `credential.helper` value pointing to `exe_path`.
pub fn formatGitHelperValue(gpa: Allocator, exe_path: []const u8) ![]u8 {
    var out = Io.Writer.Allocating.init(gpa);
    errdefer out.deinit();
    try out.writer.writeByte('!');
    if (std.mem.indexOfAny(u8, exe_path, " \t\"'\\") != null) {
        try out.writer.writeByte('"');
        for (exe_path) |c| {
            if (c == '\\') {
                try out.writer.writeAll("/");
            } else if (c == '"') {
                try out.writer.writeAll("\\\"");
            } else {
                try out.writer.writeByte(c);
            }
        }
        try out.writer.writeByte('"');
    } else {
        try out.writer.writeAll(exe_path);
    }
    try out.writer.writeAll(" git credential");
    return out.toOwnedSlice();
}

/// Run `keyring git config [--hostname <host>] [--global|--local]`.
pub fn runConfig(
    gpa: Allocator,
    opts: ConfigOptions,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var threaded = Io.Threaded.init(gpa, .{ .environ = ado.currentProcessEnviron() });
    defer threaded.deinit();
    const io = threaded.io();

    const exe_path: []const u8 = std.process.executablePathAlloc(io, a) catch "keyring";
    const helper_val = try formatGitHelperValue(a, exe_path);
    const scope_flag = if (opts.global) "--global" else "--local";

    if (opts.hostname) |raw_host| {
        const canonical = gh.normalizeHostnameAlloc(a, raw_host) catch {
            try stderr.print("keyring: git config: invalid hostname '{s}'\n", .{raw_host});
            try stderr.flush();
            return 2;
        };
        const key = try std.fmt.allocPrint(a, "credential.https://{s}.helper", .{canonical});

        // Clear any inherited helper first (empty string resets the helper chain for that host),
        // then add `!keyring git credential`, matching `gh auth setup-git`.
        runGitConfig(a, io, &.{ "git", "config", scope_flag, "--replace-all", key, "" }, stderr) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return 1,
        };
        runGitConfig(a, io, &.{ "git", "config", scope_flag, "--add", key, helper_val }, stderr) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return 1,
        };

        if (ado.isDevOpsUrl(canonical)) {
            const http_path_key = try std.fmt.allocPrint(a, "credential.https://{s}.useHttpPath", .{canonical});
            runGitConfig(a, io, &.{ "git", "config", scope_flag, http_path_key, "true" }, stderr) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return 1,
            };
        }

        try stdout.print("Configured Git credential helper for https://{s} ({s})\n", .{ canonical, scope_flag });
        try stdout.flush();
        return 0;
    }

    runGitConfig(a, io, &.{ "git", "config", scope_flag, "credential.helper", helper_val }, stderr) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return 1,
    };
    runGitConfig(a, io, &.{ "git", "config", scope_flag, "credential.https://dev.azure.com.useHttpPath", "true" }, stderr) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return 1,
    };

    try stdout.print("Configured Git credential helper ({s}): {s}\n", .{ scope_flag, helper_val });
    try stdout.flush();
    return 0;
}

fn runGitConfig(gpa: Allocator, io: Io, argv: []const []const u8, stderr: *Io.Writer) !void {
    var env_map_opt: ?std.process.Environ.Map = if (git_config_global_override) |cfg_path| blk: {
        var m = try std.process.Environ.createMap(ado.currentProcessEnviron(), gpa);
        errdefer m.deinit();
        try m.put("GIT_CONFIG_GLOBAL", cfg_path);
        break :blk m;
    } else null;
    defer if (env_map_opt) |*m| m.deinit();

    const result = std.process.run(gpa, io, .{
        .argv = argv,
        .environ_map = if (env_map_opt) |*m| m else null,
        .stdout_limit = .limited(16 * 1024),
        .stderr_limit = .limited(16 * 1024),
    }) catch |err| {
        try stderr.print("keyring: git config: failed to run git: {s}\n", .{@errorName(err)});
        try stderr.flush();
        return err;
    };
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code != 0) {
            if (result.stderr.len > 0) {
                try stderr.writeAll(result.stderr);
                try stderr.flush();
            }
            return error.GitConfigFailed;
        },
        else => return error.GitConfigFailed,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "isGitCredentialArgv0 recognizes git-credential-keyring on Unix and Windows" {
    try std.testing.expect(isGitCredentialArgv0("git-credential-keyring"));
    try std.testing.expect(isGitCredentialArgv0("/usr/local/bin/git-credential-keyring"));
    try std.testing.expect(isGitCredentialArgv0("C:\\Users\\alice\\bin\\git-credential-keyring.exe"));
    try std.testing.expect(!isGitCredentialArgv0("keyring"));
    try std.testing.expect(!isGitCredentialArgv0("/usr/local/bin/keyring"));
}

test "parseCredentialInput parses key-value pairs, url=, and capability[]=authtype" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const input1 =
        \\capability[]=authtype
        \\protocol=https
        \\host=example.ghe.com
        \\path=owner/repo.git
        \\username=alice
        \\
        \\ignored=after_blank
    ;
    const req1 = try parseCredentialInput(a, input1);
    try std.testing.expect(req1.authtype_capability);
    try std.testing.expectEqualStrings("https", req1.protocol.?);
    try std.testing.expectEqualStrings("example.ghe.com", req1.host.?);
    try std.testing.expectEqualStrings("owner/repo.git", req1.path.?);
    try std.testing.expectEqualStrings("alice", req1.username.?);

    const input2 =
        \\url=https://bob%40corp:sec%21ret@example.ghe.com/org/project.git
        \\
    ;
    const req2 = try parseCredentialInput(a, input2);
    try std.testing.expectEqualStrings("https", req2.protocol.?);
    try std.testing.expectEqualStrings("example.ghe.com", req2.host.?);
    try std.testing.expectEqualStrings("org/project.git", req2.path.?);
    try std.testing.expectEqualStrings("bob@corp", req2.username.?);
    try std.testing.expectEqualStrings("sec!ret", req2.password.?);
}

test "runCredential serves, stores, and erases GitHub credentials for github.com and *.ghe.com" {
    const gpa = std.testing.allocator;
    gh.FakeStore.reset(gpa);
    defer gh.FakeStore.reset(gpa);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = Io.Threaded.global_single_threaded.io();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const root = root_buf[0..root_len];

    const config_dir = try std.fs.path.join(gpa, &.{ root, "gh-config" });
    defer gpa.free(config_dir);

    const hosts_yaml =
        \\github.com:
        \\    git_protocol: https
        \\    users:
        \\        alice:
        \\        bob:
        \\    user: alice
        \\example.ghe.com:
        \\    git_protocol: https
        \\    users:
        \\        alice_ent:
        \\    user: alice_ent
        \\
    ;
    try Io.Dir.cwd().createDirPath(io, config_dir);
    const hosts_path = try std.fs.path.join(gpa, &.{ config_dir, gh.hosts_filename });
    defer gpa.free(hosts_path);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = hosts_path, .data = hosts_yaml });

    try gh.FakeStore.set(gpa, "gh:github.com", "alice", "gho_alice123");
    try gh.FakeStore.set(gpa, "gh:github.com", "bob", "gho_bob456");
    try gh.FakeStore.set(gpa, "gh:example.ghe.com", "alice_ent", "gho_ent789");

    gh.setTestOverrides(gh.FakeStore.store, config_dir);
    defer gh.setTestOverrides(null, null);

    // 1. Get credential for example.ghe.com
    {
        var stdin = Io.Reader.fixed("protocol=https\nhost=example.ghe.com\npath=org/repo.git\n\n");
        var stdout = Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();

        const code = try runCredential(gpa, .get, &stdin, &stdout.writer, &stderr.writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        try std.testing.expectEqualStrings(
            "protocol=https\nhost=example.ghe.com\nusername=alice_ent\npassword=gho_ent789\n\n",
            stdout.written(),
        );
    }

    // 2. Get credential for specific user bob on github.com, then `store` (as `git credential approve`
    //    does after a fetch) without changing the active user away from alice.
    {
        var stdin = Io.Reader.fixed("protocol=https\nhost=github.com\nusername=bob\n\n");
        var stdout = Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();

        const code = try runCredential(gpa, .get, &stdin, &stdout.writer, &stderr.writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        try std.testing.expectEqualStrings(
            "protocol=https\nhost=github.com\nusername=bob\npassword=gho_bob456\n\n",
            stdout.written(),
        );
    }
    {
        var store_stdin = Io.Reader.fixed(
            "protocol=https\nhost=github.com\nusername=bob\npassword=gho_bob456\n\n",
        );
        var stdout = Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();

        const code = try runCredential(gpa, .store, &store_stdin, &stdout.writer, &stderr.writer);
        try std.testing.expectEqual(@as(u8, 0), code);

        const active_cred = (try gh.lookupStoredCredential(gpa, "github.com", null)).?;
        defer active_cred.deinit(gpa);
        try std.testing.expectEqualStrings("alice", active_cred.username);
        try std.testing.expectEqualStrings("gho_alice123", active_cred.token);
    }

    // 3. Erase bob on github.com
    {
        var stdin = Io.Reader.fixed("protocol=https\nhost=github.com\nusername=bob\n\n");
        var stdout = Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();

        const code = try runCredential(gpa, .erase, &stdin, &stdout.writer, &stderr.writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        try std.testing.expect((try gh.lookupStoredCredential(gpa, "github.com", "bob")) == null);
    }

    // 4. Simulate `gh auth login` credential helper update (`git credential reject` followed by
    //    `git credential approve`) on example.ghe.com: erase without username, then store new token.
    {
        var erase_stdin = Io.Reader.fixed("protocol=https\nhost=example.ghe.com\n\n");
        var stdout = Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();

        const code = try runCredential(gpa, .erase, &erase_stdin, &stdout.writer, &stderr.writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        try std.testing.expect((try gh.lookupStoredCredential(gpa, "example.ghe.com", null)) == null);
    }
    {
        var store_stdin = Io.Reader.fixed(
            "protocol=https\nhost=example.ghe.com\nusername=alice_ent\npassword=gho_ent_refreshed\n\n",
        );
        var stdout = Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();

        const code = try runCredential(gpa, .store, &store_stdin, &stdout.writer, &stderr.writer);
        try std.testing.expectEqual(@as(u8, 0), code);
    }
    {
        var get_stdin = Io.Reader.fixed("protocol=https\nhost=example.ghe.com\n\n");
        var stdout = Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();

        const code = try runCredential(gpa, .get, &get_stdin, &stdout.writer, &stderr.writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        try std.testing.expectEqualStrings(
            "protocol=https\nhost=example.ghe.com\nusername=alice_ent\npassword=gho_ent_refreshed\n\n",
            stdout.written(),
        );
    }

    // 5. `store` ignores synthetic `x-access-token` usernames (e.g. from GH_TOKEN) so environment
    //    tokens do not overwrite keyring credentials or `hosts.yml`.
    {
        var store_stdin = Io.Reader.fixed(
            "protocol=https\nhost=example.ghe.com\nusername=x-access-token\npassword=gho_env_ephemeral\n\n",
        );
        var stdout = Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();

        const code = try runCredential(gpa, .store, &store_stdin, &stdout.writer, &stderr.writer);
        try std.testing.expectEqual(@as(u8, 0), code);

        const cred = (try gh.lookupStoredCredential(gpa, "example.ghe.com", null)).?;
        defer cred.deinit(gpa);
        try std.testing.expectEqualStrings("alice_ent", cred.username);
        try std.testing.expectEqualStrings("gho_ent_refreshed", cred.token);
    }
}

test "runCredential handles generic HTTPS store/get/erase and ignores non-https" {
    const gpa = std.testing.allocator;
    gh.FakeStore.reset(gpa);
    defer gh.FakeStore.reset(gpa);

    const GenericMock = struct {
        fn get(alloc: Allocator, service: []const u8, account: []const u8) keyring_zig.Error![]u8 {
            return gh.FakeStore.get(alloc, service, account) catch return error.EntryNotFound;
        }
        fn set(alloc: Allocator, service: []const u8, account: []const u8, password: []const u8) keyring_zig.Error!void {
            gh.FakeStore.set(alloc, service, account, password) catch return error.PlatformFailure;
        }
        fn delete(alloc: Allocator, service: []const u8, account: []const u8) keyring_zig.Error!void {
            gh.FakeStore.delete(alloc, service, account) catch return error.EntryNotFound;
        }
    };

    generic_store_override = .{
        .get = GenericMock.get,
        .set = GenericMock.set,
        .delete = GenericMock.delete,
    };
    defer generic_store_override = null;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const empty_config_dir = try std.fs.path.join(gpa, &.{ root_buf[0..root_len], "empty-gh" });
    defer gpa.free(empty_config_dir);
    gh.setTestOverrides(gh.FakeStore.store, empty_config_dir);
    defer gh.setTestOverrides(null, null);

    // 1. Non-https protocol is ignored silently.
    {
        var stdin = Io.Reader.fixed("protocol=ssh\nhost=github.com\n\n");
        var stdout = Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try std.testing.expectEqual(@as(u8, 0), try runCredential(gpa, .get, &stdin, &stdout.writer, &stderr.writer));
        try std.testing.expectEqualStrings("", stdout.written());
    }

    // 2. Generic HTTPS store -> get -> erase.
    {
        var store_stdin = Io.Reader.fixed("protocol=https\nhost=git.example.org\nusername=deploy\npassword=s3cr3t\n\n");
        var stdout = Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try std.testing.expectEqual(@as(u8, 0), try runCredential(gpa, .store, &store_stdin, &stdout.writer, &stderr.writer));
    }
    {
        var get_stdin = Io.Reader.fixed("protocol=https\nhost=git.example.org\nusername=deploy\n\n");
        var stdout = Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try std.testing.expectEqual(@as(u8, 0), try runCredential(gpa, .get, &get_stdin, &stdout.writer, &stderr.writer));
        try std.testing.expectEqualStrings(
            "protocol=https\nhost=git.example.org\nusername=deploy\npassword=s3cr3t\n\n",
            stdout.written(),
        );
    }
    {
        var erase_stdin = Io.Reader.fixed("protocol=https\nhost=git.example.org\nusername=deploy\n\n");
        var stdout = Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try std.testing.expectEqual(@as(u8, 0), try runCredential(gpa, .erase, &erase_stdin, &stdout.writer, &stderr.writer));
    }
    {
        var get_after_stdin = Io.Reader.fixed("protocol=https\nhost=git.example.org\nusername=deploy\n\n");
        var stdout = Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try std.testing.expectEqual(@as(u8, 0), try runCredential(gpa, .get, &get_after_stdin, &stdout.writer, &stderr.writer));
        try std.testing.expectEqualStrings("", stdout.written());
    }
}

test "formatGitHelperValue quotes paths with spaces or backslashes" {
    const gpa = std.testing.allocator;
    const simple = try formatGitHelperValue(gpa, "keyring");
    defer gpa.free(simple);
    try std.testing.expectEqualStrings("!keyring git credential", simple);

    const win = try formatGitHelperValue(gpa, "C:\\Program Files\\keyring\\keyring.exe");
    defer gpa.free(win);
    try std.testing.expectEqualStrings("!\"C:/Program Files/keyring/keyring.exe\" git credential", win);
}

test "runConfig preserves process environment ($HOME) and writes host-scoped and global git config" {
    const gpa = std.testing.allocator;

    // 1. Verify un-overridden `Io.Threaded.init(gpa, .{ .environ = ado.currentProcessEnviron() })`
    //    passes $HOME/$PATH to `git config --global` (regression test for `fatal: $HOME not set`).
    {
        var threaded = Io.Threaded.init(gpa, .{ .environ = ado.currentProcessEnviron() });
        defer threaded.deinit();
        const io = threaded.io();

        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try runGitConfig(gpa, io, &.{ "git", "config", "--global", "--default", "", "--get", "user.name" }, &stderr.writer);
    }

    // 2. Verify `runConfig` writes host-scoped and global credential helper entries to a temp gitconfig.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const cfg_path = try std.fs.path.join(gpa, &.{ root_buf[0..root_len], "gitconfig" });
    defer gpa.free(cfg_path);

    git_config_global_override = cfg_path;
    defer git_config_global_override = null;

    {
        var stdout = Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();

        const code = try runConfig(gpa, .{ .hostname = "example.ghe.com", .global = true }, &stdout.writer, &stderr.writer);
        try std.testing.expectEqual(@as(u8, 0), code);
        try std.testing.expectEqualStrings(
            "Configured Git credential helper for https://example.ghe.com (--global)\n",
            stdout.written(),
        );
    }

    {
        var stdout = Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();

        const code = try runConfig(gpa, .{ .hostname = "dev.azure.com", .global = true }, &stdout.writer, &stderr.writer);
        try std.testing.expectEqual(@as(u8, 0), code);
    }

    const content = try Io.Dir.cwd().readFileAlloc(io, cfg_path, gpa, .limited(64 * 1024));
    defer gpa.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "[credential \"https://example.ghe.com\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "git credential") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "useHttpPath = true") != null);
}

