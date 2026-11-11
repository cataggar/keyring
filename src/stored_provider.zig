//! Native stored-credential provider and `keyring_zig` persistence adapter (`#40`).
//!
//! Separates credential-provider lifecycle semantics (`StoredCredentialProvider`)
//! from underlying secret-store I/O (`PersistenceBackend` / `KeyringOpsAdapter`):
//! - Reuses `keyring_zig` native OS secret stores (`win_credential`, `keychain`,
//!   `secret_service`) and explicitly configured encrypted `.file` stores.
//! - Fails closed (`error.StorageUnavailable`) when `--disable` / `null_backend`,
//!   `-b ado` / `KEYRING_BACKEND=ado`, or an unconfigured `.file` store is active;
//!   never writes plaintext/base64 fallback files or touches `ado-keyring`,
//!   `refresh.dat`, `session.dat`, or `gh:` entries.
//! - Isolates stored credentials under `credential-provider://<scheme>/<authority>`
//!   (or `container-registry://<authority>` for single-slot registry helpers) and
//!   prefixes named account slots with `"account:"` so an account literally named
//!   `"default"` never collides with the unnamed `"default"` slot.
//! - Persists versioned v1 JSON envelopes while remaining backward-compatible with
//!   legacy v0 `{"username":"...","secret":"..."}` records (`"<token>"` ->
//!   `.identity_token`, otherwise `.basic`) without inventing expiry or scopes.
const std = @import("std");
const builtin = @import("builtin");
const dbus = @import("dbus");
const keyring_zig = @import("keyring_zig");
const cp = @import("credential_provider.zig");

const Allocator = std.mem.Allocator;

pub const default_namespace_prefix = "credential-provider://";
pub const container_registry_namespace_prefix = "container-registry://";
pub const legacy_identity_token_username = "<token>";
const named_account_slot_prefix = "account:";
const secret_service_destination = "org.freedesktop.secrets";
const secret_service_object_path = "/org/freedesktop/secrets";
const secret_service_interface = "org.freedesktop.Secret.Service";
const secret_service_default_alias_path = "/org/freedesktop/secrets/aliases/default";

// ---------------------------------------------------------------------------
// 1. Persistence Abstraction
// ---------------------------------------------------------------------------

pub const PersistenceOptions = struct {
    interaction: cp.InteractionPolicy = .never,
    deadline: cp.Deadline = .{},
};

pub const PersistenceBackend = struct {
    ctx: ?*anyopaque = null,
    checkAvailableFn: *const fn (ctx: ?*anyopaque, gpa: Allocator, options: PersistenceOptions) cp.ProviderError!void,
    getFn: *const fn (
        ctx: ?*anyopaque,
        gpa: Allocator,
        service: []const u8,
        account: []const u8,
        options: PersistenceOptions,
    ) cp.ProviderError![]u8,
    setFn: *const fn (
        ctx: ?*anyopaque,
        gpa: Allocator,
        service: []const u8,
        account: []const u8,
        value: []const u8,
        options: PersistenceOptions,
    ) cp.ProviderError!void,
    deleteFn: *const fn (
        ctx: ?*anyopaque,
        gpa: Allocator,
        service: []const u8,
        account: []const u8,
        options: PersistenceOptions,
    ) cp.ProviderError!void,
};

// ---------------------------------------------------------------------------
// 2. KeyringPersistence & KeyringOpsAdapter (Backed by keyring_zig)
// ---------------------------------------------------------------------------

/// Optional hook allowing `main.zig` to report when an app-only non-general
/// backend (such as `-b ado` or `KEYRING_BACKEND=ado`) was selected.
pub var is_app_backend_disallowed_fn: ?*const fn () bool = null;

/// Optional environment-variable lookup hook for deterministic unit tests.
pub var env_override_fn: ?*const fn (name: []const u8) ?[]const u8 = null;

pub fn mapKeyringError(err: keyring_zig.Error) cp.ProviderError {
    const ExtendedError = keyring_zig.Error || error{Unsupported};
    return switch (@as(ExtendedError, err)) {
        error.EntryNotFound => error.CredentialNotFound,
        error.Locked => error.StorageLocked,
        error.NoStorageAccess => error.StorageUnavailable,
        error.InputTooLong, error.InvalidUtf8 => error.InvalidInput,
        error.Unsupported => error.UnsupportedOperation,
        error.OutOfMemory => error.OutOfMemory,
        error.PlatformFailure, error.Ambiguous, error.BufferTooSmall => error.StorageFailure,
    };
}

/// Verify that `keyring_zig` is configured to use a genuine encrypted/OS secret
/// store rather than `null_backend`, an app-forced `ado` backend, or an
/// unconfigured `.file` backend.
pub fn checkSecureBackendAvailable(gpa: Allocator) cp.ProviderError!void {
    if (is_app_backend_disallowed_fn) |disallowed_fn| {
        if (disallowed_fn()) return error.StorageUnavailable;
    }
    if (try getEnvOwned(gpa, "KEYRING_BACKEND")) |backend_env| {
        defer gpa.free(backend_env);
        const trimmed = std.mem.trim(u8, backend_env, " \t\r\n");
        if (std.ascii.eqlIgnoreCase(trimmed, "ado") or
            std.ascii.eqlIgnoreCase(trimmed, "azure_devops"))
        {
            return error.StorageUnavailable;
        }
    }

    const current = keyring_zig.currentBackend();
    if (@hasField(keyring_zig.Backend, "file") and current == .file) {
        if (!(try hasConfiguredFileBackendPath(gpa))) {
            return error.StorageUnavailable;
        }
        const passphrase = (try getEnvOwned(gpa, "KEYRING_FILE_PASSPHRASE")) orelse
            return error.StorageUnavailable;
        defer {
            std.crypto.secureZero(u8, passphrase);
            gpa.free(passphrase);
        }
        if (passphrase.len == 0) {
            return error.StorageUnavailable;
        }
        return;
    }

    switch (current) {
        .null_backend => return error.StorageUnavailable,
        .secret_service => try ensureDefaultSecretServiceCollectionSelected(gpa),
        .keychain, .win_credential => {},
        else => {},
    }
}

fn ensureDefaultSecretServiceCollectionSelected(gpa: Allocator) cp.ProviderError!void {
    if (try getEnvOwned(gpa, "KEYRING_PROPERTY_COLLECTION")) |raw_col| {
        defer gpa.free(raw_col);
        const col = std.mem.trim(u8, raw_col, " \t\r\n");
        if (col.len > 0 and !std.mem.eql(u8, col, "default")) {
            return error.StorageUnavailable;
        }
    }
}

pub const RawKeyringOps = struct {
    get: *const fn (gpa: Allocator, service: []const u8, account: []const u8) keyring_zig.Error![]u8,
    set: *const fn (gpa: Allocator, service: []const u8, account: []const u8, password: []const u8) keyring_zig.Error!void,
    delete: *const fn (gpa: Allocator, service: []const u8, account: []const u8) keyring_zig.Error!void,
};

pub const live_keyring_ops: RawKeyringOps = .{
    .get = keyring_zig.getAlloc,
    .set = keyring_zig.setAlloc,
    .delete = keyring_zig.deleteAlloc,
};

const win32_err = if (builtin.os.tag == .windows) struct {
    const ERROR_ACCESS_DENIED: u32 = 5;
    extern "kernel32" fn GetLastError() callconv(.winapi) u32;
    extern "kernel32" fn SetLastError(dwErrCode: u32) callconv(.winapi) void;
} else struct {};

const DbusPreflightReply = struct {
    body: []u8,
    err_name: ?[]u8 = null,

    fn deinit(self: *const DbusPreflightReply, gpa: Allocator) void {
        gpa.free(self.body);
        if (self.err_name) |e| gpa.free(e);
    }
};

const DbusPreflightCallReq = struct {
    destination: []const u8,
    path: []const u8,
    interface: []const u8,
    member: []const u8,
    signature: ?[]const u8,
    body: []const u8,
};

const DbusPreflightCallFn = *const fn (
    ctx: ?*anyopaque,
    gpa: Allocator,
    req: DbusPreflightCallReq,
) cp.ProviderError!DbusPreflightReply;

fn isTruthyDisableFlag(raw: []const u8) bool {
    const v = std.mem.trim(u8, raw, " \t\r\n");
    return std.ascii.eqlIgnoreCase(v, "1") or
        std.ascii.eqlIgnoreCase(v, "true") or
        std.ascii.eqlIgnoreCase(v, "yes");
}

fn isLinuxSecretPromptAvailable(gpa: Allocator) cp.ProviderError!bool {
    if (try getEnvOwned(gpa, "KEYRING_NONINTERACTIVE")) |v| {
        defer gpa.free(v);
        if (isTruthyDisableFlag(v)) return false;
    }
    if (try getEnvOwned(gpa, "ADO_KEYRING_NONINTERACTIVE")) |v| {
        defer gpa.free(v);
        if (isTruthyDisableFlag(v)) return false;
    }
    if (try getEnvOwned(gpa, "GIT_TERMINAL_PROMPT")) |v| {
        defer gpa.free(v);
        const t = std.mem.trim(u8, v, " \t\r\n");
        if (std.ascii.eqlIgnoreCase(t, "0") or std.ascii.eqlIgnoreCase(t, "false")) return false;
    }
    if (try getEnvOwned(gpa, "GCM_INTERACTIVE")) |v| {
        defer gpa.free(v);
        const t = std.mem.trim(u8, v, " \t\r\n");
        if (std.ascii.eqlIgnoreCase(t, "never") or
            std.ascii.eqlIgnoreCase(t, "false") or
            std.ascii.eqlIgnoreCase(t, "0"))
        {
            return false;
        }
    }

    if (try getEnvOwned(gpa, "DISPLAY")) |disp| {
        defer gpa.free(disp);
        if (std.mem.trim(u8, disp, " \t\r\n").len > 0) return true;
    }
    if (try getEnvOwned(gpa, "WAYLAND_DISPLAY")) |wdisp| {
        defer gpa.free(wdisp);
        if (std.mem.trim(u8, wdisp, " \t\r\n").len > 0) return true;
    }
    return false;
}

const CollectionLockCheckResult = enum {
    unlocked_or_absent,
    alias_missing,
};

fn queryCollectionLockedAtPath(
    gpa: Allocator,
    options: PersistenceOptions,
    collection_path: []const u8,
    ctx: ?*anyopaque,
    call_fn: DbusPreflightCallFn,
) cp.ProviderError!CollectionLockCheckResult {
    var prop_body: std.ArrayList(u8) = .empty;
    defer prop_body.deinit(gpa);
    var pw = dbus.wire.Writer.init(gpa, &prop_body);
    try pw.writeString("org.freedesktop.Secret.Collection");
    try pw.writeString("Locked");

    const prop_reply = try call_fn(ctx, gpa, .{
        .destination = secret_service_destination,
        .path = collection_path,
        .interface = "org.freedesktop.DBus.Properties",
        .member = "Get",
        .signature = "ss",
        .body = prop_body.items,
    });
    defer prop_reply.deinit(gpa);
    try options.deadline.checkBudget();

    if (prop_reply.err_name) |err_name| {
        if (std.mem.indexOf(u8, err_name, "AccessDenied") != null) return error.AccessDenied;
        if (std.mem.indexOf(u8, err_name, "NoSuchObject") != null or
            std.mem.indexOf(u8, err_name, "UnknownObject") != null)
        {
            return .alias_missing;
        }
        if (std.mem.indexOf(u8, err_name, "UnknownMethod") != null or
            std.mem.indexOf(u8, err_name, "UnknownInterface") != null)
        {
            return .unlocked_or_absent;
        }
        if (std.mem.indexOf(u8, err_name, "IsLocked") != null) return error.StorageLocked;
        if (std.mem.indexOf(u8, err_name, "ServiceUnknown") != null or
            std.mem.indexOf(u8, err_name, "NameHasNoOwner") != null or
            std.mem.indexOf(u8, err_name, "Spawn.") != null)
        {
            return error.StorageUnavailable;
        }
        return error.StorageFailure;
    }

    var pr = dbus.wire.Reader.init(prop_reply.body);
    const variant_sig = pr.readSignatureValue() catch return error.StorageFailure;
    if (!std.mem.eql(u8, variant_sig, "b")) return error.StorageFailure;
    const locked = pr.readBool() catch return error.StorageFailure;
    if (locked) return error.StorageLocked;
    return .unlocked_or_absent;
}

fn runSecretServicePreflightWithCaller(
    gpa: Allocator,
    options: PersistenceOptions,
    ctx: ?*anyopaque,
    call_fn: DbusPreflightCallFn,
) cp.ProviderError!void {
    try options.deadline.checkBudget();
    try ensureDefaultSecretServiceCollectionSelected(gpa);

    var name_body: std.ArrayList(u8) = .empty;
    defer name_body.deinit(gpa);
    var nw = dbus.wire.Writer.init(gpa, &name_body);
    try nw.writeString(secret_service_destination);

    const owner_reply = try call_fn(ctx, gpa, .{
        .destination = "org.freedesktop.DBus",
        .path = "/org/freedesktop/DBus",
        .interface = "org.freedesktop.DBus",
        .member = "NameHasOwner",
        .signature = "s",
        .body = name_body.items,
    });
    defer owner_reply.deinit(gpa);
    try options.deadline.checkBudget();

    if (owner_reply.err_name) |err_name| {
        if (std.mem.indexOf(u8, err_name, "AccessDenied") != null) return error.AccessDenied;
        return error.StorageUnavailable;
    }

    var owner_reader = dbus.wire.Reader.init(owner_reply.body);
    const has_owner = owner_reader.readBool() catch return error.StorageFailure;

    if (!has_owner) {
        const act_reply = try call_fn(ctx, gpa, .{
            .destination = "org.freedesktop.DBus",
            .path = "/org/freedesktop/DBus",
            .interface = "org.freedesktop.DBus",
            .member = "ListActivatableNames",
            .signature = null,
            .body = &.{},
        });
        defer act_reply.deinit(gpa);
        try options.deadline.checkBudget();

        if (act_reply.err_name) |err_name| {
            if (std.mem.indexOf(u8, err_name, "AccessDenied") != null) return error.AccessDenied;
            return error.StorageUnavailable;
        }

        var act_reader = dbus.wire.Reader.init(act_reply.body);
        const arr = act_reader.beginArray(4) catch return error.StorageFailure;
        var activatable = false;
        while (act_reader.arrayHasMore(arr)) {
            const bus_name = act_reader.readString() catch return error.StorageFailure;
            if (std.mem.eql(u8, bus_name, secret_service_destination)) {
                activatable = true;
                break;
            }
        }
        if (!activatable) return error.StorageUnavailable;
    }

    const interactive_available = try isLinuxSecretPromptAvailable(gpa);
    if (!options.interaction.allowsInteractive(interactive_available)) {
        const initial = try queryCollectionLockedAtPath(
            gpa,
            options,
            secret_service_default_alias_path,
            ctx,
            call_fn,
        );
        if (initial == .alias_missing) {
            var alias_body: std.ArrayList(u8) = .empty;
            defer alias_body.deinit(gpa);
            var aw = dbus.wire.Writer.init(gpa, &alias_body);
            try aw.writeString("default");

            const alias_reply = try call_fn(ctx, gpa, .{
                .destination = secret_service_destination,
                .path = secret_service_object_path,
                .interface = secret_service_interface,
                .member = "ReadAlias",
                .signature = "s",
                .body = alias_body.items,
            });
            defer alias_reply.deinit(gpa);
            try options.deadline.checkBudget();

            if (alias_reply.err_name) |err_name| {
                if (std.mem.indexOf(u8, err_name, "AccessDenied") != null) return error.AccessDenied;
                if (std.mem.indexOf(u8, err_name, "NoSuchObject") != null or
                    std.mem.indexOf(u8, err_name, "UnknownObject") != null or
                    std.mem.indexOf(u8, err_name, "UnknownMethod") != null or
                    std.mem.indexOf(u8, err_name, "UnknownInterface") != null)
                {
                    return;
                }
                if (std.mem.indexOf(u8, err_name, "IsLocked") != null) return error.StorageLocked;
                if (std.mem.indexOf(u8, err_name, "ServiceUnknown") != null or
                    std.mem.indexOf(u8, err_name, "NameHasNoOwner") != null or
                    std.mem.indexOf(u8, err_name, "Spawn.") != null)
                {
                    return error.StorageUnavailable;
                }
                return error.StorageFailure;
            }

            var ar = dbus.wire.Reader.init(alias_reply.body);
            const resolved_path = ar.readObjectPath() catch return error.StorageFailure;
            if (std.mem.eql(u8, resolved_path, "/")) return;

            _ = try queryCollectionLockedAtPath(gpa, options, resolved_path, ctx, call_fn);
        }
    }
}

const LinuxSecretServicePreflight = if (builtin.os.tag == .linux) struct {
    fn callBus(
        ctx: ?*anyopaque,
        gpa: Allocator,
        req: DbusPreflightCallReq,
    ) cp.ProviderError!DbusPreflightReply {
        const conn: *dbus.connection.Connection = @ptrCast(@alignCast(ctx.?));
        var reply = dbus.connection.call(conn, .{
            .destination = req.destination,
            .path = req.path,
            .interface = req.interface,
            .member = req.member,
            .signature = req.signature,
            .body = req.body,
        }) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.StorageUnavailable,
        };
        defer reply.deinit();

        const body_copy = try gpa.dupe(u8, reply.body);
        errdefer gpa.free(body_copy);
        const err_copy = if (reply.err) |e| try gpa.dupe(u8, e.name) else null;
        return .{
            .body = body_copy,
            .err_name = err_copy,
        };
    }

    fn run(gpa: Allocator, options: PersistenceOptions) cp.ProviderError!void {
        var conn = dbus.connection.connectSession(gpa) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.StorageUnavailable,
        };
        defer conn.deinit();
        return runSecretServicePreflightWithCaller(gpa, options, &conn, callBus);
    }
} else struct {};

pub const KeyringOpsAdapter = struct {
    ops: RawKeyringOps = live_keyring_ops,
    enforce_secure_backend: bool = true,

    pub fn backend(self: *const KeyringOpsAdapter) PersistenceBackend {
        return .{
            .ctx = @ptrCast(@constCast(self)),
            .checkAvailableFn = checkAvailableImpl,
            .getFn = getImpl,
            .setFn = setImpl,
            .deleteFn = deleteImpl,
        };
    }

    fn usesLiveKeyringOps(self: *const KeyringOpsAdapter) bool {
        return self.ops.get == live_keyring_ops.get and
            self.ops.set == live_keyring_ops.set and
            self.ops.delete == live_keyring_ops.delete;
    }

    fn preflightIfNeeded(
        self: *const KeyringOpsAdapter,
        gpa: Allocator,
        options: PersistenceOptions,
    ) cp.ProviderError!void {
        try options.deadline.checkBudget();
        if (self.enforce_secure_backend) {
            try checkSecureBackendAvailable(gpa);
            if (builtin.os.tag == .linux and
                keyring_zig.currentBackend() == .secret_service and
                self.usesLiveKeyringOps())
            {
                try LinuxSecretServicePreflight.run(gpa, options);
            }
        }
        try options.deadline.checkBudget();
    }

    fn mapOpError(err: keyring_zig.Error, options: PersistenceOptions) cp.ProviderError {
        const mapped: cp.ProviderError = blk: {
            if (builtin.os.tag == .windows and err == error.PlatformFailure) {
                if (win32_err.GetLastError() == win32_err.ERROR_ACCESS_DENIED) {
                    break :blk error.AccessDenied;
                }
            }
            break :blk mapKeyringError(err);
        };
        if (mapped != error.OutOfMemory) {
            options.deadline.checkBudget() catch |budget_err| return budget_err;
        }
        return mapped;
    }

    fn checkAvailableImpl(
        ctx: ?*anyopaque,
        gpa: Allocator,
        options: PersistenceOptions,
    ) cp.ProviderError!void {
        const self: *const KeyringOpsAdapter = @ptrCast(@alignCast(ctx.?));
        try self.preflightIfNeeded(gpa, options);
    }

    fn getImpl(
        ctx: ?*anyopaque,
        gpa: Allocator,
        service: []const u8,
        account: []const u8,
        options: PersistenceOptions,
    ) cp.ProviderError![]u8 {
        const self: *const KeyringOpsAdapter = @ptrCast(@alignCast(ctx.?));
        try self.preflightIfNeeded(gpa, options);
        if (builtin.os.tag == .windows) win32_err.SetLastError(0);
        const val = self.ops.get(gpa, service, account) catch |err| return mapOpError(err, options);
        errdefer {
            std.crypto.secureZero(u8, val);
            gpa.free(val);
        }
        try options.deadline.checkBudget();
        return val;
    }

    fn setImpl(
        ctx: ?*anyopaque,
        gpa: Allocator,
        service: []const u8,
        account: []const u8,
        value: []const u8,
        options: PersistenceOptions,
    ) cp.ProviderError!void {
        const self: *const KeyringOpsAdapter = @ptrCast(@alignCast(ctx.?));
        try self.preflightIfNeeded(gpa, options);
        if (builtin.os.tag == .windows) win32_err.SetLastError(0);
        self.ops.set(gpa, service, account, value) catch |err| return mapOpError(err, options);
        try options.deadline.checkBudget();
    }

    fn deleteImpl(
        ctx: ?*anyopaque,
        gpa: Allocator,
        service: []const u8,
        account: []const u8,
        options: PersistenceOptions,
    ) cp.ProviderError!void {
        const self: *const KeyringOpsAdapter = @ptrCast(@alignCast(ctx.?));
        try self.preflightIfNeeded(gpa, options);
        if (builtin.os.tag == .windows) win32_err.SetLastError(0);
        self.ops.delete(gpa, service, account) catch |err| return mapOpError(err, options);
        try options.deadline.checkBudget();
    }
};

pub const KeyringPersistence = KeyringOpsAdapter;

const default_keyring_adapter: KeyringOpsAdapter = .{
    .ops = live_keyring_ops,
    .enforce_secure_backend = true,
};

pub fn defaultKeyringPersistence() PersistenceBackend {
    return default_keyring_adapter.backend();
}

// ---------------------------------------------------------------------------
// 3. StoredCredentialProvider
// ---------------------------------------------------------------------------

pub const Config = struct {
    namespace_prefix: []const u8 = default_namespace_prefix,
    include_scheme_in_key: bool = true,
    default_account_slot: []const u8 = "default",
    single_slot_per_target: bool = false,
};

pub const StoredCredentialProvider = struct {
    persistence: PersistenceBackend,
    config: Config = .{},

    pub fn init(persistence: PersistenceBackend, config: Config) StoredCredentialProvider {
        return .{
            .persistence = persistence,
            .config = config,
        };
    }

    pub fn initDefault() StoredCredentialProvider {
        return .{
            .persistence = defaultKeyringPersistence(),
            .config = .{},
        };
    }

    pub fn initContainerRegistry(persistence: PersistenceBackend) StoredCredentialProvider {
        return .{
            .persistence = persistence,
            .config = .{
                .namespace_prefix = container_registry_namespace_prefix,
                .include_scheme_in_key = false,
                .default_account_slot = "default",
                .single_slot_per_target = true,
            },
        };
    }

    pub fn provider(self: *const StoredCredentialProvider) cp.Provider {
        return .{
            .name = "stored_credentials",
            .ctx = @ptrCast(@constCast(self)),
            .getFn = providerGet,
            .loginFn = providerLogin,
            .logoutFn = providerLogout,
            .renewNoninteractiveFn = null,
        };
    }

    pub fn get(
        self: *const StoredCredentialProvider,
        gpa: Allocator,
        request: cp.Request,
    ) cp.ProviderError!cp.CredentialResult {
        if (request.operation != .get) return error.InvalidInput;
        try request.validate();
        try request.deadline.checkBudget();

        const service_key = try self.resolveServiceKeyAlloc(gpa, request.target);
        defer gpa.free(service_key);

        const slot_selector: ?[]const u8 = if (self.config.single_slot_per_target) null else request.account;
        const account_slot = try self.resolveAccountSlotAlloc(gpa, slot_selector);
        defer gpa.free(account_slot);

        const persist_opts: PersistenceOptions = .{
            .interaction = .never,
            .deadline = request.deadline,
        };

        try self.persistence.checkAvailableFn(self.persistence.ctx, gpa, persist_opts);

        const raw = try self.persistence.getFn(self.persistence.ctx, gpa, service_key, account_slot, persist_opts);
        defer {
            std.crypto.secureZero(u8, raw);
            gpa.free(raw);
        }

        try request.deadline.checkBudget();

        var res = try decodeEnvelopeAlloc(gpa, raw);
        errdefer res.deinit(gpa);

        if (self.config.single_slot_per_target) {
            if (request.account) |req_acc| {
                if (!matchesRequestedAccount(res, req_acc)) {
                    return error.CredentialNotFound;
                }
            }
        } else if (request.account) |req_acc| {
            if (res.account) |stored_acc| {
                if (!std.mem.eql(u8, stored_acc, req_acc)) {
                    return error.StorageFailure;
                }
            }
        }

        if (request.audience) |req_aud| {
            const stored_aud = res.audience orelse return error.CredentialNotFound;
            if (!std.mem.eql(u8, stored_aud, req_aud)) {
                return error.CredentialNotFound;
            }
        }

        if (request.scopes.len > 0) {
            const stored_scopes = res.scopes orelse return error.CredentialNotFound;
            if (!containsAllScopes(stored_scopes, request.scopes)) {
                return error.CredentialNotFound;
            }
        }

        if (res.isExpiredAt(request.deadline.nowSeconds())) {
            return error.ReauthenticationRequired;
        }

        return res;
    }

    pub fn login(
        self: *const StoredCredentialProvider,
        gpa: Allocator,
        input: cp.LoginInput,
    ) cp.ProviderError!cp.CredentialResult {
        if (input.request.operation != .login) return error.InvalidInput;
        try input.request.validate();
        try input.request.deadline.checkBudget();

        const cred = input.credential orelse return error.UnsupportedOperation;
        try cred.validate();

        if (!cred.cache_policy.isPersistent()) {
            return error.InvalidInput;
        }

        if (input.request.account != null and cred.account != null and
            !std.mem.eql(u8, input.request.account.?, cred.account.?))
        {
            return error.InvalidInput;
        }

        if (input.request.audience != null and cred.audience != null and
            !std.mem.eql(u8, input.request.audience.?, cred.audience.?))
        {
            return error.InvalidInput;
        }

        if (input.request.scopes.len > 0) {
            const cred_scopes = cred.scopes orelse return error.InvalidInput;
            if (!containsAllScopes(cred_scopes, input.request.scopes)) {
                return error.InvalidInput;
            }
        }

        const effective_account: ?[]const u8 = input.request.account orelse cred.account;

        const service_key = try self.resolveServiceKeyAlloc(gpa, input.request.target);
        defer gpa.free(service_key);

        const slot_selector: ?[]const u8 = if (self.config.single_slot_per_target) null else input.request.account;
        const account_slot = try self.resolveAccountSlotAlloc(gpa, slot_selector);
        defer gpa.free(account_slot);

        const persist_opts: PersistenceOptions = .{
            .interaction = input.request.interaction,
            .deadline = input.request.deadline,
        };

        try self.persistence.checkAvailableFn(self.persistence.ctx, gpa, persist_opts);
        try input.request.deadline.checkBudget();

        var out = try cred.clone(gpa);
        errdefer out.deinit(gpa);
        out.supports_noninteractive_renewal = false;
        if (out.account == null) {
            if (effective_account) |acc| {
                out.account = try gpa.dupe(u8, acc);
            }
        }

        const encoded = try encodeEnvelopeV1Alloc(gpa, out);
        defer {
            std.crypto.secureZero(u8, encoded);
            gpa.free(encoded);
        }

        try self.persistence.setFn(self.persistence.ctx, gpa, service_key, account_slot, encoded, persist_opts);
        try input.request.deadline.checkBudget();

        return out;
    }

    pub fn logout(
        self: *const StoredCredentialProvider,
        gpa: Allocator,
        request: cp.Request,
    ) cp.ProviderError!void {
        if (request.operation != .logout) return error.InvalidInput;
        try request.validate();
        try request.deadline.checkBudget();

        const service_key = try self.resolveServiceKeyAlloc(gpa, request.target);
        defer gpa.free(service_key);

        const slot_selector: ?[]const u8 = if (self.config.single_slot_per_target) null else request.account;
        const account_slot = try self.resolveAccountSlotAlloc(gpa, slot_selector);
        defer gpa.free(account_slot);

        const persist_opts: PersistenceOptions = .{
            .interaction = request.interaction,
            .deadline = request.deadline,
        };

        try self.persistence.checkAvailableFn(self.persistence.ctx, gpa, persist_opts);

        if (self.config.single_slot_per_target) {
            if (request.account) |req_acc| {
                const raw = try self.persistence.getFn(self.persistence.ctx, gpa, service_key, account_slot, persist_opts);
                defer {
                    std.crypto.secureZero(u8, raw);
                    gpa.free(raw);
                }

                try request.deadline.checkBudget();

                var existing = try decodeEnvelopeAlloc(gpa, raw);
                defer existing.deinit(gpa);

                if (!matchesRequestedAccount(existing, req_acc)) {
                    return error.CredentialNotFound;
                }
            }
        }

        try self.persistence.deleteFn(self.persistence.ctx, gpa, service_key, account_slot, persist_opts);
        try request.deadline.checkBudget();
    }

    fn resolveServiceKeyAlloc(
        self: *const StoredCredentialProvider,
        gpa: Allocator,
        target: cp.Target,
    ) cp.ProviderError![]u8 {
        const key = try target.serviceKeyAlloc(
            gpa,
            self.config.namespace_prefix,
            self.config.include_scheme_in_key,
        );
        errdefer gpa.free(key);

        if (isForbiddenReservedServiceKey(key)) {
            return error.InvalidInput;
        }
        return key;
    }

    fn resolveAccountSlotAlloc(
        self: *const StoredCredentialProvider,
        gpa: Allocator,
        effective_account: ?[]const u8,
    ) cp.ProviderError![]u8 {
        const default_slot = self.config.default_account_slot;
        if (default_slot.len == 0 or
            hasControlChars(default_slot) or
            std.mem.startsWith(u8, default_slot, named_account_slot_prefix))
        {
            return error.InvalidInput;
        }

        if (effective_account) |acc| {
            if (acc.len == 0 or hasControlChars(acc)) return error.InvalidInput;
            return std.fmt.allocPrint(gpa, "{s}{s}", .{ named_account_slot_prefix, acc });
        }
        return gpa.dupe(u8, default_slot);
    }

    fn providerGet(
        ctx: ?*anyopaque,
        gpa: Allocator,
        request: cp.Request,
    ) cp.ProviderError!cp.CredentialResult {
        const self: *const StoredCredentialProvider = @ptrCast(@alignCast(ctx.?));
        return self.get(gpa, request);
    }

    fn providerLogin(
        ctx: ?*anyopaque,
        gpa: Allocator,
        input: cp.LoginInput,
    ) cp.ProviderError!cp.CredentialResult {
        const self: *const StoredCredentialProvider = @ptrCast(@alignCast(ctx.?));
        return self.login(gpa, input);
    }

    fn providerLogout(
        ctx: ?*anyopaque,
        gpa: Allocator,
        request: cp.Request,
    ) cp.ProviderError!void {
        const self: *const StoredCredentialProvider = @ptrCast(@alignCast(ctx.?));
        return self.logout(gpa, request);
    }
};

// ---------------------------------------------------------------------------
// Envelope Serialization & Legacy Compatibility
// ---------------------------------------------------------------------------

const StoredEnvelopeV1 = struct {
    v: u32 = 1,
    kind: []const u8,
    username: ?[]const u8 = null,
    secret: []const u8,
    account: ?[]const u8 = null,
    expires_at: ?i64 = null,
    cache_policy: []const u8,
    audience: ?[]const u8 = null,
    scopes: ?[]const []const u8 = null,
};

fn encodeEnvelopeV1Alloc(gpa: Allocator, cred: cp.CredentialResult) cp.ProviderError![]u8 {
    try cred.validate();

    const cache_policy_str: []const u8 = switch (cred.cache_policy) {
        .eternal => "eternal",
        .until_expiration => "until_expiration",
        .session, .never => return error.InvalidInput,
    };

    var kind_str: []const u8 = undefined;
    var username: ?[]const u8 = null;
    var secret: []const u8 = undefined;

    switch (cred.secret) {
        .basic => |b| {
            kind_str = "basic";
            username = b.username;
            secret = b.secret;
        },
        .bearer_token => |tok| {
            kind_str = "bearer_token";
            secret = tok;
        },
        .identity_token => |tok| {
            kind_str = "identity_token";
            secret = tok;
        },
    }

    var const_scopes: ?[][]const u8 = null;
    defer if (const_scopes) |cs| gpa.free(cs);
    if (cred.scopes) |scope_list| {
        const buf = try gpa.alloc([]const u8, scope_list.len);
        for (scope_list, 0..) |s, idx| {
            buf[idx] = s;
        }
        const_scopes = buf;
    }

    const envelope: StoredEnvelopeV1 = .{
        .v = 1,
        .kind = kind_str,
        .username = username,
        .secret = secret,
        .account = cred.account,
        .expires_at = cred.expires_at,
        .cache_policy = cache_policy_str,
        .audience = cred.audience,
        .scopes = const_scopes,
    };

    var out = std.Io.Writer.Allocating.init(gpa);
    errdefer {
        std.crypto.secureZero(u8, out.written());
        out.deinit();
    }

    var stringify: std.json.Stringify = .{
        .writer = &out.writer,
        .options = .{ .emit_null_optional_fields = false },
    };
    stringify.write(envelope) catch return error.OutOfMemory;

    return out.toOwnedSlice() catch error.OutOfMemory;
}

fn decodeEnvelopeAlloc(gpa: Allocator, raw: []const u8) cp.ProviderError!cp.CredentialResult {
    if (raw.len == 0) return error.StorageFailure;

    var parsed = std.json.parseFromSlice(std.json.Value, gpa, raw, .{
        .allocate = .alloc_always,
    }) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.StorageFailure,
    };
    defer {
        zeroJsonStrings(&parsed.value);
        parsed.deinit();
    }

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.StorageFailure,
    };

    if (obj.get("v")) |v_val| {
        return decodeEnvelopeV1(gpa, obj, v_val);
    }
    return decodeLegacyEnvelopeV0(gpa, obj);
}

fn decodeLegacyEnvelopeV0(
    gpa: Allocator,
    obj: std.json.ObjectMap,
) cp.ProviderError!cp.CredentialResult {
    // Legacy v0 records ({"username":"...","secret":"..."}) must not contain v1 envelope keys.
    if (obj.get("kind") != null or
        obj.get("cache_policy") != null or
        obj.get("expires_at") != null or
        obj.get("account") != null or
        obj.get("audience") != null or
        obj.get("scopes") != null)
    {
        return error.StorageFailure;
    }

    const username = getRequiredNonEmptyString(obj, "username") orelse return error.StorageFailure;
    const secret = getRequiredNonEmptyString(obj, "secret") orelse return error.StorageFailure;

    var cred_secret: cp.CredentialSecret = if (std.mem.eql(u8, username, legacy_identity_token_username))
        .{ .identity_token = try gpa.dupe(u8, secret) }
    else blk: {
        const user_copy = try gpa.dupe(u8, username);
        errdefer gpa.free(user_copy);
        const sec_copy = try gpa.dupe(u8, secret);
        break :blk .{
            .basic = .{
                .username = user_copy,
                .secret = sec_copy,
            },
        };
    };
    errdefer cred_secret.deinit(gpa);

    const res: cp.CredentialResult = .{
        .secret = cred_secret,
        .account = null,
        .expires_at = null,
        .cache_policy = .eternal,
        .audience = null,
        .scopes = null,
        .supports_noninteractive_renewal = false,
    };
    res.validate() catch return error.StorageFailure;
    return res;
}

fn decodeEnvelopeV1(
    gpa: Allocator,
    obj: std.json.ObjectMap,
    v_val: std.json.Value,
) cp.ProviderError!cp.CredentialResult {
    switch (v_val) {
        .integer => |ver| if (ver != 1) return error.StorageFailure,
        else => return error.StorageFailure,
    }

    const kind_str = getRequiredNonEmptyString(obj, "kind") orelse return error.StorageFailure;
    const secret_str = getRequiredNonEmptyString(obj, "secret") orelse return error.StorageFailure;
    const cache_policy_str = getRequiredNonEmptyString(obj, "cache_policy") orelse return error.StorageFailure;

    const cache_policy: cp.CachePolicy = if (std.mem.eql(u8, cache_policy_str, "eternal"))
        .eternal
    else if (std.mem.eql(u8, cache_policy_str, "until_expiration"))
        .until_expiration
    else
        return error.StorageFailure;

    const username_opt = try getOptionalString(obj, "username");
    const account_opt = try getOptionalString(obj, "account");
    const audience_opt = try getOptionalString(obj, "audience");
    const expires_at_opt = try getOptionalInteger(obj, "expires_at");

    if (cache_policy == .until_expiration and expires_at_opt == null) {
        return error.StorageFailure;
    }

    var cred_secret: cp.CredentialSecret = undefined;
    if (std.mem.eql(u8, kind_str, "basic")) {
        const uname = username_opt orelse return error.StorageFailure;
        if (uname.len == 0) return error.StorageFailure;
        const user_copy = try gpa.dupe(u8, uname);
        errdefer gpa.free(user_copy);
        const sec_copy = try gpa.dupe(u8, secret_str);
        cred_secret = .{
            .basic = .{
                .username = user_copy,
                .secret = sec_copy,
            },
        };
    } else if (std.mem.eql(u8, kind_str, "bearer_token")) {
        if (username_opt != null) return error.StorageFailure;
        cred_secret = .{ .bearer_token = try gpa.dupe(u8, secret_str) };
    } else if (std.mem.eql(u8, kind_str, "identity_token")) {
        if (username_opt != null) return error.StorageFailure;
        cred_secret = .{ .identity_token = try gpa.dupe(u8, secret_str) };
    } else {
        return error.StorageFailure;
    }
    errdefer cred_secret.deinit(gpa);

    const account_copy: ?[]u8 = if (account_opt) |acc| blk: {
        if (acc.len == 0) return error.StorageFailure;
        break :blk try gpa.dupe(u8, acc);
    } else null;
    errdefer if (account_copy) |acc| gpa.free(acc);

    const audience_copy: ?[]u8 = if (audience_opt) |aud| blk: {
        if (aud.len == 0) return error.StorageFailure;
        break :blk try gpa.dupe(u8, aud);
    } else null;
    errdefer if (audience_copy) |aud| gpa.free(aud);

    const scopes_copy = try decodeOptionalScopesAlloc(gpa, obj);
    errdefer if (scopes_copy) |scope_list| {
        for (scope_list) |s| gpa.free(s);
        gpa.free(scope_list);
    };

    const res: cp.CredentialResult = .{
        .secret = cred_secret,
        .account = account_copy,
        .expires_at = expires_at_opt,
        .cache_policy = cache_policy,
        .audience = audience_copy,
        .scopes = scopes_copy,
        .supports_noninteractive_renewal = false,
    };
    res.validate() catch return error.StorageFailure;
    return res;
}

fn getRequiredNonEmptyString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .string => |s| if (s.len > 0) s else null,
        else => null,
    };
}

fn getOptionalString(obj: std.json.ObjectMap, key: []const u8) cp.ProviderError!?[]const u8 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .null => null,
        .string => |s| s,
        else => error.StorageFailure,
    };
}

fn getOptionalInteger(obj: std.json.ObjectMap, key: []const u8) cp.ProviderError!?i64 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .null => null,
        .integer => |i| i,
        else => error.StorageFailure,
    };
}

fn decodeOptionalScopesAlloc(gpa: Allocator, obj: std.json.ObjectMap) cp.ProviderError!?[][]u8 {
    const val = obj.get("scopes") orelse return null;
    const arr = switch (val) {
        .null => return null,
        .array => |a| a,
        else => return error.StorageFailure,
    };

    const out = try gpa.alloc([]u8, arr.items.len);
    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |item| gpa.free(item);
        gpa.free(out);
    }

    for (arr.items, 0..) |elem, idx| {
        const scope_str = switch (elem) {
            .string => |s| s,
            else => return error.StorageFailure,
        };
        if (scope_str.len == 0 or hasControlChars(scope_str)) {
            return error.StorageFailure;
        }
        out[idx] = try gpa.dupe(u8, scope_str);
        initialized += 1;
    }

    return out;
}

fn zeroJsonStrings(val: *std.json.Value) void {
    switch (val.*) {
        .string => |s| std.crypto.secureZero(u8, @constCast(s)),
        .number_string => |s| std.crypto.secureZero(u8, @constCast(s)),
        .array => |*arr| {
            for (arr.items) |*item| zeroJsonStrings(item);
        },
        .object => |*obj| {
            var it = obj.iterator();
            while (it.next()) |entry| {
                std.crypto.secureZero(u8, @constCast(entry.key_ptr.*));
                zeroJsonStrings(entry.value_ptr);
            }
        },
        .null, .bool, .integer, .float => {},
    }
}

// ---------------------------------------------------------------------------
// Internal Environment, Account, & Validation Helpers
// ---------------------------------------------------------------------------

fn matchesRequestedAccount(cred: cp.CredentialResult, requested_account: []const u8) bool {
    if (cred.account) |acc| {
        return std.mem.eql(u8, acc, requested_account);
    }
    return switch (cred.secret) {
        .basic => |b| std.mem.eql(u8, b.username, requested_account),
        .identity_token => std.mem.eql(u8, requested_account, legacy_identity_token_username),
        .bearer_token => false,
    };
}

fn containsAllScopes(have: []const []u8, required: []const []const u8) bool {
    for (required) |req_scope| {
        var found = false;
        for (have) |s| {
            if (std.mem.eql(u8, s, req_scope)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn isForbiddenReservedServiceKey(key: []const u8) bool {
    if (std.ascii.startsWithIgnoreCase(key, "gh:")) return true;
    if (std.ascii.eqlIgnoreCase(key, "copilot-cli") or
        std.ascii.startsWithIgnoreCase(key, "copilot-cli/") or
        std.ascii.startsWithIgnoreCase(key, "copilot-cli:") or
        std.ascii.endsWithIgnoreCase(key, ".copilot-cli") or
        std.ascii.endsWithIgnoreCase(key, "@copilot-cli"))
    {
        return true;
    }
    if (std.ascii.eqlIgnoreCase(key, "ado-keyring") or
        std.ascii.startsWithIgnoreCase(key, "ado-keyring/") or
        std.ascii.startsWithIgnoreCase(key, "ado-keyring:"))
    {
        return true;
    }
    if (std.ascii.eqlIgnoreCase(key, "refresh.dat") or
        std.ascii.eqlIgnoreCase(key, "session.dat"))
    {
        return true;
    }
    return false;
}

fn hasControlChars(s: []const u8) bool {
    for (s) |c| {
        if (c == 0 or std.ascii.isControl(c)) return true;
    }
    return false;
}

fn hasConfiguredFileBackendPath(gpa: Allocator) cp.ProviderError!bool {
    return hasConfiguredFileBackendPathForOs(gpa, builtin.os.tag);
}

fn hasConfiguredFileBackendPathForOs(gpa: Allocator, os_tag: std.Target.Os.Tag) cp.ProviderError!bool {
    if (try getEnvOwned(gpa, "KEYRING_FILE_PATH")) |file_path| {
        defer gpa.free(file_path);
        return std.mem.trim(u8, file_path, " \t\r\n").len > 0;
    }

    // `keyring_zig`'s `.file` backend ignores `KEYRING_PROPERTY_FILE_PATH`.
    // Reject non-empty `KEYRING_PROPERTY_FILE_PATH` when `KEYRING_FILE_PATH` is
    // unset so callers never silently fall back to the default `store.bin`.
    if (try getEnvOwned(gpa, "KEYRING_PROPERTY_FILE_PATH")) |prop_env_path| {
        defer gpa.free(prop_env_path);
        if (std.mem.trim(u8, prop_env_path, " \t\r\n").len > 0) {
            return false;
        }
    }

    return switch (os_tag) {
        .windows => blk: {
            if (try getEnvOwned(gpa, "LOCALAPPDATA")) |lad| {
                defer gpa.free(lad);
                if (lad.len > 0) break :blk true;
            }
            break :blk false;
        },
        .macos => blk: {
            if (try getEnvOwned(gpa, "HOME")) |home| {
                defer gpa.free(home);
                if (home.len > 0) break :blk true;
            }
            break :blk false;
        },
        .wasi => false,
        else => blk: {
            if (try getEnvOwned(gpa, "XDG_DATA_HOME")) |xdg| {
                defer gpa.free(xdg);
                if (xdg.len > 0 and xdg[0] == '/') break :blk true;
            }
            if (try getEnvOwned(gpa, "HOME")) |home| {
                defer gpa.free(home);
                if (home.len > 0) break :blk true;
            }
            break :blk false;
        },
    };
}

pub fn getEnvOwned(gpa: Allocator, name: []const u8) cp.ProviderError!?[]u8 {
    if (env_override_fn) |override_fn| {
        if (override_fn(name)) |val| return try gpa.dupe(u8, val);
        return null;
    }
    return getProcessEnvOwned(gpa, name);
}

fn getProcessEnvOwned(gpa: Allocator, name: []const u8) cp.ProviderError!?[]u8 {
    if (builtin.os.tag == .wasi) return null;
    if (builtin.os.tag == .windows) {
        var map = std.process.Environ.createMap(.{ .block = .global }, gpa) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        };
        defer map.deinit();
        if (map.get(name)) |val| return try gpa.dupe(u8, val);
        return null;
    }
    var idx: usize = 0;
    while (std.c.environ[idx]) |entry_ptr| : (idx += 1) {
        const entry = std.mem.span(entry_ptr);
        if (entry.len > name.len and entry[name.len] == '=' and std.mem.eql(u8, entry[0..name.len], name)) {
            return try gpa.dupe(u8, entry[name.len + 1 ..]);
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// Deterministic Unit Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const TestClock = struct {
    var current_ms: i64 = 1_700_000_000_000;

    fn nowMs() i64 {
        return current_ms;
    }
};

const FakePersistence = struct {
    const Entry = struct {
        service: []u8,
        account: []u8,
        value: []u8,

        fn deinit(self: *Entry, gpa: Allocator) void {
            gpa.free(self.service);
            gpa.free(self.account);
            std.crypto.secureZero(u8, self.value);
            gpa.free(self.value);
        }
    };

    entries: std.ArrayList(Entry) = .empty,
    owner_gpa: Allocator,
    available_err: ?cp.ProviderError = null,
    get_err: ?cp.ProviderError = null,
    set_err: ?cp.ProviderError = null,
    delete_err: ?cp.ProviderError = null,
    advance_ms_on_get: i64 = 0,
    last_interaction: ?cp.InteractionPolicy = null,

    fn init(owner_gpa: Allocator) FakePersistence {
        return .{ .owner_gpa = owner_gpa };
    }

    fn deinit(self: *FakePersistence) void {
        for (self.entries.items) |*entry| {
            entry.deinit(self.owner_gpa);
        }
        self.entries.deinit(self.owner_gpa);
    }

    fn backend(self: *FakePersistence) PersistenceBackend {
        return .{
            .ctx = self,
            .checkAvailableFn = checkAvailable,
            .getFn = get,
            .setFn = set,
            .deleteFn = delete,
        };
    }

    fn putRaw(self: *FakePersistence, service: []const u8, account: []const u8, raw: []const u8) !void {
        try set(self, self.owner_gpa, service, account, raw, .{});
    }

    fn rawAt(self: *const FakePersistence, service: []const u8, account: []const u8) ?[]const u8 {
        for (self.entries.items) |entry| {
            if (std.mem.eql(u8, entry.service, service) and std.mem.eql(u8, entry.account, account)) {
                return entry.value;
            }
        }
        return null;
    }

    fn count(self: *const FakePersistence) usize {
        return self.entries.items.len;
    }

    fn checkAvailable(ctx: ?*anyopaque, _: Allocator, options: PersistenceOptions) cp.ProviderError!void {
        const self: *FakePersistence = @ptrCast(@alignCast(ctx.?));
        self.last_interaction = options.interaction;
        try options.deadline.checkBudget();
        if (self.available_err) |err| return err;
    }

    fn get(
        ctx: ?*anyopaque,
        gpa: Allocator,
        service: []const u8,
        account: []const u8,
        options: PersistenceOptions,
    ) cp.ProviderError![]u8 {
        const self: *FakePersistence = @ptrCast(@alignCast(ctx.?));
        self.last_interaction = options.interaction;
        try options.deadline.checkBudget();
        if (self.get_err) |err| return err;
        TestClock.current_ms += self.advance_ms_on_get;
        for (self.entries.items) |entry| {
            if (std.mem.eql(u8, entry.service, service) and std.mem.eql(u8, entry.account, account)) {
                return gpa.dupe(u8, entry.value);
            }
        }
        return error.CredentialNotFound;
    }

    fn set(
        ctx: ?*anyopaque,
        gpa: Allocator,
        service: []const u8,
        account: []const u8,
        value: []const u8,
        options: PersistenceOptions,
    ) cp.ProviderError!void {
        const self: *FakePersistence = @ptrCast(@alignCast(ctx.?));
        self.last_interaction = options.interaction;
        try options.deadline.checkBudget();
        if (self.set_err) |err| return err;

        // Exercise caller `gpa` for OOM testing before committing into `owner_gpa`.
        const probe = try gpa.dupe(u8, value);
        std.crypto.secureZero(u8, probe);
        gpa.free(probe);

        const val_copy = try self.owner_gpa.dupe(u8, value);
        errdefer {
            std.crypto.secureZero(u8, val_copy);
            self.owner_gpa.free(val_copy);
        }

        for (self.entries.items) |*entry| {
            if (std.mem.eql(u8, entry.service, service) and std.mem.eql(u8, entry.account, account)) {
                std.crypto.secureZero(u8, entry.value);
                self.owner_gpa.free(entry.value);
                entry.value = val_copy;
                return;
            }
        }

        const svc_copy = try self.owner_gpa.dupe(u8, service);
        errdefer self.owner_gpa.free(svc_copy);
        const acc_copy = try self.owner_gpa.dupe(u8, account);
        errdefer self.owner_gpa.free(acc_copy);

        try self.entries.append(self.owner_gpa, .{
            .service = svc_copy,
            .account = acc_copy,
            .value = val_copy,
        });
    }

    fn delete(
        ctx: ?*anyopaque,
        _: Allocator,
        service: []const u8,
        account: []const u8,
        options: PersistenceOptions,
    ) cp.ProviderError!void {
        const self: *FakePersistence = @ptrCast(@alignCast(ctx.?));
        self.last_interaction = options.interaction;
        try options.deadline.checkBudget();
        if (self.delete_err) |err| return err;

        for (self.entries.items, 0..) |*entry, idx| {
            if (std.mem.eql(u8, entry.service, service) and std.mem.eql(u8, entry.account, account)) {
                var removed = self.entries.orderedRemove(idx);
                removed.deinit(self.owner_gpa);
                return;
            }
        }
        return error.CredentialNotFound;
    }
};

test "StoredCredentialProvider lifecycle keeps basic, bearer_token, and identity_token distinct" {
    const gpa = testing.allocator;
    var store = FakePersistence.init(gpa);
    defer store.deinit();

    const sp = StoredCredentialProvider.init(store.backend(), .{});
    const prov = sp.provider();
    try testing.expectEqualStrings("stored_credentials", prov.name);
    try testing.expect(prov.renewNoninteractiveFn == null);

    var target_gh = try cp.Target.parseAlloc(gpa, "https://github.com", .{});
    defer target_gh.deinit(gpa);
    var target_ado = try cp.Target.parseAlloc(gpa, "https://dev.azure.com", .{});
    defer target_ado.deinit(gpa);
    var target_reg = try cp.Target.parseAlloc(gpa, "https://registry.example.io:5000", .{});
    defer target_reg.deinit(gpa);

    // Interactive/OAuth login without an explicit credential returns UnsupportedOperation.
    try testing.expectError(
        error.UnsupportedOperation,
        prov.executeLogin(gpa, .{
            .request = .{
                .target = target_gh,
                .operation = .login,
                .interaction = .always,
            },
            .credential = null,
        }),
    );

    // 1. Store & retrieve `basic` credential.
    var basic_in: cp.CredentialResult = .{
        .secret = .{
            .basic = .{
                .username = try gpa.dupe(u8, "octocat"),
                .secret = try gpa.dupe(u8, "ghp_secret_1"),
            },
        },
    };
    defer basic_in.deinit(gpa);

    var basic_saved = try prov.executeLogin(gpa, .{
        .request = .{ .target = target_gh, .operation = .login },
        .credential = &basic_in,
    });
    defer basic_saved.deinit(gpa);
    try testing.expectEqual(cp.CredentialKind.basic, basic_saved.secret.kind());

    // Service key is isolated under credential-provider://https/<host>, never gh: or https://.
    try testing.expect(store.rawAt("credential-provider://https/github.com", "default") != null);
    try testing.expect(store.rawAt("gh:github.com", "default") == null);
    try testing.expect(store.rawAt("https://github.com", "default") == null);

    var basic_got = try prov.executeGet(gpa, .{
        .target = target_gh,
        .interaction = .always, // executeGet + stored provider never prompt interactively
    });
    defer basic_got.deinit(gpa);
    try testing.expectEqual(cp.CredentialKind.basic, basic_got.secret.kind());
    try testing.expectEqualStrings("octocat", basic_got.secret.basic.username);
    try testing.expectEqualStrings("ghp_secret_1", basic_got.secret.basic.secret);

    // 2. Store & retrieve `bearer_token` credential (even on dev.azure.com host: isolated key!).
    var bearer_in: cp.CredentialResult = .{
        .secret = .{ .bearer_token = try gpa.dupe(u8, "eyJ_bearer_token") },
    };
    defer bearer_in.deinit(gpa);

    var bearer_saved = try prov.executeLogin(gpa, .{
        .request = .{ .target = target_ado, .operation = .login },
        .credential = &bearer_in,
    });
    defer bearer_saved.deinit(gpa);

    const raw_bearer = store.rawAt("credential-provider://https/dev.azure.com", "default").?;
    try testing.expect(std.mem.indexOf(u8, raw_bearer, "\"username\"") == null);
    try testing.expect(store.rawAt("ado-keyring", "refresh-token") == null);

    var bearer_got = try prov.executeGet(gpa, .{ .target = target_ado });
    defer bearer_got.deinit(gpa);
    try testing.expectEqual(cp.CredentialKind.bearer_token, bearer_got.secret.kind());
    try testing.expectEqualStrings("eyJ_bearer_token", bearer_got.secret.bearer_token);

    // 3. Store & retrieve `identity_token` credential.
    var id_in: cp.CredentialResult = .{
        .secret = .{ .identity_token = try gpa.dupe(u8, "acr_refresh_identity_tok") },
    };
    defer id_in.deinit(gpa);

    var id_saved = try prov.executeLogin(gpa, .{
        .request = .{ .target = target_reg, .operation = .login },
        .credential = &id_in,
    });
    defer id_saved.deinit(gpa);

    var id_got = try prov.executeGet(gpa, .{ .target = target_reg });
    defer id_got.deinit(gpa);
    try testing.expectEqual(cp.CredentialKind.identity_token, id_got.secret.kind());
    try testing.expectEqualStrings("acr_refresh_identity_tok", id_got.secret.identity_token);

    // 4. Replacement overwrites the prior credential cleanly at the same target/slot.
    var replacement_in: cp.CredentialResult = .{
        .secret = .{ .bearer_token = try gpa.dupe(u8, "rotated_token_v2") },
    };
    defer replacement_in.deinit(gpa);

    var replaced = try prov.executeLogin(gpa, .{
        .request = .{ .target = target_gh, .operation = .login },
        .credential = &replacement_in,
    });
    defer replaced.deinit(gpa);

    var after_replace = try prov.executeGet(gpa, .{ .target = target_gh });
    defer after_replace.deinit(gpa);
    try testing.expectEqual(cp.CredentialKind.bearer_token, after_replace.secret.kind());
    try testing.expectEqualStrings("rotated_token_v2", after_replace.secret.bearer_token);
    try testing.expectEqual(@as(usize, 3), store.count());

    // 5. Targeted logout erases only target_gh, leaving target_ado and target_reg untouched.
    try prov.executeLogout(gpa, .{ .target = target_gh, .operation = .logout });
    try testing.expectError(error.CredentialNotFound, prov.executeGet(gpa, .{ .target = target_gh }));
    try testing.expectError(
        error.CredentialNotFound,
        prov.executeLogout(gpa, .{ .target = target_gh, .operation = .logout }),
    );

    var still_ado = try prov.executeGet(gpa, .{ .target = target_ado });
    defer still_ado.deinit(gpa);
    try testing.expectEqualStrings("eyJ_bearer_token", still_ado.secret.bearer_token);
}

test "StoredCredentialProvider preserves null metadata when unknown and round-trips explicit metadata" {
    const gpa = testing.allocator;
    var store = FakePersistence.init(gpa);
    defer store.deinit();
    TestClock.current_ms = 1_700_000_000_000; // 1_700_000_000s

    const sp = StoredCredentialProvider.init(store.backend(), .{});
    var target = try cp.Target.parseAlloc(gpa, "https://api.example.com", .{});
    defer target.deinit(gpa);

    // Unknown metadata stays null; supports_noninteractive_renewal stays false.
    var minimal_in: cp.CredentialResult = .{
        .secret = .{ .identity_token = try gpa.dupe(u8, "opaque-id-token") },
    };
    defer minimal_in.deinit(gpa);

    var minimal_saved = try sp.login(gpa, .{
        .request = .{ .target = target, .operation = .login },
        .credential = &minimal_in,
    });
    defer minimal_saved.deinit(gpa);

    var minimal_got = try sp.get(gpa, .{
        .target = target,
        .deadline = .{ .now_ms_fn = TestClock.nowMs },
    });
    defer minimal_got.deinit(gpa);
    try testing.expectEqual(@as(?[]u8, null), minimal_got.account);
    try testing.expectEqual(@as(?i64, null), minimal_got.expires_at);
    try testing.expectEqual(cp.CachePolicy.eternal, minimal_got.cache_policy);
    try testing.expectEqual(@as(?[]u8, null), minimal_got.audience);
    try testing.expectEqual(@as(?[][]u8, null), minimal_got.scopes);
    try testing.expect(!minimal_got.supports_noninteractive_renewal);

    // Explicit metadata round-trips accurately; supports_noninteractive_renewal is forced false.
    const scopes_buf = try gpa.alloc([]u8, 2);
    scopes_buf[0] = try gpa.dupe(u8, "repo");
    scopes_buf[1] = try gpa.dupe(u8, "read:packages");

    var rich_in: cp.CredentialResult = .{
        .secret = .{ .bearer_token = try gpa.dupe(u8, "scoped-oauth-token") },
        .account = try gpa.dupe(u8, "deploy-bot"),
        .expires_at = 1_700_003_600,
        .cache_policy = .until_expiration,
        .audience = try gpa.dupe(u8, "https://api.example.com"),
        .scopes = scopes_buf,
        .supports_noninteractive_renewal = true, // must not claim renewal capability when stored statically
    };
    defer rich_in.deinit(gpa);

    var rich_saved = try sp.login(gpa, .{
        .request = .{
            .target = target,
            .operation = .login,
            .account = "deploy-bot",
            .deadline = .{ .now_ms_fn = TestClock.nowMs },
        },
        .credential = &rich_in,
    });
    defer rich_saved.deinit(gpa);
    try testing.expect(!rich_saved.supports_noninteractive_renewal);

    var rich_got = try sp.get(gpa, .{
        .target = target,
        .account = "deploy-bot",
        .deadline = .{ .now_ms_fn = TestClock.nowMs },
    });
    defer rich_got.deinit(gpa);

    try testing.expectEqual(cp.CredentialKind.bearer_token, rich_got.secret.kind());
    try testing.expectEqualStrings("scoped-oauth-token", rich_got.secret.bearer_token);
    try testing.expectEqualStrings("deploy-bot", rich_got.account.?);
    try testing.expectEqual(@as(?i64, 1_700_003_600), rich_got.expires_at);
    try testing.expectEqual(cp.CachePolicy.until_expiration, rich_got.cache_policy);
    try testing.expectEqualStrings("https://api.example.com", rich_got.audience.?);
    try testing.expectEqual(@as(usize, 2), rich_got.scopes.?.len);
    try testing.expectEqualStrings("repo", rich_got.scopes.?[0]);
    try testing.expectEqualStrings("read:packages", rich_got.scopes.?[1]);
    try testing.expect(!rich_got.supports_noninteractive_renewal);
}

test "StoredCredentialProvider rejects non-persistent cache policies and invalid login inputs" {
    const gpa = testing.allocator;
    var store = FakePersistence.init(gpa);
    defer store.deinit();

    const sp = StoredCredentialProvider.init(store.backend(), .{});
    var target = try cp.Target.parseAlloc(gpa, "https://packages.example.com", .{});
    defer target.deinit(gpa);

    var session_cred: cp.CredentialResult = .{
        .secret = .{ .bearer_token = try gpa.dupe(u8, "ephemeral-session-tok") },
        .cache_policy = .session,
    };
    defer session_cred.deinit(gpa);

    try testing.expectError(
        error.InvalidInput,
        sp.login(gpa, .{
            .request = .{ .target = target, .operation = .login },
            .credential = &session_cred,
        }),
    );
    try testing.expectEqual(@as(usize, 0), store.count());

    var never_cred: cp.CredentialResult = .{
        .secret = .{ .bearer_token = try gpa.dupe(u8, "one-shot-tok") },
        .cache_policy = .never,
    };
    defer never_cred.deinit(gpa);

    try testing.expectError(
        error.InvalidInput,
        sp.login(gpa, .{
            .request = .{ .target = target, .operation = .login },
            .credential = &never_cred,
        }),
    );
    try testing.expectEqual(@as(usize, 0), store.count());

    var missing_exp_cred: cp.CredentialResult = .{
        .secret = .{ .bearer_token = try gpa.dupe(u8, "missing-exp-tok") },
        .cache_policy = .until_expiration,
        .expires_at = null,
    };
    defer missing_exp_cred.deinit(gpa);

    try testing.expectError(
        error.InvalidInput,
        sp.login(gpa, .{
            .request = .{ .target = target, .operation = .login },
            .credential = &missing_exp_cred,
        }),
    );
    try testing.expectEqual(@as(usize, 0), store.count());

    // Conflicting request.account and credential.account is rejected.
    var alice_cred: cp.CredentialResult = .{
        .secret = .{ .bearer_token = try gpa.dupe(u8, "alice-tok") },
        .account = try gpa.dupe(u8, "alice"),
    };
    defer alice_cred.deinit(gpa);

    try testing.expectError(
        error.InvalidInput,
        sp.login(gpa, .{
            .request = .{ .target = target, .operation = .login, .account = "bob" },
            .credential = &alice_cred,
        }),
    );
    try testing.expectEqual(@as(usize, 0), store.count());

    // Wrong operation tags are rejected.
    try testing.expectError(error.InvalidInput, sp.get(gpa, .{ .target = target, .operation = .logout }));
    try testing.expectError(error.InvalidInput, sp.logout(gpa, .{ .target = target, .operation = .get }));
    try testing.expectError(
        error.InvalidInput,
        sp.login(gpa, .{
            .request = .{ .target = target, .operation = .get },
            .credential = &alice_cred,
        }),
    );
}

test "StoredCredentialProvider surfaces authoritative errors and halts ProviderChain on expiry or storage faults" {
    const gpa = testing.allocator;
    var store = FakePersistence.init(gpa);
    defer store.deinit();

    const FallbackSpy = struct {
        called: usize = 0,
        fn get(ctx: ?*anyopaque, alloc: Allocator, _: cp.Request) cp.ProviderError!cp.CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.called += 1;
            return .{ .secret = .{ .bearer_token = try alloc.dupe(u8, "fallback-identity") } };
        }
    };

    const sp = StoredCredentialProvider.init(store.backend(), .{});
    var spy: FallbackSpy = .{};
    const providers = [_]cp.Provider{
        sp.provider(),
        .{ .name = "fallback-spy", .ctx = &spy, .getFn = FallbackSpy.get },
    };
    const chain: cp.ProviderChain = .{ .providers = &providers };

    var target = try cp.Target.parseAlloc(gpa, "https://ghcr.io", .{});
    defer target.deinit(gpa);

    // 1. Missing credential -> CredentialNotFound (chain advances to fallback).
    {
        var fb = try chain.get(gpa, .{ .target = target });
        defer fb.deinit(gpa);
        try testing.expectEqualStrings("fallback-identity", fb.secret.bearer_token);
        try testing.expectEqual(@as(usize, 1), spy.called);
    }
    spy.called = 0;

    // 2. Expired credential -> ReauthenticationRequired (chain MUST NOT fall back!).
    TestClock.current_ms = 1_000_000; // 1_000s
    {
        var exp_in: cp.CredentialResult = .{
            .secret = .{ .bearer_token = try gpa.dupe(u8, "short-lived-tok") },
            .expires_at = 1_500,
            .cache_policy = .until_expiration,
        };
        defer exp_in.deinit(gpa);

        var saved = try sp.login(gpa, .{
            .request = .{
                .target = target,
                .operation = .login,
                .deadline = .{ .now_ms_fn = TestClock.nowMs },
            },
            .credential = &exp_in,
        });
        defer saved.deinit(gpa);
    }

    TestClock.current_ms = 1_500_000; // 1_500s == expires_at
    try testing.expectError(
        error.ReauthenticationRequired,
        chain.get(gpa, .{
            .target = target,
            .deadline = .{ .now_ms_fn = TestClock.nowMs },
        }),
    );
    try testing.expectEqual(@as(usize, 0), spy.called);

    // 3. StorageUnavailable, StorageLocked, and AccessDenied halt ProviderChain immediately.
    const backend_errors = [_]cp.ProviderError{
        error.StorageUnavailable,
        error.StorageLocked,
        error.AccessDenied,
    };
    for (backend_errors) |be_err| {
        store.available_err = be_err;
        try testing.expectError(
            be_err,
            chain.get(gpa, .{
                .target = target,
                .deadline = .{ .now_ms_fn = TestClock.nowMs },
            }),
        );
        try testing.expectEqual(@as(usize, 0), spy.called);
    }
    store.available_err = null;

    // 4. Corrupt / invalid stored JSON envelopes return StorageFailure and halt ProviderChain.
    const corrupt_payloads = [_][]const u8{
        "",
        "{not-json",
        "[]",
        "123",
        "null",
        "{\"v\":null,\"username\":\"alice\",\"secret\":\"pw\"}",
        "{\"v\":2,\"kind\":\"basic\",\"username\":\"alice\",\"secret\":\"pw\",\"cache_policy\":\"eternal\"}",
        "{\"v\":0,\"kind\":\"basic\",\"username\":\"alice\",\"secret\":\"pw\",\"cache_policy\":\"eternal\"}",
        "{\"v\":\"1\",\"kind\":\"basic\",\"username\":\"alice\",\"secret\":\"pw\",\"cache_policy\":\"eternal\"}",
        "{\"v\":1,\"kind\":\"oauth\",\"secret\":\"pw\",\"cache_policy\":\"eternal\"}",
        "{\"v\":1,\"kind\":\"basic\",\"secret\":\"pw\",\"cache_policy\":\"eternal\"}",
        "{\"v\":1,\"kind\":\"basic\",\"username\":\"\",\"secret\":\"pw\",\"cache_policy\":\"eternal\"}",
        "{\"v\":1,\"kind\":\"bearer_token\",\"username\":\"alice\",\"secret\":\"pw\",\"cache_policy\":\"eternal\"}",
        "{\"v\":1,\"kind\":\"identity_token\",\"username\":\"alice\",\"secret\":\"pw\",\"cache_policy\":\"eternal\"}",
        "{\"v\":1,\"kind\":\"bearer_token\",\"secret\":\"\",\"cache_policy\":\"eternal\"}",
        "{\"v\":1,\"kind\":\"bearer_token\",\"secret\":\"pw\",\"cache_policy\":\"session\"}",
        "{\"v\":1,\"kind\":\"bearer_token\",\"secret\":\"pw\",\"cache_policy\":\"never\"}",
        "{\"v\":1,\"kind\":\"bearer_token\",\"secret\":\"pw\",\"cache_policy\":\"until_expiration\"}",
        "{\"v\":1,\"kind\":\"bearer_token\",\"secret\":\"pw\",\"cache_policy\":\"eternal\",\"scopes\":[\"ok\",\"\"]}",
        "{\"username\":\"\",\"secret\":\"pw\"}",
        "{\"username\":\"alice\",\"secret\":\"\"}",
        "{\"kind\":\"basic\",\"username\":\"alice\",\"secret\":\"pw\"}",
    };
    for (corrupt_payloads) |bad_json| {
        try store.putRaw("credential-provider://https/ghcr.io", "default", bad_json);
        try testing.expectError(
            error.StorageFailure,
            chain.get(gpa, .{
                .target = target,
                .deadline = .{ .now_ms_fn = TestClock.nowMs },
            }),
        );
        try testing.expectEqual(@as(usize, 0), spy.called);
    }

    // Restore valid non-expired record to test cancellation and deadline expiry.
    try store.putRaw(
        "credential-provider://https/ghcr.io",
        "default",
        "{\"v\":1,\"kind\":\"bearer_token\",\"secret\":\"valid-tok\",\"cache_policy\":\"eternal\"}",
    );

    // 5. Cancellation and expired deadline (both pre-flight and mid-flight).
    var cancelled = std.atomic.Value(bool).init(true);
    try testing.expectError(
        error.Cancelled,
        chain.get(gpa, .{
            .target = target,
            .deadline = .{
                .now_ms_fn = TestClock.nowMs,
                .deadline_ms = 1_000, // also expired, Cancelled takes precedence
                .cancelled = &cancelled,
            },
        }),
    );
    try testing.expectEqual(@as(usize, 0), spy.called);

    cancelled.store(false, .release);
    TestClock.current_ms = 2_000_000;
    try testing.expectError(
        error.DeadlineExceeded,
        chain.get(gpa, .{
            .target = target,
            .deadline = .{
                .now_ms_fn = TestClock.nowMs,
                .deadline_ms = 2_000_000,
                .cancelled = &cancelled,
            },
        }),
    );

    // Mid-operation deadline expiration after persistence read completes.
    TestClock.current_ms = 2_000_000;
    store.advance_ms_on_get = 500;
    try testing.expectError(
        error.DeadlineExceeded,
        sp.get(gpa, .{
            .target = target,
            .deadline = .{
                .now_ms_fn = TestClock.nowMs,
                .deadline_ms = 2_000_250,
            },
        }),
    );
    try testing.expectEqual(@as(usize, 0), spy.called);
}

test "mapKeyringError and KeyringPersistence enforce secure backend requirements" {
    const gpa = testing.allocator;

    // Verify exhaustive keyring_zig.Error -> cp.ProviderError mapping.
    try testing.expectEqual(cp.ProviderError.CredentialNotFound, mapKeyringError(error.EntryNotFound));
    try testing.expectEqual(cp.ProviderError.StorageLocked, mapKeyringError(error.Locked));
    try testing.expectEqual(cp.ProviderError.StorageUnavailable, mapKeyringError(error.NoStorageAccess));
    try testing.expectEqual(cp.ProviderError.InvalidInput, mapKeyringError(error.InputTooLong));
    try testing.expectEqual(cp.ProviderError.InvalidInput, mapKeyringError(error.InvalidUtf8));
    try testing.expectEqual(cp.ProviderError.OutOfMemory, mapKeyringError(error.OutOfMemory));
    try testing.expectEqual(cp.ProviderError.StorageFailure, mapKeyringError(error.PlatformFailure));
    try testing.expectEqual(cp.ProviderError.StorageFailure, mapKeyringError(error.Ambiguous));
    try testing.expectEqual(cp.ProviderError.StorageFailure, mapKeyringError(error.BufferTooSmall));

    const prev_backend = keyring_zig.currentBackend();
    defer keyring_zig.setDefaultBackend(prev_backend) catch {};
    defer {
        is_app_backend_disallowed_fn = null;
        env_override_fn = null;
    }

    const EnvMock = struct {
        var file_path: ?[]const u8 = null;
        var prop_file_path: ?[]const u8 = null;
        var passphrase: ?[]const u8 = null;
        var backend_name: ?[]const u8 = null;
        var local_appdata: ?[]const u8 = null;
        var user_profile: ?[]const u8 = null;
        var xdg_data_home: ?[]const u8 = null;
        var home: ?[]const u8 = null;
        var collection: ?[]const u8 = null;

        fn reset() void {
            file_path = null;
            prop_file_path = null;
            passphrase = null;
            backend_name = null;
            local_appdata = null;
            user_profile = null;
            xdg_data_home = null;
            home = null;
            collection = null;
        }

        fn get(name: []const u8) ?[]const u8 {
            if (std.mem.eql(u8, name, "KEYRING_FILE_PATH")) return file_path;
            if (std.mem.eql(u8, name, "KEYRING_PROPERTY_FILE_PATH")) return prop_file_path;
            if (std.mem.eql(u8, name, "KEYRING_FILE_PASSPHRASE")) return passphrase;
            if (std.mem.eql(u8, name, "KEYRING_BACKEND")) return backend_name;
            if (std.mem.eql(u8, name, "LOCALAPPDATA")) return local_appdata;
            if (std.mem.eql(u8, name, "USERPROFILE")) return user_profile;
            if (std.mem.eql(u8, name, "XDG_DATA_HOME")) return xdg_data_home;
            if (std.mem.eql(u8, name, "HOME")) return home;
            if (std.mem.eql(u8, name, "KEYRING_PROPERTY_COLLECTION")) return collection;
            return null;
        }
    };
    EnvMock.reset();
    env_override_fn = EnvMock.get;

    // 1. `null_backend` (--disable / KEYRING_BACKEND=null) -> StorageUnavailable.
    try keyring_zig.setDefaultBackend(.null_backend);
    try testing.expectError(error.StorageUnavailable, checkSecureBackendAvailable(gpa));

    var target = try cp.Target.parseAlloc(gpa, "https://github.com", .{});
    defer target.deinit(gpa);
    const default_sp = StoredCredentialProvider.initDefault();
    try testing.expectError(error.StorageUnavailable, default_sp.get(gpa, .{ .target = target }));

    // 2. Unconfigured `.file` backend -> StorageUnavailable when path or passphrase is missing/empty.
    var file_backend_active = false;
    if (@hasField(keyring_zig.Backend, "file")) {
        if (keyring_zig.setDefaultBackend(.file)) |_| {
            file_backend_active = true;
            try testing.expectError(error.StorageUnavailable, checkSecureBackendAvailable(gpa));

            // Explicit path without passphrase fails.
            EnvMock.file_path = "vault.enc";
            EnvMock.passphrase = null;
            try testing.expectError(error.StorageUnavailable, checkSecureBackendAvailable(gpa));

            EnvMock.file_path = "vault.enc";
            EnvMock.passphrase = "";
            try testing.expectError(error.StorageUnavailable, checkSecureBackendAvailable(gpa));

            // Passphrase without explicit path AND without platform default base dir fails.
            EnvMock.reset();
            EnvMock.passphrase = "correct-horse-battery-staple";
            try testing.expectError(error.StorageUnavailable, checkSecureBackendAvailable(gpa));

            // Platform-exact default path resolution matches keyring-file.zig:
            // Windows requires LOCALAPPDATA (ignores USERPROFILE); macOS requires HOME (ignores XDG_DATA_HOME);
            // Linux accepts absolute XDG_DATA_HOME or HOME.
            EnvMock.reset();
            EnvMock.user_profile = "C:\\Users\\test";
            try testing.expect(!(try hasConfiguredFileBackendPathForOs(gpa, .windows)));
            EnvMock.local_appdata = "C:\\Users\\test\\AppData\\Local";
            try testing.expect(try hasConfiguredFileBackendPathForOs(gpa, .windows));

            EnvMock.reset();
            EnvMock.xdg_data_home = "/Users/test/.local/share";
            try testing.expect(!(try hasConfiguredFileBackendPathForOs(gpa, .macos)));
            try testing.expect(try hasConfiguredFileBackendPathForOs(gpa, .linux));
            EnvMock.home = "/Users/test";
            try testing.expect(try hasConfiguredFileBackendPathForOs(gpa, .macos));

            // Platform default base dir + passphrase succeeds!
            EnvMock.local_appdata = "C:\\Users\\test\\AppData\\Local";
            EnvMock.home = "/home/test";
            EnvMock.passphrase = "correct-horse-battery-staple";
            try checkSecureBackendAvailable(gpa);

            // Empty/whitespace KEYRING_FILE_PATH="" fails even when default base dir is present.
            EnvMock.file_path = "";
            try testing.expectError(error.StorageUnavailable, checkSecureBackendAvailable(gpa));
            EnvMock.file_path = "   ";
            try testing.expectError(error.StorageUnavailable, checkSecureBackendAvailable(gpa));

            // KEYRING_PROPERTY_FILE_PATH without KEYRING_FILE_PATH fails so callers never silently
            // fall back to default store.bin when expecting KEYRING_PROPERTY_FILE_PATH to apply.
            EnvMock.file_path = null;
            EnvMock.prop_file_path = "prop-vault.enc";
            try testing.expectError(error.StorageUnavailable, checkSecureBackendAvailable(gpa));

            // 3. Configured `.file` backend (non-empty KEYRING_FILE_PATH + non-empty passphrase) -> passes!
            EnvMock.prop_file_path = null;
            EnvMock.file_path = "vault.enc";
            EnvMock.passphrase = "correct-horse-battery-staple";
            try checkSecureBackendAvailable(gpa);
        } else |err| switch (err) {
            error.BackendUnavailable => {},
        }
    }

    if (!file_backend_active) {
        var avail_buf: [5]keyring_zig.Backend = undefined;
        for (keyring_zig.availableBackends(&avail_buf)) |candidate| {
            if (candidate != .null_backend) {
                try keyring_zig.setDefaultBackend(candidate);
                break;
            }
        }
    }

    // 4. Forced `ado` backend via `is_app_backend_disallowed_fn` OR `KEYRING_BACKEND=ado` -> StorageUnavailable.
    const DisallowHook = struct {
        fn disallowed() bool {
            return true;
        }
        fn allowed() bool {
            return false;
        }
    };
    is_app_backend_disallowed_fn = DisallowHook.disallowed;
    try testing.expectError(error.StorageUnavailable, checkSecureBackendAvailable(gpa));

    is_app_backend_disallowed_fn = DisallowHook.allowed;
    try checkSecureBackendAvailable(gpa);

    is_app_backend_disallowed_fn = null;
    EnvMock.backend_name = "ado";
    try testing.expectError(error.StorageUnavailable, checkSecureBackendAvailable(gpa));
    EnvMock.backend_name = null;

    // 5. KeyringOpsAdapter maps raw keyring operations cleanly and honors enforce_secure_backend.
    const MockRawKeyring = struct {
        var last_service: ?[]const u8 = null;
        fn getAlloc(alloc: Allocator, service: []const u8, _: []const u8) keyring_zig.Error![]u8 {
            last_service = service;
            return alloc.dupe(u8, "{\"username\":\"alice\",\"secret\":\"tok\"}") catch error.OutOfMemory;
        }
        fn setAlloc(_: Allocator, _: []const u8, _: []const u8, _: []const u8) keyring_zig.Error!void {}
        fn deleteAlloc(_: Allocator, _: []const u8, _: []const u8) keyring_zig.Error!void {
            return error.Locked;
        }
    };

    const adapter: KeyringOpsAdapter = .{
        .ops = .{
            .get = MockRawKeyring.getAlloc,
            .set = MockRawKeyring.setAlloc,
            .delete = MockRawKeyring.deleteAlloc,
        },
        .enforce_secure_backend = true,
    };
    const adapted_sp = StoredCredentialProvider.init(adapter.backend(), .{});
    var loaded = try adapted_sp.get(gpa, .{ .target = target });
    defer loaded.deinit(gpa);
    try testing.expectEqualStrings("alice", loaded.secret.basic.username);
    try testing.expectError(
        error.StorageLocked,
        adapted_sp.logout(gpa, .{ .target = target, .operation = .logout }),
    );
}

test "StoredCredentialProvider isolates multi-account slots, enforces single-slot matching, and reads legacy v0 records" {
    const gpa = testing.allocator;

    // 1. Multi-account isolation (`account = null` vs `"alice"` vs `"bob"` vs literal `"default"`).
    {
        var store = FakePersistence.init(gpa);
        defer store.deinit();

        const sp = StoredCredentialProvider.init(store.backend(), .{});
        var target = try cp.Target.parseAlloc(gpa, "https://github.com", .{});
        defer target.deinit(gpa);

        const accounts = [_]struct {
            account: ?[]const u8,
            token: []const u8,
            expected_slot: []const u8,
        }{
            .{ .account = null, .token = "tok-unnamed", .expected_slot = "default" },
            .{ .account = "alice", .token = "tok-alice", .expected_slot = "account:alice" },
            .{ .account = "bob", .token = "tok-bob", .expected_slot = "account:bob" },
            .{ .account = "default", .token = "tok-literal-default", .expected_slot = "account:default" },
        };

        for (accounts) |entry| {
            var cred: cp.CredentialResult = .{
                .secret = .{ .bearer_token = try gpa.dupe(u8, entry.token) },
                .account = if (entry.account) |a| try gpa.dupe(u8, a) else null,
            };
            defer cred.deinit(gpa);

            var saved = try sp.login(gpa, .{
                .request = .{ .target = target, .operation = .login, .account = entry.account },
                .credential = &cred,
            });
            defer saved.deinit(gpa);

            try testing.expect(store.rawAt("credential-provider://https/github.com", entry.expected_slot) != null);
        }
        try testing.expectEqual(@as(usize, 4), store.count());

        for (accounts) |entry| {
            var got = try sp.get(gpa, .{ .target = target, .account = entry.account });
            defer got.deinit(gpa);
            try testing.expectEqualStrings(entry.token, got.secret.bearer_token);
            if (entry.account) |expected_acc| {
                try testing.expectEqualStrings(expected_acc, got.account.?);
            } else {
                try testing.expectEqual(@as(?[]u8, null), got.account);
            }
        }

        // Erasing unnamed `null` slot does NOT erase literal `"default"`, `"alice"`, or `"bob"`.
        try sp.logout(gpa, .{ .target = target, .operation = .logout, .account = null });
        try testing.expectError(error.CredentialNotFound, sp.get(gpa, .{ .target = target, .account = null }));

        var literal_default = try sp.get(gpa, .{ .target = target, .account = "default" });
        defer literal_default.deinit(gpa);
        try testing.expectEqualStrings("tok-literal-default", literal_default.secret.bearer_token);

        var alice_still = try sp.get(gpa, .{ .target = target, .account = "alice" });
        defer alice_still.deinit(gpa);
        try testing.expectEqualStrings("tok-alice", alice_still.secret.bearer_token);
    }

    // 2. Single-slot container-registry mode (`initContainerRegistry`) account matching & legacy v0 decoding.
    {
        var store = FakePersistence.init(gpa);
        defer store.deinit();

        const reg_sp = StoredCredentialProvider.initContainerRegistry(store.backend());
        var target = try cp.Target.parseAlloc(gpa, "https://ghcr.io", .{});
        defer target.deinit(gpa);

        // Legacy v0 basic credential written by `keyring podman` / `docker-credential-keyring`.
        try store.putRaw("container-registry://ghcr.io", "default", "{\"username\":\"octocat\",\"secret\":\"ghp_123\"}");

        var v0_any = try reg_sp.get(gpa, .{ .target = target });
        defer v0_any.deinit(gpa);
        try testing.expectEqual(cp.CredentialKind.basic, v0_any.secret.kind());
        try testing.expectEqualStrings("octocat", v0_any.secret.basic.username);
        try testing.expectEqualStrings("ghp_123", v0_any.secret.basic.secret);
        try testing.expectEqual(@as(?[]u8, null), v0_any.account);
        try testing.expectEqual(@as(?i64, null), v0_any.expires_at);
        try testing.expectEqual(cp.CachePolicy.eternal, v0_any.cache_policy);
        try testing.expectEqual(@as(?[]u8, null), v0_any.audience);
        try testing.expectEqual(@as(?[][]u8, null), v0_any.scopes);
        try testing.expect(!v0_any.supports_noninteractive_renewal);

        // Account match succeeds for `"octocat"` and returns CredentialNotFound for `"bob"`.
        var v0_match = try reg_sp.get(gpa, .{ .target = target, .account = "octocat" });
        defer v0_match.deinit(gpa);
        try testing.expectEqualStrings("ghp_123", v0_match.secret.basic.secret);

        try testing.expectError(
            error.CredentialNotFound,
            reg_sp.get(gpa, .{ .target = target, .account = "bob" }),
        );

        // Logout for `"bob"` refuses to delete `"octocat"`'s credential!
        try testing.expectError(
            error.CredentialNotFound,
            reg_sp.logout(gpa, .{ .target = target, .operation = .logout, .account = "bob" }),
        );
        try testing.expectEqual(@as(usize, 1), store.count());

        // Logout for `"octocat"` deletes it cleanly.
        try reg_sp.logout(gpa, .{ .target = target, .operation = .logout, .account = "octocat" });
        try testing.expectEqual(@as(usize, 0), store.count());

        // Legacy v0 `<token>` sentinel decodes as `.identity_token` without invented metadata.
        try store.putRaw("container-registry://ghcr.io", "default", "{\"username\":\"<token>\",\"secret\":\"jwt\"}");

        var v0_tok = try reg_sp.get(gpa, .{ .target = target });
        defer v0_tok.deinit(gpa);
        try testing.expectEqual(cp.CredentialKind.identity_token, v0_tok.secret.kind());
        try testing.expectEqualStrings("jwt", v0_tok.secret.identity_token);
        try testing.expectEqual(@as(?[]u8, null), v0_tok.account);
        try testing.expectEqual(@as(?i64, null), v0_tok.expires_at);
        try testing.expectEqual(cp.CachePolicy.eternal, v0_tok.cache_policy);
        try testing.expectEqual(@as(?[]u8, null), v0_tok.audience);
        try testing.expectEqual(@as(?[][]u8, null), v0_tok.scopes);
        try testing.expect(!v0_tok.supports_noninteractive_renewal);

        // Because v0 `<token>` has no real account, requesting a named account returns CredentialNotFound.
        try testing.expectError(
            error.CredentialNotFound,
            reg_sp.get(gpa, .{ .target = target, .account = "alice" }),
        );

        // V1 single-slot login for `"alice"` replaces `<token>`, rejects `"bob"` on get/logout, and deletes `"alice"`.
        var v1_alice: cp.CredentialResult = .{
            .secret = .{ .identity_token = try gpa.dupe(u8, "alice-registry-jwt") },
            .account = try gpa.dupe(u8, "alice"),
        };
        defer v1_alice.deinit(gpa);

        var v1_saved = try reg_sp.login(gpa, .{
            .request = .{ .target = target, .operation = .login, .account = "alice" },
            .credential = &v1_alice,
        });
        defer v1_saved.deinit(gpa);

        try testing.expectError(
            error.CredentialNotFound,
            reg_sp.get(gpa, .{ .target = target, .account = "bob" }),
        );
        try testing.expectError(
            error.CredentialNotFound,
            reg_sp.logout(gpa, .{ .target = target, .operation = .logout, .account = "bob" }),
        );

        var alice_got = try reg_sp.get(gpa, .{ .target = target, .account = "alice" });
        defer alice_got.deinit(gpa);
        try testing.expectEqualStrings("alice-registry-jwt", alice_got.secret.identity_token);

        try reg_sp.logout(gpa, .{ .target = target, .operation = .logout, .account = "alice" });
        try testing.expectEqual(@as(usize, 0), store.count());
    }
}

test "StoredCredentialProvider is leak-free across all allocation failure points" {
    const gpa = testing.allocator;

    const scopes_seed = try gpa.alloc([]u8, 2);
    scopes_seed[0] = try gpa.dupe(u8, "repo");
    scopes_seed[1] = try gpa.dupe(u8, "write:packages");
    var seed: cp.CredentialResult = .{
        .secret = .{
            .basic = .{
                .username = try gpa.dupe(u8, "alice"),
                .secret = try gpa.dupe(u8, "s3cr3t_value"),
            },
        },
        .account = try gpa.dupe(u8, "alice"),
        .expires_at = 2_000_000_000,
        .cache_policy = .until_expiration,
        .audience = try gpa.dupe(u8, "https://packages.example.com"),
        .scopes = scopes_seed,
    };
    defer seed.deinit(gpa);

    const OomHarness = struct {
        fn run(alloc: Allocator, backing_gpa: Allocator, cred_seed: *const cp.CredentialResult) !void {
            TestClock.current_ms = 1_700_000_000_000;
            var store = FakePersistence.init(backing_gpa);
            defer store.deinit();

            const sp = StoredCredentialProvider.init(store.backend(), .{});
            var target = try cp.Target.parseAlloc(alloc, "https://packages.example.com:8443", .{});
            defer target.deinit(alloc);

            var saved = try sp.login(alloc, .{
                .request = .{
                    .target = target,
                    .operation = .login,
                    .account = "alice",
                    .deadline = .{ .now_ms_fn = TestClock.nowMs },
                },
                .credential = cred_seed,
            });
            saved.deinit(alloc);

            var got = try sp.get(alloc, .{
                .target = target,
                .account = "alice",
                .deadline = .{ .now_ms_fn = TestClock.nowMs },
            });
            got.deinit(alloc);

            try sp.logout(alloc, .{
                .target = target,
                .operation = .logout,
                .account = "alice",
                .deadline = .{ .now_ms_fn = TestClock.nowMs },
            });
        }
    };

    try testing.checkAllAllocationFailures(gpa, OomHarness.run, .{ gpa, &seed });
}

test "StoredCredentialProvider unnamed slot round-trip with credential account metadata and PersistenceOptions forwarding" {
    const gpa = testing.allocator;
    var store = FakePersistence.init(gpa);
    defer store.deinit();

    const sp = StoredCredentialProvider.init(store.backend(), .{});
    var target = try cp.Target.parseAlloc(gpa, "https://github.com", .{});
    defer target.deinit(gpa);

    var cred_in: cp.CredentialResult = .{
        .secret = .{
            .basic = .{
                .username = try gpa.dupe(u8, "octocat"),
                .secret = try gpa.dupe(u8, "ghp_default_slot"),
            },
        },
        .account = try gpa.dupe(u8, "octocat"),
    };
    defer cred_in.deinit(gpa);

    // Storing with request.account = null and cred.account = "octocat" writes to the unnamed
    // "default" slot while preserving "octocat" in the stored v1 envelope metadata.
    var saved = try sp.login(gpa, .{
        .request = .{
            .target = target,
            .operation = .login,
            .account = null,
            .interaction = .if_available,
        },
        .credential = &cred_in,
    });
    defer saved.deinit(gpa);
    try testing.expectEqual(cp.InteractionPolicy.if_available, store.last_interaction.?);
    try testing.expect(store.rawAt("credential-provider://https/github.com", "default") != null);
    try testing.expect(store.rawAt("credential-provider://https/github.com", "account:octocat") == null);

    // Retrieval ALWAYS passes InteractionPolicy.never to PersistenceBackend and finds the
    // unnamed slot when request.account == null.
    var got = try sp.get(gpa, .{
        .target = target,
        .account = null,
        .interaction = .always,
    });
    defer got.deinit(gpa);
    try testing.expectEqual(cp.InteractionPolicy.never, store.last_interaction.?);
    try testing.expectEqualStrings("octocat", got.account.?);
    try testing.expectEqualStrings("octocat", got.secret.basic.username);
    try testing.expectEqualStrings("ghp_default_slot", got.secret.basic.secret);

    // Logout with request.account == null removes the unnamed slot cleanly.
    try sp.logout(gpa, .{
        .target = target,
        .operation = .logout,
        .account = null,
        .interaction = .always,
    });
    try testing.expectEqual(cp.InteractionPolicy.always, store.last_interaction.?);
    try testing.expectEqual(@as(usize, 0), store.count());
    try testing.expectError(error.CredentialNotFound, sp.get(gpa, .{ .target = target, .account = null }));
}

test "StoredCredentialProvider enforces audience and scopes matching on login and get" {
    const gpa = testing.allocator;
    var store = FakePersistence.init(gpa);
    defer store.deinit();

    const sp = StoredCredentialProvider.init(store.backend(), .{});
    var target = try cp.Target.parseAlloc(gpa, "https://api.example.com", .{});
    defer target.deinit(gpa);

    // 1. Unknown audience/scopes (`null`): login rejects non-empty request.scopes; get rejects
    // non-null request.audience or non-empty request.scopes with CredentialNotFound.
    {
        var unknown_cred: cp.CredentialResult = .{
            .secret = .{ .bearer_token = try gpa.dupe(u8, "opaque-tok") },
            .audience = null,
            .scopes = null,
        };
        defer unknown_cred.deinit(gpa);

        try testing.expectError(
            error.InvalidInput,
            sp.login(gpa, .{
                .request = .{
                    .target = target,
                    .operation = .login,
                    .scopes = &.{"read:packages"},
                },
                .credential = &unknown_cred,
            }),
        );

        var saved = try sp.login(gpa, .{
            .request = .{ .target = target, .operation = .login },
            .credential = &unknown_cred,
        });
        defer saved.deinit(gpa);

        // Unconstrained get succeeds.
        var got_any = try sp.get(gpa, .{ .target = target });
        defer got_any.deinit(gpa);
        try testing.expectEqualStrings("opaque-tok", got_any.secret.bearer_token);

        // Requesting audience when stored audience == null -> CredentialNotFound.
        try testing.expectError(
            error.CredentialNotFound,
            sp.get(gpa, .{ .target = target, .audience = "https://api.example.com" }),
        );

        // Requesting scopes when stored scopes == null -> CredentialNotFound.
        try testing.expectError(
            error.CredentialNotFound,
            sp.get(gpa, .{ .target = target, .scopes = &.{"read:packages"} }),
        );
    }

    // 2. Populated audience and scopes: validate login conflicts and get subset/superset/mismatch.
    {
        const scopes_buf = try gpa.alloc([]u8, 3);
        scopes_buf[0] = try gpa.dupe(u8, "repo");
        scopes_buf[1] = try gpa.dupe(u8, "read:packages");
        scopes_buf[2] = try gpa.dupe(u8, "write:packages");

        var scoped_cred: cp.CredentialResult = .{
            .secret = .{ .bearer_token = try gpa.dupe(u8, "scoped-tok") },
            .audience = try gpa.dupe(u8, "https://api.example.com"),
            .scopes = scopes_buf,
        };
        defer scoped_cred.deinit(gpa);

        // Conflicting audience on login -> InvalidInput.
        try testing.expectError(
            error.InvalidInput,
            sp.login(gpa, .{
                .request = .{
                    .target = target,
                    .operation = .login,
                    .audience = "https://other.example.com",
                },
                .credential = &scoped_cred,
            }),
        );

        // Missing requested scope on login -> InvalidInput.
        try testing.expectError(
            error.InvalidInput,
            sp.login(gpa, .{
                .request = .{
                    .target = target,
                    .operation = .login,
                    .scopes = &.{ "repo", "admin:org" },
                },
                .credential = &scoped_cred,
            }),
        );

        // Matching audience and subset of scopes on login -> succeeds.
        var saved = try sp.login(gpa, .{
            .request = .{
                .target = target,
                .operation = .login,
                .audience = "https://api.example.com",
                .scopes = &.{ "read:packages", "repo" },
            },
            .credential = &scoped_cred,
        });
        defer saved.deinit(gpa);

        // Audience mismatch on get -> CredentialNotFound.
        try testing.expectError(
            error.CredentialNotFound,
            sp.get(gpa, .{
                .target = target,
                .audience = "https://wrong.example.com",
            }),
        );

        // Scope superset / missing scope on get -> CredentialNotFound.
        try testing.expectError(
            error.CredentialNotFound,
            sp.get(gpa, .{
                .target = target,
                .scopes = &.{ "repo", "admin:org" },
            }),
        );

        // Exact audience + scope subset on get -> succeeds!
        var got_subset = try sp.get(gpa, .{
            .target = target,
            .audience = "https://api.example.com",
            .scopes = &.{ "write:packages", "repo" },
        });
        defer got_subset.deinit(gpa);
        try testing.expectEqualStrings("scoped-tok", got_subset.secret.bearer_token);
    }
}

test "Secret Service D-Bus preflight classifies missing daemon, locked collection, NoSuchObject, and AccessDenied" {
    const gpa = testing.allocator;
    defer env_override_fn = null;

    const FakeBus = struct {
        has_owner: bool = true,
        activatable: bool = false,
        owner_err: ?[]const u8 = null,
        locked: bool = false,
        prop_err: ?[]const u8 = null,
        alias_prop_err: ?[]const u8 = null,
        read_alias_path: []const u8 = "/",
        saw_collection_path: ?[]u8 = null,
        prop_calls: usize = 0,

        fn deinit(self: *@This(), alloc: Allocator) void {
            if (self.saw_collection_path) |p| alloc.free(p);
        }

        fn call(
            ctx: ?*anyopaque,
            alloc: Allocator,
            req: DbusPreflightCallReq,
        ) cp.ProviderError!DbusPreflightReply {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));

            if (std.mem.eql(u8, req.member, "NameHasOwner")) {
                if (self.owner_err) |e| {
                    return .{
                        .body = try alloc.alloc(u8, 0),
                        .err_name = try alloc.dupe(u8, e),
                    };
                }
                var out: std.ArrayList(u8) = .empty;
                defer out.deinit(alloc);
                var w = dbus.wire.Writer.init(alloc, &out);
                try w.writeBool(self.has_owner);
                return .{ .body = try alloc.dupe(u8, out.items) };
            }

            if (std.mem.eql(u8, req.member, "ListActivatableNames")) {
                var out: std.ArrayList(u8) = .empty;
                defer out.deinit(alloc);
                var w = dbus.wire.Writer.init(alloc, &out);
                const arr = try w.beginArray(4);
                try w.writeString("org.freedesktop.DBus");
                if (self.activatable) {
                    try w.writeString("org.freedesktop.secrets");
                }
                w.endArray(arr);
                return .{ .body = try alloc.dupe(u8, out.items) };
            }

            if (std.mem.eql(u8, req.member, "ReadAlias") and
                std.mem.eql(u8, req.interface, "org.freedesktop.Secret.Service"))
            {
                var out: std.ArrayList(u8) = .empty;
                defer out.deinit(alloc);
                var w = dbus.wire.Writer.init(alloc, &out);
                try w.writeObjectPath(self.read_alias_path);
                return .{ .body = try alloc.dupe(u8, out.items) };
            }

            if (std.mem.eql(u8, req.member, "Get") and
                std.mem.eql(u8, req.interface, "org.freedesktop.DBus.Properties"))
            {
                self.prop_calls += 1;
                if (self.saw_collection_path) |old| alloc.free(old);
                self.saw_collection_path = try alloc.dupe(u8, req.path);

                if (std.mem.eql(u8, req.path, "/org/freedesktop/secrets/aliases/default")) {
                    if (self.alias_prop_err) |e| {
                        return .{
                            .body = try alloc.alloc(u8, 0),
                            .err_name = try alloc.dupe(u8, e),
                        };
                    }
                }
                if (self.prop_err) |e| {
                    return .{
                        .body = try alloc.alloc(u8, 0),
                        .err_name = try alloc.dupe(u8, e),
                    };
                }
                var out: std.ArrayList(u8) = .empty;
                defer out.deinit(alloc);
                var w = dbus.wire.Writer.init(alloc, &out);
                try w.writeSignatureValue("b");
                try w.writeBool(self.locked);
                return .{ .body = try alloc.dupe(u8, out.items) };
            }

            return error.StorageFailure;
        }
    };

    const ColEnv = struct {
        var collection: ?[]const u8 = null;
        var display: ?[]const u8 = null;
        var noninteractive: ?[]const u8 = null;
        fn reset() void {
            collection = null;
            display = null;
            noninteractive = null;
        }
        fn get(name: []const u8) ?[]const u8 {
            if (std.mem.eql(u8, name, "KEYRING_PROPERTY_COLLECTION")) return collection;
            if (std.mem.eql(u8, name, "DISPLAY")) return display;
            if (std.mem.eql(u8, name, "KEYRING_NONINTERACTIVE")) return noninteractive;
            return null;
        }
    };
    ColEnv.reset();
    env_override_fn = ColEnv.get;

    // 1. Bus exists, no owner and not activatable -> StorageUnavailable.
    {
        var bus: FakeBus = .{ .has_owner = false, .activatable = false };
        defer bus.deinit(gpa);
        try testing.expectError(
            error.StorageUnavailable,
            runSecretServicePreflightWithCaller(gpa, .{ .interaction = .never }, &bus, FakeBus.call),
        );
        try testing.expectEqual(@as(usize, 0), bus.prop_calls);
    }

    // 2. Activatable service + Locked == true under InteractionPolicy.never -> StorageLocked without calling keyring_zig.
    {
        var bus: FakeBus = .{ .has_owner = false, .activatable = true, .locked = true };
        defer bus.deinit(gpa);
        try testing.expectError(
            error.StorageLocked,
            runSecretServicePreflightWithCaller(gpa, .{ .interaction = .never }, &bus, FakeBus.call),
        );
        try testing.expectEqual(@as(usize, 1), bus.prop_calls);
        try testing.expectEqualStrings("/org/freedesktop/secrets/aliases/default", bus.saw_collection_path.?);
    }

    // 3. InteractionPolicy.always and graphical .if_available skip preflight lock rejection,
    // while headless or KEYRING_NONINTERACTIVE=1 .if_available rejects locked collections!
    {
        var bus: FakeBus = .{ .has_owner = true, .locked = true };
        defer bus.deinit(gpa);
        try runSecretServicePreflightWithCaller(gpa, .{ .interaction = .always }, &bus, FakeBus.call);
        try testing.expectEqual(@as(usize, 0), bus.prop_calls);

        try testing.expectError(
            error.StorageLocked,
            runSecretServicePreflightWithCaller(gpa, .{ .interaction = .if_available }, &bus, FakeBus.call),
        );

        ColEnv.display = ":0";
        bus.prop_calls = 0;
        try runSecretServicePreflightWithCaller(gpa, .{ .interaction = .if_available }, &bus, FakeBus.call);
        try testing.expectEqual(@as(usize, 0), bus.prop_calls);

        ColEnv.noninteractive = "1";
        try testing.expectError(
            error.StorageLocked,
            runSecretServicePreflightWithCaller(gpa, .{ .interaction = .if_available }, &bus, FakeBus.call),
        );
        ColEnv.reset();
    }

    // 4. Non-default KEYRING_PROPERTY_COLLECTION fails closed with StorageUnavailable;
    // NoSuchObject on /aliases/default falls back to Service.ReadAlias("default").
    {
        ColEnv.collection = "login";
        var bus_bad_col: FakeBus = .{ .has_owner = true };
        defer bus_bad_col.deinit(gpa);
        try testing.expectError(
            error.StorageUnavailable,
            runSecretServicePreflightWithCaller(gpa, .{ .interaction = .never }, &bus_bad_col, FakeBus.call),
        );

        ColEnv.collection = "default";
        var bus_alias_locked: FakeBus = .{
            .has_owner = true,
            .locked = true,
            .alias_prop_err = "org.freedesktop.Secret.Error.NoSuchObject",
            .read_alias_path = "/org/freedesktop/secrets/collection/default",
        };
        defer bus_alias_locked.deinit(gpa);
        try testing.expectError(
            error.StorageLocked,
            runSecretServicePreflightWithCaller(gpa, .{ .interaction = .never }, &bus_alias_locked, FakeBus.call),
        );
        try testing.expectEqualStrings("/org/freedesktop/secrets/collection/default", bus_alias_locked.saw_collection_path.?);

        var bus_alias_absent: FakeBus = .{
            .has_owner = true,
            .locked = true,
            .alias_prop_err = "org.freedesktop.Secret.Error.NoSuchObject",
            .read_alias_path = "/",
        };
        defer bus_alias_absent.deinit(gpa);
        try runSecretServicePreflightWithCaller(gpa, .{ .interaction = .never }, &bus_alias_absent, FakeBus.call);
        ColEnv.reset();
    }

    // 5. D-Bus AccessDenied maps to error.AccessDenied.
    {
        ColEnv.collection = null;
        var bus1: FakeBus = .{ .owner_err = "org.freedesktop.DBus.Error.AccessDenied" };
        defer bus1.deinit(gpa);
        try testing.expectError(
            error.AccessDenied,
            runSecretServicePreflightWithCaller(gpa, .{ .interaction = .never }, &bus1, FakeBus.call),
        );

        var bus2: FakeBus = .{
            .has_owner = true,
            .prop_err = "org.freedesktop.DBus.Error.AccessDenied",
        };
        defer bus2.deinit(gpa);
        try testing.expectError(
            error.AccessDenied,
            runSecretServicePreflightWithCaller(gpa, .{ .interaction = .never }, &bus2, FakeBus.call),
        );
    }

    // 6. On Windows, PlatformFailure with ERROR_ACCESS_DENIED (5) maps to error.AccessDenied.
    if (builtin.os.tag == .windows) {
        const WinDenyOps = struct {
            fn getDenied(_: Allocator, _: []const u8, _: []const u8) keyring_zig.Error![]u8 {
                win32_err.SetLastError(win32_err.ERROR_ACCESS_DENIED);
                return error.PlatformFailure;
            }
            fn setNoop(_: Allocator, _: []const u8, _: []const u8, _: []const u8) keyring_zig.Error!void {}
            fn delNoop(_: Allocator, _: []const u8, _: []const u8) keyring_zig.Error!void {}
        };
        const adapter: KeyringOpsAdapter = .{
            .ops = .{
                .get = WinDenyOps.getDenied,
                .set = WinDenyOps.setNoop,
                .delete = WinDenyOps.delNoop,
            },
            .enforce_secure_backend = false,
        };
        var target = try cp.Target.parseAlloc(gpa, "https://github.com", .{});
        defer target.deinit(gpa);
        const sp = StoredCredentialProvider.init(adapter.backend(), .{});
        try testing.expectError(error.AccessDenied, sp.get(gpa, .{ .target = target }));
    }
}
