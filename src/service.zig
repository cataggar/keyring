const std = @import("std");
const builtin = @import("builtin");
const dbus = @import("dbus");
const vault = @import("vault.zig");

const Allocator = std.mem.Allocator;
const wire = dbus.wire;
const message = dbus.message;
const Aes128 = std.crypto.core.aes.Aes128;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

pub const service_destination = "org.freedesktop.secrets";
pub const service_path = "/org/freedesktop/secrets";
pub const collection_path = "/org/freedesktop/secrets/collection/default";
pub const collection_alias_path = "/org/freedesktop/secrets/aliases/default";
pub const prompt_locked_path = "/org/freedesktop/secrets/prompt/locked";
pub const dh_algorithm = "dh-ietf1024-sha256-aes128-cbc-pkcs7";
pub const managed_marker = "# Managed by cataggar/keyring";

const unsupported_platform_message = "keyring: built-in service is only supported on Linux\n";

pub const RunOptions = struct {
    replace: bool = false,
    lock_timeout_seconds: ?u32 = null,
};

pub const InstallOptions = struct {
    force: bool = false,
};

pub const UninstallOptions = struct {
    force: bool = false,
};

pub const Action = union(enum) {
    run: RunOptions,
    install: InstallOptions,
    uninstall: UninstallOptions,
    status,
};

pub const ServicePaths = struct {
    dbus_service_path: []u8,
    systemd_unit_path: []u8,

    pub fn deinit(self: *ServicePaths, gpa: Allocator) void {
        gpa.free(self.dbus_service_path);
        gpa.free(self.systemd_unit_path);
        self.* = undefined;
    }
};

pub fn parseArgs(args: []const []const u8) ?Action {
    if (args.len > 0) {
        if (std.mem.eql(u8, args[0], "install")) {
            var opts: InstallOptions = .{};
            for (args[1..]) |arg| {
                if (std.mem.eql(u8, arg, "--force")) {
                    opts.force = true;
                } else return null;
            }
            return .{ .install = opts };
        }
        if (std.mem.eql(u8, args[0], "uninstall")) {
            var opts: UninstallOptions = .{};
            for (args[1..]) |arg| {
                if (std.mem.eql(u8, arg, "--force")) {
                    opts.force = true;
                } else return null;
            }
            return .{ .uninstall = opts };
        }
        if (std.mem.eql(u8, args[0], "status")) {
            return if (args.len == 1) .status else null;
        }
    }

    var opts: RunOptions = .{};
    var index: usize = 0;
    while (index < args.len) {
        if (std.mem.eql(u8, args[index], "--replace")) {
            opts.replace = true;
            index += 1;
        } else if (std.mem.eql(u8, args[index], "--lock-timeout")) {
            if (index + 1 >= args.len) return null;
            const parsed = std.fmt.parseInt(u32, args[index + 1], 10) catch return null;
            if (parsed == 0) return null;
            opts.lock_timeout_seconds = parsed;
            index += 2;
        } else return null;
    }
    return .{ .run = opts };
}

const service_interface = "org.freedesktop.Secret.Service";
const collection_interface = "org.freedesktop.Secret.Collection";
const item_interface = "org.freedesktop.Secret.Item";
const session_interface = "org.freedesktop.Secret.Session";
const prompt_interface = "org.freedesktop.Secret.Prompt";
const properties_interface = "org.freedesktop.DBus.Properties";
const peer_interface = "org.freedesktop.DBus.Peer";
const introspectable_interface = "org.freedesktop.DBus.Introspectable";
const control_interface = "io.github.cataggar.Keyring1";
const generic_item_type = "org.freedesktop.Secret.Generic";

const DispatchError = error{
    InvalidArgs,
    IsLocked,
    NoSuchObject,
    NotSupported,
    UnknownInterface,
    UnknownMethod,
    UnknownProperty,
};

pub const ItemRecord = struct {
    id: []u8,
    label: []u8,
    secret: []u8,
    content_type: []u8,
    attributes: std.StringHashMapUnmanaged([]u8) = .empty,
    created: u64,
    modified: u64,
};

pub const Session = union(enum) {
    plain,
    dh_ietf: [16]u8,

    fn deinit(self: *Session) void {
        switch (self.*) {
            .plain => {},
            .dh_ietf => |*key| std.crypto.secureZero(u8, key),
        }
        self.* = .plain;
    }
};

pub const OutboundMessages = struct {
    gpa: Allocator,
    frames: std.ArrayListUnmanaged([]u8) = .empty,

    pub fn deinit(self: *OutboundMessages) void {
        for (self.frames.items) |frame| self.gpa.free(frame);
        self.frames.deinit(self.gpa);
        self.* = undefined;
    }
};

pub const Status = struct {
    initialized: bool,
    locked: bool,
    item_count: u32,
    store_path: []u8,

    pub fn deinit(self: *Status, gpa: Allocator) void {
        gpa.free(self.store_path);
        self.* = undefined;
    }
};

pub const ServiceState = struct {
    gpa: Allocator,
    unlocked: bool = false,
    dek: ?[vault.dek_len]u8 = null,
    store_id: ?[vault.store_id_len]u8 = null,
    items: std.ArrayListUnmanaged(ItemRecord) = .empty,
    next_item_id: u64 = 1,
    label: []u8,
    created: u64,
    modified: u64,
    sessions: std.AutoHashMapUnmanaged(u32, Session) = .empty,
    next_session_id: u32 = 1,
    next_serial: u32 = 1,

    pub fn init(gpa: Allocator) !ServiceState {
        const now = unixNow();
        return .{
            .gpa = gpa,
            .label = try gpa.dupe(u8, "Default"),
            .created = now,
            .modified = now,
        };
    }

    pub fn deinit(self: *ServiceState) void {
        self.lockAll();
        self.items.deinit(self.gpa);
        var sessions = self.sessions.valueIterator();
        while (sessions.next()) |session| session.deinit();
        self.sessions.deinit(self.gpa);
        self.gpa.free(self.label);
        self.* = undefined;
    }

    pub fn lockAll(self: *ServiceState) void {
        if (self.dek) |*dek| std.crypto.secureZero(u8, dek);
        self.dek = null;
        self.store_id = null;
        self.clearItems();
        self.unlocked = false;
    }

    pub fn checkIdleTimeout(self: *ServiceState, now_sec: u64, last_activity_sec: u64, timeout_seconds: ?u32) bool {
        if (!self.unlocked) return false;
        const t = timeout_seconds orelse return false;
        if (now_sec >= last_activity_sec +| @as(u64, t)) {
            self.lockAll();
            return true;
        }
        return false;
    }

    fn clearItems(self: *ServiceState) void {
        for (self.items.items) |*item| deinitItem(self.gpa, item);
        self.items.clearRetainingCapacity();
    }

    fn unlockWithMasterKey(self: *ServiceState, master_key_value: [vault.dek_len]u8) !void {
        var master_key = master_key_value;
        defer std.crypto.secureZero(u8, &master_key);

        var document = try vault.loadVaultEnvelope(self.gpa);
        defer document.deinit();
        const store_id = try parseStoreId(document.value.store_id_hex);
        var payload = try vault.decryptPayload(
            self.gpa,
            master_key,
            store_id,
            document.value.payload_nonce_b64,
            document.value.payload_ciphertext_b64,
        );
        defer {
            for (payload.value.items) |item| std.crypto.secureZero(u8, @constCast(item.secret_b64));
            payload.deinit();
        }

        var new_items: std.ArrayListUnmanaged(ItemRecord) = .empty;
        errdefer {
            for (new_items.items) |*item| deinitItem(self.gpa, item);
            new_items.deinit(self.gpa);
        }
        for (payload.value.items) |source| {
            try new_items.append(self.gpa, try cloneVaultItem(self.gpa, source));
        }
        const new_label = try self.gpa.dupe(u8, payload.value.label);
        errdefer self.gpa.free(new_label);

        self.clearItems();
        self.items.deinit(self.gpa);
        self.items = new_items;
        self.gpa.free(self.label);
        self.label = new_label;
        self.created = payload.value.created;
        self.modified = payload.value.modified;
        self.next_item_id = payload.value.next_item_id;
        self.store_id = store_id;
        self.dek = master_key;
        self.unlocked = true;
    }

    fn persist(self: *ServiceState) !void {
        if (!self.unlocked or self.dek == null or self.store_id == null) return DispatchError.IsLocked;

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const vault_items = try a.alloc(vault.VaultItem, self.items.items.len);
        var encoded_count: usize = 0;
        defer for (vault_items[0..encoded_count]) |item| std.crypto.secureZero(u8, @constCast(item.secret_b64));
        for (self.items.items, vault_items) |item, *out| {
            var attrs: std.json.ArrayHashMap([]const u8) = .{};
            var iterator = item.attributes.iterator();
            while (iterator.next()) |entry| {
                try attrs.map.put(a, entry.key_ptr.*, entry.value_ptr.*);
            }
            out.* = .{
                .id = item.id,
                .label = item.label,
                .secret_b64 = try base64EncodeAlloc(a, item.secret),
                .content_type = item.content_type,
                .attributes = attrs,
                .created = item.created,
                .modified = item.modified,
            };
            encoded_count += 1;
        }
        const payload: vault.VaultPayload = .{
            .label = self.label,
            .created = self.created,
            .modified = self.modified,
            .next_item_id = self.next_item_id,
            .items = vault_items,
        };
        var encrypted = try vault.encryptPayload(
            self.gpa,
            std.Io.Threaded.global_single_threaded.io(),
            self.dek.?,
            self.store_id.?,
            &payload,
        );
        defer encrypted.deinit(self.gpa);

        var document = try vault.loadVaultEnvelope(self.gpa);
        defer document.deinit();
        const disk_store_id = try parseStoreId(document.value.store_id_hex);
        if (!std.mem.eql(u8, &disk_store_id, &self.store_id.?)) return error.InvalidVault;
        document.value.payload_nonce_b64 = encrypted.nonce_b64;
        document.value.payload_ciphertext_b64 = encrypted.ciphertext_b64;
        try vault.saveVaultEnvelope(self.gpa, &document.value);
    }

    pub fn getStatus(self: *ServiceState) !Status {
        var initialized = true;
        if (vault.loadVaultEnvelope(self.gpa)) |document_value| {
            var document = document_value;
            document.deinit();
        } else |err| switch (err) {
            error.VaultNotFound => initialized = false,
            else => return err,
        }
        return .{
            .initialized = initialized,
            .locked = !self.unlocked,
            .item_count = if (self.unlocked) @intCast(self.items.items.len) else 0,
            .store_path = try vault.vaultPath(self.gpa),
        };
    }

    pub fn handleMessage(self: *ServiceState, call: message.Parsed) !OutboundMessages {
        return self.dispatch(call) catch |err| switch (err) {
            DispatchError.InvalidArgs => self.errorReply(call, "org.freedesktop.DBus.Error.InvalidArgs", "Invalid method arguments"),
            DispatchError.IsLocked => self.errorReply(call, "org.freedesktop.Secret.Error.IsLocked", "Collection is locked; run 'keyring unlock'"),
            DispatchError.NoSuchObject => self.errorReply(call, "org.freedesktop.Secret.Error.NoSuchObject", "No such object"),
            DispatchError.NotSupported => self.errorReply(call, "org.freedesktop.DBus.Error.NotSupported", "Operation is not supported"),
            DispatchError.UnknownInterface => self.errorReply(call, "org.freedesktop.DBus.Error.UnknownInterface", "Unknown interface"),
            DispatchError.UnknownMethod => self.errorReply(call, "org.freedesktop.DBus.Error.UnknownMethod", "Unknown method"),
            DispatchError.UnknownProperty => self.errorReply(call, "org.freedesktop.DBus.Error.UnknownProperty", "Unknown property"),
            else => self.errorReply(call, "org.freedesktop.DBus.Error.Failed", @errorName(err)),
        };
    }

    fn dispatch(self: *ServiceState, call: message.Parsed) !OutboundMessages {
        if (call.header.msg_type != .method_call) return DispatchError.InvalidArgs;
        const path = call.header.path orelse return DispatchError.InvalidArgs;
        const member = call.header.member orelse return DispatchError.InvalidArgs;
        const interface = call.header.interface orelse (inferInterface(path, member) orelse return DispatchError.NoSuchObject);

        if (std.mem.eql(u8, interface, peer_interface)) {
            if (std.mem.eql(u8, member, "Ping")) return self.emptyReply(call);
            if (std.mem.eql(u8, member, "GetMachineId")) {
                var body: std.ArrayList(u8) = .empty;
                defer body.deinit(self.gpa);
                var w = wire.Writer.init(self.gpa, &body);
                try w.writeString("00000000000000000000000000000000");
                return self.reply(call, "s", body.items);
            }
            return DispatchError.UnknownMethod;
        }
        if (std.mem.eql(u8, interface, introspectable_interface)) {
            if (!std.mem.eql(u8, member, "Introspect")) return DispatchError.UnknownMethod;
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var w = wire.Writer.init(self.gpa, &body);
            try w.writeString("<node/>");
            return self.reply(call, "s", body.items);
        }
        if (std.mem.eql(u8, interface, properties_interface)) {
            return self.handleProperties(call, path, member);
        }
        if (std.mem.eql(u8, path, service_path)) {
            if (std.mem.eql(u8, interface, service_interface)) return self.handleService(call, member);
            if (std.mem.eql(u8, interface, control_interface)) return self.handleControl(call, member);
            return DispatchError.UnknownInterface;
        }
        if (isCollectionPath(path)) {
            if (!std.mem.eql(u8, interface, collection_interface)) return DispatchError.UnknownInterface;
            return self.handleCollection(call, member);
        }
        if (std.mem.eql(u8, path, prompt_locked_path)) {
            if (!std.mem.eql(u8, interface, prompt_interface)) return DispatchError.UnknownInterface;
            return self.handlePrompt(call, member);
        }
        if (sessionIdFromPath(path)) |session_id| {
            if (!std.mem.eql(u8, interface, session_interface)) return DispatchError.UnknownInterface;
            return self.handleSession(call, member, session_id);
        }
        if (itemIdFromPath(path)) |item_id| {
            if (!std.mem.eql(u8, interface, item_interface)) return DispatchError.UnknownInterface;
            return self.handleItem(call, member, item_id);
        }
        return DispatchError.NoSuchObject;
    }

    fn handleService(self: *ServiceState, call: message.Parsed, member: []const u8) !OutboundMessages {
        if (std.mem.eql(u8, member, "OpenSession")) return self.openSession(call);
        if (std.mem.eql(u8, member, "ReadAlias")) {
            var r = wire.Reader.init(call.body);
            const name = r.readString() catch return DispatchError.InvalidArgs;
            const path = if (std.mem.eql(u8, name, "default")) collection_path else "/";
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var w = wire.Writer.init(self.gpa, &body);
            try w.writeObjectPath(path);
            return self.reply(call, "o", body.items);
        }
        if (std.mem.eql(u8, member, "SetAlias")) {
            var r = wire.Reader.init(call.body);
            const name = r.readString() catch return DispatchError.InvalidArgs;
            const collection = r.readObjectPath() catch return DispatchError.InvalidArgs;
            if (name.len == 0 or collection.len == 0 or collection[0] != '/') return DispatchError.InvalidArgs;
            if (!std.mem.eql(u8, name, "default")) return DispatchError.NotSupported;
            if (isCollectionPath(collection)) return self.emptyReply(call);
            if (std.mem.eql(u8, collection, "/")) return DispatchError.NotSupported;
            return DispatchError.NoSuchObject;
        }
        if (std.mem.eql(u8, member, "CreateCollection")) {
            var r = wire.Reader.init(call.body);
            try skipDictSv(&r);
            _ = r.readString() catch return DispatchError.InvalidArgs;
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var w = wire.Writer.init(self.gpa, &body);
            try w.writeObjectPath(collection_path);
            try w.writeObjectPath("/");
            return self.reply(call, "oo", body.items);
        }
        if (std.mem.eql(u8, member, "SearchItems")) {
            var r = wire.Reader.init(call.body);
            var query = try readAttributes(self.gpa, &r);
            defer deinitAttributes(self.gpa, &query);
            var matches: std.ArrayListUnmanaged([]const u8) = .empty;
            defer {
                for (matches.items) |path| self.gpa.free(path);
                matches.deinit(self.gpa);
            }
            if (self.unlocked) try self.collectMatchingPaths(&matches, &query);
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var w = wire.Writer.init(self.gpa, &body);
            if (self.unlocked) {
                try writeObjectPathArray(&w, matches.items);
                try writeObjectPathArray(&w, &.{});
            } else {
                try writeObjectPathArray(&w, &.{});
                try writeObjectPathArray(&w, &.{collection_path});
            }
            return self.reply(call, "aoao", body.items);
        }
        if (std.mem.eql(u8, member, "Unlock")) {
            var r = wire.Reader.init(call.body);
            var objects = try readObjectPaths(self.gpa, &r);
            defer objects.deinit(self.gpa);
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var w = wire.Writer.init(self.gpa, &body);
            if (self.unlocked) {
                try writeObjectPathArray(&w, objects.items);
                try w.writeObjectPath("/");
            } else {
                try writeObjectPathArray(&w, &.{});
                try w.writeObjectPath(prompt_locked_path);
            }
            return self.reply(call, "aoo", body.items);
        }
        if (std.mem.eql(u8, member, "Lock")) {
            var r = wire.Reader.init(call.body);
            var objects = try readObjectPaths(self.gpa, &r);
            defer objects.deinit(self.gpa);
            self.lockAll();
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var w = wire.Writer.init(self.gpa, &body);
            try writeObjectPathArray(&w, objects.items);
            try w.writeObjectPath("/");
            return self.reply(call, "aoo", body.items);
        }
        if (std.mem.eql(u8, member, "GetSecrets")) {
            if (!self.unlocked) return DispatchError.IsLocked;
            var r = wire.Reader.init(call.body);
            var requested = try readObjectPaths(self.gpa, &r);
            defer requested.deinit(self.gpa);
            const session_path = r.readObjectPath() catch return DispatchError.InvalidArgs;
            const session = self.sessionForPath(session_path) orelse return DispatchError.NoSuchObject;
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var w = wire.Writer.init(self.gpa, &body);
            const array = try w.beginArray(8);
            for (requested.items) |item_path| {
                const id = itemIdFromPath(item_path) orelse continue;
                const item = self.findItem(id) orelse continue;
                try w.alignStruct();
                try w.writeObjectPath(item_path);
                try writeSecret(self.gpa, &w, item.secret, item.content_type, session_path, session.*);
            }
            w.endArray(array);
            return self.reply(call, "a{o(oayays)}", body.items);
        }
        return DispatchError.UnknownMethod;
    }

    fn openSession(self: *ServiceState, call: message.Parsed) !OutboundMessages {
        var r = wire.Reader.init(call.body);
        const algorithm = r.readString() catch return DispatchError.InvalidArgs;
        const variant_signature = r.readSignatureValue() catch return DispatchError.InvalidArgs;
        const id = self.next_session_id;
        self.next_session_id +%= 1;
        if (self.next_session_id == 0) self.next_session_id = 1;

        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.gpa);
        var w = wire.Writer.init(self.gpa, &body);
        if (std.mem.eql(u8, algorithm, "plain")) {
            if (!std.mem.eql(u8, variant_signature, "s")) return DispatchError.InvalidArgs;
            _ = r.readString() catch return DispatchError.InvalidArgs;
            try self.sessions.put(self.gpa, id, .plain);
            try w.writeSignatureValue("s");
            try w.writeString("");
        } else if (std.mem.eql(u8, algorithm, dh_algorithm)) {
            if (!std.mem.eql(u8, variant_signature, "ay")) return DispatchError.InvalidArgs;
            const client_key = try readByteArray(&r);
            var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
            secureRandom(&seed);
            var rng = std.Random.DefaultCsprng.init(seed);
            var key_pair = try generateDhKeyPair(rng.random());
            defer std.crypto.secureZero(u8, &key_pair.private);
            var key = try deriveDhSharedKey(key_pair.private, client_key);
            errdefer std.crypto.secureZero(u8, &key);
            try self.sessions.put(self.gpa, id, .{ .dh_ietf = key });
            try w.writeSignatureValue("ay");
            try writeByteArray(&w, &key_pair.public);
        } else {
            return DispatchError.NotSupported;
        }
        const path = try std.fmt.allocPrint(self.gpa, "/org/freedesktop/secrets/session/s{d}", .{id});
        defer self.gpa.free(path);
        try w.writeObjectPath(path);
        return self.reply(call, "vo", body.items);
    }

    fn handleCollection(self: *ServiceState, call: message.Parsed, member: []const u8) !OutboundMessages {
        if (std.mem.eql(u8, member, "SearchItems")) {
            var r = wire.Reader.init(call.body);
            var query = try readAttributes(self.gpa, &r);
            defer deinitAttributes(self.gpa, &query);
            var matches: std.ArrayListUnmanaged([]const u8) = .empty;
            defer {
                for (matches.items) |path| self.gpa.free(path);
                matches.deinit(self.gpa);
            }
            if (self.unlocked) try self.collectMatchingPaths(&matches, &query);
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var w = wire.Writer.init(self.gpa, &body);
            try writeObjectPathArray(&w, matches.items);
            return self.reply(call, "ao", body.items);
        }
        if (std.mem.eql(u8, member, "CreateItem")) {
            if (!self.unlocked) return DispatchError.IsLocked;
            return self.createItem(call);
        }
        if (std.mem.eql(u8, member, "Delete")) {
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var w = wire.Writer.init(self.gpa, &body);
            try w.writeObjectPath("/");
            return self.reply(call, "o", body.items);
        }
        return DispatchError.UnknownMethod;
    }

    fn createItem(self: *ServiceState, call: message.Parsed) !OutboundMessages {
        var r = wire.Reader.init(call.body);
        var properties = try readItemProperties(self.gpa, &r);
        defer properties.deinit(self.gpa);
        const encoded_secret = try readSecretTuple(&r);
        const replace = r.readBool() catch return DispatchError.InvalidArgs;
        const session = self.sessionForPath(encoded_secret.session) orelse return DispatchError.NoSuchObject;
        const plaintext = try decodeSecret(self.gpa, encoded_secret, session.*);
        defer {
            std.crypto.secureZero(u8, plaintext);
            self.gpa.free(plaintext);
        }
        const now = unixNow();

        var existing: ?*ItemRecord = null;
        if (replace and properties.attributes.count() > 0) {
            for (self.items.items) |*item| {
                if (attributesEqual(&item.attributes, &properties.attributes)) {
                    existing = item;
                    break;
                }
            }
        }
        var item_id: []const u8 = undefined;
        if (existing) |item| {
            var new_attributes = try cloneAttributes(self.gpa, &properties.attributes);
            var attributes_moved = false;
            errdefer if (!attributes_moved) deinitAttributes(self.gpa, &new_attributes);
            try replaceOwned(self.gpa, &item.label, properties.label);
            try secureReplaceOwned(self.gpa, &item.secret, plaintext);
            try replaceOwned(self.gpa, &item.content_type, encoded_secret.content_type);
            deinitAttributes(self.gpa, &item.attributes);
            item.attributes = new_attributes;
            attributes_moved = true;
            item.modified = now;
            item_id = item.id;
        } else {
            const id = try std.fmt.allocPrint(self.gpa, "{d}", .{self.next_item_id});
            self.next_item_id += 1;
            var item = makeItem(
                self.gpa,
                id,
                properties.label,
                plaintext,
                encoded_secret.content_type,
                &properties.attributes,
                now,
            ) catch |err| {
                self.gpa.free(id);
                return err;
            };
            var item_moved = false;
            errdefer if (!item_moved) deinitItem(self.gpa, &item);
            try self.items.append(self.gpa, item);
            item_moved = true;
            item_id = self.items.items[self.items.items.len - 1].id;
        }
        self.modified = now;
        try self.persist();

        const path = try itemPathAlloc(self.gpa, item_id);
        defer self.gpa.free(path);
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.gpa);
        var w = wire.Writer.init(self.gpa, &body);
        try w.writeObjectPath(path);
        try w.writeObjectPath("/");
        var out = try self.reply(call, "oo", body.items);
        errdefer out.deinit();
        try self.appendCollectionItemSignal(&out, if (existing != null) "ItemChanged" else "ItemCreated", path);
        return out;
    }

    fn handleItem(self: *ServiceState, call: message.Parsed, member: []const u8, item_id: []const u8) !OutboundMessages {
        if (!self.unlocked) return DispatchError.IsLocked;
        const index = self.findItemIndex(item_id) orelse return DispatchError.NoSuchObject;
        if (std.mem.eql(u8, member, "GetSecret")) {
            var r = wire.Reader.init(call.body);
            const session_path = r.readObjectPath() catch return DispatchError.InvalidArgs;
            const session = self.sessionForPath(session_path) orelse return DispatchError.NoSuchObject;
            const item = &self.items.items[index];
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var w = wire.Writer.init(self.gpa, &body);
            try writeSecret(self.gpa, &w, item.secret, item.content_type, session_path, session.*);
            return self.reply(call, "(oayays)", body.items);
        }
        if (std.mem.eql(u8, member, "SetSecret")) {
            var r = wire.Reader.init(call.body);
            const encoded = try readSecretTuple(&r);
            const session = self.sessionForPath(encoded.session) orelse return DispatchError.NoSuchObject;
            const plaintext = try decodeSecret(self.gpa, encoded, session.*);
            defer {
                std.crypto.secureZero(u8, plaintext);
                self.gpa.free(plaintext);
            }
            const item = &self.items.items[index];
            try secureReplaceOwned(self.gpa, &item.secret, plaintext);
            try replaceOwned(self.gpa, &item.content_type, encoded.content_type);
            item.modified = unixNow();
            self.modified = item.modified;
            try self.persist();
            const item_path = try itemPathAlloc(self.gpa, item_id);
            defer self.gpa.free(item_path);
            var out = try self.emptyReply(call);
            errdefer out.deinit();
            try self.appendCollectionItemSignal(&out, "ItemChanged", item_path);
            return out;
        }
        if (std.mem.eql(u8, member, "Delete")) {
            const deleted_path = try itemPathAlloc(self.gpa, item_id);
            defer self.gpa.free(deleted_path);
            var removed = self.items.orderedRemove(index);
            deinitItem(self.gpa, &removed);
            self.modified = unixNow();
            try self.persist();
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var w = wire.Writer.init(self.gpa, &body);
            try w.writeObjectPath("/");
            var out = try self.reply(call, "o", body.items);
            errdefer out.deinit();
            try self.appendCollectionItemSignal(&out, "ItemDeleted", deleted_path);
            return out;
        }
        return DispatchError.UnknownMethod;
    }

    fn handleSession(self: *ServiceState, call: message.Parsed, member: []const u8, session_id: u32) !OutboundMessages {
        if (!std.mem.eql(u8, member, "Close")) return DispatchError.UnknownMethod;
        const removed = self.sessions.fetchRemove(session_id) orelse return DispatchError.NoSuchObject;
        var session = removed.value;
        session.deinit();
        return self.emptyReply(call);
    }

    fn handlePrompt(self: *ServiceState, call: message.Parsed, member: []const u8) !OutboundMessages {
        if (std.mem.eql(u8, member, "Prompt")) {
            var r = wire.Reader.init(call.body);
            _ = r.readString() catch return DispatchError.InvalidArgs;
            return self.promptReply(call, !self.unlocked);
        }
        if (std.mem.eql(u8, member, "Dismiss")) return self.promptReply(call, true);
        return DispatchError.UnknownMethod;
    }

    fn handleControl(self: *ServiceState, call: message.Parsed, member: []const u8) !OutboundMessages {
        if (std.mem.eql(u8, member, "UnlockWithMasterKey")) {
            var r = wire.Reader.init(call.body);
            const bytes = try readByteArray(&r);
            if (bytes.len != vault.dek_len) return DispatchError.InvalidArgs;
            var key: [vault.dek_len]u8 = undefined;
            @memcpy(&key, bytes);
            defer std.crypto.secureZero(u8, &key);
            try self.unlockWithMasterKey(key);
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var w = wire.Writer.init(self.gpa, &body);
            try w.writeBool(true);
            return self.reply(call, "b", body.items);
        }
        if (std.mem.eql(u8, member, "LockAll")) {
            self.lockAll();
            return self.emptyReply(call);
        }
        if (std.mem.eql(u8, member, "GetStatus")) {
            var status = try self.getStatus();
            defer status.deinit(self.gpa);
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var w = wire.Writer.init(self.gpa, &body);
            try w.writeBool(status.initialized);
            try w.writeBool(status.locked);
            try w.writeU32(status.item_count);
            try w.writeString(status.store_path);
            return self.reply(call, "bbus", body.items);
        }
        return DispatchError.UnknownMethod;
    }

    fn handleProperties(self: *ServiceState, call: message.Parsed, path: []const u8, member: []const u8) !OutboundMessages {
        var r = wire.Reader.init(call.body);
        if (std.mem.eql(u8, member, "Get")) {
            const raw_interface = r.readString() catch return DispatchError.InvalidArgs;
            const property = r.readString() catch return DispatchError.InvalidArgs;
            const interface = try resolvePropertiesInterface(path, raw_interface);
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var w = wire.Writer.init(self.gpa, &body);
            try self.writeProperty(&w, path, interface, property);
            return self.reply(call, "v", body.items);
        }
        if (std.mem.eql(u8, member, "GetAll")) {
            const raw_interface = r.readString() catch return DispatchError.InvalidArgs;
            const interface = try resolvePropertiesInterface(path, raw_interface);
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var w = wire.Writer.init(self.gpa, &body);
            try self.writeAllProperties(&w, path, interface);
            return self.reply(call, "a{sv}", body.items);
        }
        if (std.mem.eql(u8, member, "Set")) {
            const raw_interface = r.readString() catch return DispatchError.InvalidArgs;
            const property = r.readString() catch return DispatchError.InvalidArgs;
            const signature = r.readSignatureValue() catch return DispatchError.InvalidArgs;
            const interface = try resolvePropertiesInterface(path, raw_interface);
            const item_changed = try self.setProperty(path, interface, property, signature, &r);
            var out = try self.emptyReply(call);
            errdefer out.deinit();
            if (item_changed) {
                try self.appendCollectionItemSignal(&out, "ItemChanged", path);
            }
            return out;
        }
        return DispatchError.UnknownMethod;
    }

    fn writeProperty(self: *ServiceState, w: *wire.Writer, path: []const u8, interface: []const u8, property: []const u8) !void {
        if (std.mem.eql(u8, path, service_path)) {
            if (!std.mem.eql(u8, interface, service_interface)) return DispatchError.UnknownInterface;
            if (!std.mem.eql(u8, property, "Collections")) return DispatchError.UnknownProperty;
            try w.writeSignatureValue("ao");
            try writeObjectPathArray(w, &.{collection_path});
            return;
        }
        if (isCollectionPath(path)) {
            if (!std.mem.eql(u8, interface, collection_interface)) return DispatchError.UnknownInterface;
            if (std.mem.eql(u8, property, "Items")) {
                try w.writeSignatureValue("ao");
                try self.writeAllItemPaths(w);
            } else if (std.mem.eql(u8, property, "Label")) {
                try w.writeSignatureValue("s");
                try w.writeString(self.label);
            } else if (std.mem.eql(u8, property, "Locked")) {
                try w.writeSignatureValue("b");
                try w.writeBool(!self.unlocked);
            } else if (std.mem.eql(u8, property, "Created")) {
                try w.writeSignatureValue("t");
                try w.writeU64(self.created);
            } else if (std.mem.eql(u8, property, "Modified")) {
                try w.writeSignatureValue("t");
                try w.writeU64(self.modified);
            } else return DispatchError.UnknownProperty;
            return;
        }
        if (itemIdFromPath(path)) |item_id| {
            if (!std.mem.eql(u8, interface, item_interface)) return DispatchError.UnknownInterface;
            const item = self.findItem(item_id) orelse return DispatchError.NoSuchObject;
            if (std.mem.eql(u8, property, "Locked")) {
                try w.writeSignatureValue("b");
                try w.writeBool(!self.unlocked);
            } else if (std.mem.eql(u8, property, "Attributes")) {
                try w.writeSignatureValue("a{ss}");
                try writeAttributes(w, &item.attributes);
            } else if (std.mem.eql(u8, property, "Label")) {
                try w.writeSignatureValue("s");
                try w.writeString(item.label);
            } else if (std.mem.eql(u8, property, "Type")) {
                try w.writeSignatureValue("s");
                try w.writeString(generic_item_type);
            } else if (std.mem.eql(u8, property, "Created")) {
                try w.writeSignatureValue("t");
                try w.writeU64(item.created);
            } else if (std.mem.eql(u8, property, "Modified")) {
                try w.writeSignatureValue("t");
                try w.writeU64(item.modified);
            } else return DispatchError.UnknownProperty;
            return;
        }
        return DispatchError.NoSuchObject;
    }

    fn writeAllProperties(self: *ServiceState, w: *wire.Writer, path: []const u8, interface: []const u8) !void {
        const array = try w.beginArray(8);
        if (std.mem.eql(u8, path, service_path)) {
            if (!std.mem.eql(u8, interface, service_interface)) return DispatchError.UnknownInterface;
            try writePropertyEntryStart(w, "Collections", "ao");
            try writeObjectPathArray(w, &.{collection_path});
        } else if (isCollectionPath(path)) {
            if (!std.mem.eql(u8, interface, collection_interface)) return DispatchError.UnknownInterface;
            try writePropertyEntryStart(w, "Items", "ao");
            try self.writeAllItemPaths(w);
            try writePropertyEntryStart(w, "Label", "s");
            try w.writeString(self.label);
            try writePropertyEntryStart(w, "Locked", "b");
            try w.writeBool(!self.unlocked);
            try writePropertyEntryStart(w, "Created", "t");
            try w.writeU64(self.created);
            try writePropertyEntryStart(w, "Modified", "t");
            try w.writeU64(self.modified);
        } else if (itemIdFromPath(path)) |item_id| {
            if (!std.mem.eql(u8, interface, item_interface)) return DispatchError.UnknownInterface;
            const item = self.findItem(item_id) orelse return DispatchError.NoSuchObject;
            try writePropertyEntryStart(w, "Locked", "b");
            try w.writeBool(!self.unlocked);
            try writePropertyEntryStart(w, "Attributes", "a{ss}");
            try writeAttributes(w, &item.attributes);
            try writePropertyEntryStart(w, "Label", "s");
            try w.writeString(item.label);
            try writePropertyEntryStart(w, "Type", "s");
            try w.writeString(generic_item_type);
            try writePropertyEntryStart(w, "Created", "t");
            try w.writeU64(item.created);
            try writePropertyEntryStart(w, "Modified", "t");
            try w.writeU64(item.modified);
        } else return DispatchError.NoSuchObject;
        w.endArray(array);
    }

    fn setProperty(self: *ServiceState, path: []const u8, interface: []const u8, property: []const u8, signature: []const u8, r: *wire.Reader) !bool {
        if (isCollectionPath(path)) {
            if (!std.mem.eql(u8, interface, collection_interface)) return DispatchError.UnknownInterface;
            if (!std.mem.eql(u8, property, "Label") or !std.mem.eql(u8, signature, "s")) return DispatchError.UnknownProperty;
            if (!self.unlocked) return DispatchError.IsLocked;
            const label = r.readString() catch return DispatchError.InvalidArgs;
            try replaceOwned(self.gpa, &self.label, label);
            self.modified = unixNow();
            try self.persist();
            return false;
        }
        if (itemIdFromPath(path)) |item_id| {
            if (!self.unlocked) return DispatchError.IsLocked;
            if (!std.mem.eql(u8, interface, item_interface)) return DispatchError.UnknownInterface;
            const item = self.findItem(item_id) orelse return DispatchError.NoSuchObject;
            if (std.mem.eql(u8, property, "Label") and std.mem.eql(u8, signature, "s")) {
                const label = r.readString() catch return DispatchError.InvalidArgs;
                try replaceOwned(self.gpa, &item.label, label);
            } else if (std.mem.eql(u8, property, "Attributes") and std.mem.eql(u8, signature, "a{ss}")) {
                const attributes = try readAttributes(self.gpa, r);
                deinitAttributes(self.gpa, &item.attributes);
                item.attributes = attributes;
            } else return DispatchError.UnknownProperty;
            item.modified = unixNow();
            self.modified = item.modified;
            try self.persist();
            return true;
        }
        if (std.mem.eql(u8, path, service_path)) {
            if (!std.mem.eql(u8, interface, service_interface)) return DispatchError.UnknownInterface;
            return DispatchError.UnknownProperty;
        }
        return DispatchError.NoSuchObject;
    }

    fn collectMatchingPaths(self: *ServiceState, out: *std.ArrayListUnmanaged([]const u8), query: *const std.StringHashMapUnmanaged([]u8)) !void {
        for (self.items.items) |*item| {
            if (attributesContain(&item.attributes, query)) {
                try out.append(self.gpa, try itemPathAlloc(self.gpa, item.id));
            }
        }
    }

    fn writeAllItemPaths(self: *ServiceState, w: *wire.Writer) !void {
        const array = try w.beginArray(4);
        if (self.unlocked) {
            for (self.items.items) |item| {
                const path = try itemPathAlloc(self.gpa, item.id);
                defer self.gpa.free(path);
                try w.writeObjectPath(path);
            }
        }
        w.endArray(array);
    }

    fn findItem(self: *ServiceState, id: []const u8) ?*ItemRecord {
        const index = self.findItemIndex(id) orelse return null;
        return &self.items.items[index];
    }

    fn findItemIndex(self: *ServiceState, id: []const u8) ?usize {
        for (self.items.items, 0..) |item, index| {
            if (std.mem.eql(u8, item.id, id)) return index;
        }
        return null;
    }

    fn sessionForPath(self: *ServiceState, path: []const u8) ?*Session {
        const id = sessionIdFromPath(path) orelse return null;
        return self.sessions.getPtr(id);
    }

    fn promptReply(self: *ServiceState, call: message.Parsed, dismissed: bool) !OutboundMessages {
        var out = try self.emptyReply(call);
        errdefer out.deinit();
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.gpa);
        var w = wire.Writer.init(self.gpa, &body);
        try w.writeBool(dismissed);
        try w.writeSignatureValue("ao");
        if (dismissed) try writeObjectPathArray(&w, &.{}) else try writeObjectPathArray(&w, &.{collection_path});
        try self.appendFrame(&out, .{
            .msg_type = .signal,
            .serial = self.takeSerial(),
            .path = prompt_locked_path,
            .interface = prompt_interface,
            .member = "Completed",
            .signature = "bv",
        }, body.items);
        return out;
    }

    fn appendCollectionItemSignal(self: *ServiceState, out: *OutboundMessages, member: []const u8, item_path: []const u8) !void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.gpa);
        var w = wire.Writer.init(self.gpa, &body);
        try w.writeObjectPath(item_path);
        try self.appendFrame(out, .{
            .msg_type = .signal,
            .serial = self.takeSerial(),
            .path = collection_path,
            .interface = collection_interface,
            .member = member,
            .signature = "o",
        }, body.items);
    }

    fn emptyReply(self: *ServiceState, call: message.Parsed) !OutboundMessages {
        return self.reply(call, null, &.{});
    }

    fn reply(self: *ServiceState, call: message.Parsed, signature: ?[]const u8, body: []const u8) !OutboundMessages {
        var out: OutboundMessages = .{ .gpa = self.gpa };
        errdefer out.deinit();
        if (!call.header.flags.no_reply_expected) {
            try self.appendFrame(&out, .{
                .msg_type = .method_return,
                .serial = self.takeSerial(),
                .reply_serial = call.header.serial,
                .destination = call.header.sender,
                .signature = signature,
            }, body);
        }
        return out;
    }

    fn errorReply(self: *ServiceState, call: message.Parsed, name: []const u8, text: []const u8) !OutboundMessages {
        var out: OutboundMessages = .{ .gpa = self.gpa };
        errdefer out.deinit();
        if (!call.header.flags.no_reply_expected) {
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            var w = wire.Writer.init(self.gpa, &body);
            try w.writeString(text);
            try self.appendFrame(&out, .{
                .msg_type = .error_reply,
                .serial = self.takeSerial(),
                .error_name = name,
                .reply_serial = call.header.serial,
                .destination = call.header.sender,
                .signature = "s",
            }, body.items);
        }
        return out;
    }

    fn appendFrame(self: *ServiceState, out: *OutboundMessages, header: message.Header, body: []const u8) !void {
        var frame: std.ArrayList(u8) = .empty;
        errdefer frame.deinit(self.gpa);
        try message.serialize(self.gpa, &frame, header, body);
        try out.frames.append(self.gpa, try frame.toOwnedSlice(self.gpa));
    }

    fn takeSerial(self: *ServiceState) u32 {
        const serial = self.next_serial;
        self.next_serial +%= 1;
        if (self.next_serial == 0) self.next_serial = 1;
        return serial;
    }
};

const ItemProperties = struct {
    label: []const u8 = "",
    attributes: std.StringHashMapUnmanaged([]u8) = .empty,

    fn deinit(self: *ItemProperties, gpa: Allocator) void {
        deinitAttributes(gpa, &self.attributes);
    }
};

const EncodedSecret = struct {
    session: []const u8,
    parameters: []const u8,
    value: []const u8,
    content_type: []const u8,
};

fn inferInterface(path: []const u8, member: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, member, "Ping") or std.mem.eql(u8, member, "GetMachineId")) {
        return peer_interface;
    }
    if (std.mem.eql(u8, member, "Introspect")) {
        return introspectable_interface;
    }
    if (std.mem.eql(u8, member, "Get") or std.mem.eql(u8, member, "GetAll") or std.mem.eql(u8, member, "Set")) {
        return properties_interface;
    }
    if (std.mem.eql(u8, path, service_path)) {
        if (std.mem.eql(u8, member, "UnlockWithMasterKey") or
            std.mem.eql(u8, member, "LockAll") or
            std.mem.eql(u8, member, "GetStatus"))
        {
            return control_interface;
        }
        return service_interface;
    }
    if (isCollectionPath(path)) return collection_interface;
    if (std.mem.eql(u8, path, prompt_locked_path)) return prompt_interface;
    if (sessionIdFromPath(path) != null) return session_interface;
    if (itemIdFromPath(path) != null) return item_interface;
    return null;
}

fn resolvePropertiesInterface(path: []const u8, raw_interface: []const u8) DispatchError![]const u8 {
    if (raw_interface.len != 0) return raw_interface;
    if (std.mem.eql(u8, path, service_path)) return service_interface;
    if (isCollectionPath(path)) return collection_interface;
    if (itemIdFromPath(path) != null) return item_interface;
    return DispatchError.NoSuchObject;
}

fn readItemProperties(gpa: Allocator, r: *wire.Reader) !ItemProperties {
    var result: ItemProperties = .{};
    errdefer result.deinit(gpa);
    const array = r.beginArray(8) catch return DispatchError.InvalidArgs;
    while (r.arrayHasMore(array)) {
        r.alignStruct() catch return DispatchError.InvalidArgs;
        const key = r.readString() catch return DispatchError.InvalidArgs;
        const signature = r.readSignatureValue() catch return DispatchError.InvalidArgs;
        if ((std.mem.eql(u8, key, "org.freedesktop.Secret.Item.Label") or std.mem.eql(u8, key, "Label")) and std.mem.eql(u8, signature, "s")) {
            result.label = r.readString() catch return DispatchError.InvalidArgs;
        } else if ((std.mem.eql(u8, key, "org.freedesktop.Secret.Item.Attributes") or std.mem.eql(u8, key, "Attributes")) and std.mem.eql(u8, signature, "a{ss}")) {
            const attributes = try readAttributes(gpa, r);
            deinitAttributes(gpa, &result.attributes);
            result.attributes = attributes;
        } else {
            try skipValue(r, signature);
        }
    }
    return result;
}

fn readAttributes(gpa: Allocator, r: *wire.Reader) !std.StringHashMapUnmanaged([]u8) {
    var result: std.StringHashMapUnmanaged([]u8) = .empty;
    errdefer deinitAttributes(gpa, &result);
    const array = r.beginArray(8) catch return DispatchError.InvalidArgs;
    while (r.arrayHasMore(array)) {
        r.alignStruct() catch return DispatchError.InvalidArgs;
        const key = r.readString() catch return DispatchError.InvalidArgs;
        const value = r.readString() catch return DispatchError.InvalidArgs;
        const key_owned = try gpa.dupe(u8, key);
        errdefer gpa.free(key_owned);
        const value_owned = try gpa.dupe(u8, value);
        errdefer gpa.free(value_owned);
        const entry = try result.getOrPut(gpa, key_owned);
        if (entry.found_existing) {
            gpa.free(key_owned);
            gpa.free(entry.value_ptr.*);
        }
        entry.value_ptr.* = value_owned;
    }
    return result;
}

fn readObjectPaths(gpa: Allocator, r: *wire.Reader) !std.ArrayListUnmanaged([]const u8) {
    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer result.deinit(gpa);
    const array = r.beginArray(4) catch return DispatchError.InvalidArgs;
    while (r.arrayHasMore(array)) {
        try result.append(gpa, r.readObjectPath() catch return DispatchError.InvalidArgs);
    }
    return result;
}

fn readByteArray(r: *wire.Reader) ![]const u8 {
    const array = r.beginArray(1) catch return DispatchError.InvalidArgs;
    return r.readBytes(array.end - r.pos) catch return DispatchError.InvalidArgs;
}

fn readSecretTuple(r: *wire.Reader) !EncodedSecret {
    r.alignStruct() catch return DispatchError.InvalidArgs;
    const session = r.readObjectPath() catch return DispatchError.InvalidArgs;
    const parameters = try readByteArray(r);
    const value = try readByteArray(r);
    const content_type = r.readString() catch return DispatchError.InvalidArgs;
    return .{
        .session = session,
        .parameters = parameters,
        .value = value,
        .content_type = content_type,
    };
}

fn skipDictSv(r: *wire.Reader) !void {
    const array = r.beginArray(8) catch return DispatchError.InvalidArgs;
    while (r.arrayHasMore(array)) {
        r.alignStruct() catch return DispatchError.InvalidArgs;
        _ = r.readString() catch return DispatchError.InvalidArgs;
        const signature = r.readSignatureValue() catch return DispatchError.InvalidArgs;
        try skipValue(r, signature);
    }
}

fn skipValue(r: *wire.Reader, signature: []const u8) !void {
    if (std.mem.eql(u8, signature, "s") or std.mem.eql(u8, signature, "o")) {
        _ = r.readString() catch return DispatchError.InvalidArgs;
    } else if (std.mem.eql(u8, signature, "y")) {
        _ = r.readByte() catch return DispatchError.InvalidArgs;
    } else if (std.mem.eql(u8, signature, "n") or std.mem.eql(u8, signature, "q")) {
        _ = r.readU16() catch return DispatchError.InvalidArgs;
    } else if (std.mem.eql(u8, signature, "b") or std.mem.eql(u8, signature, "u") or std.mem.eql(u8, signature, "i")) {
        _ = r.readU32() catch return DispatchError.InvalidArgs;
    } else if (std.mem.eql(u8, signature, "t") or std.mem.eql(u8, signature, "x")) {
        _ = r.readU64() catch return DispatchError.InvalidArgs;
    } else if (std.mem.eql(u8, signature, "ay")) {
        _ = try readByteArray(r);
    } else if (std.mem.eql(u8, signature, "ao")) {
        var paths = try readObjectPaths(std.heap.page_allocator, r);
        paths.deinit(std.heap.page_allocator);
    } else if (std.mem.eql(u8, signature, "a{ss}")) {
        var attrs = try readAttributes(std.heap.page_allocator, r);
        deinitAttributes(std.heap.page_allocator, &attrs);
    } else return DispatchError.InvalidArgs;
}

fn writeObjectPathArray(w: *wire.Writer, paths: []const []const u8) !void {
    const array = try w.beginArray(4);
    for (paths) |path| try w.writeObjectPath(path);
    w.endArray(array);
}

fn writeByteArray(w: *wire.Writer, bytes: []const u8) !void {
    const array = try w.beginArray(1);
    try w.writeBytes(bytes);
    w.endArray(array);
}

fn writeAttributes(w: *wire.Writer, attributes: *const std.StringHashMapUnmanaged([]u8)) !void {
    const array = try w.beginArray(8);
    var iterator = attributes.iterator();
    while (iterator.next()) |entry| {
        try w.alignStruct();
        try w.writeString(entry.key_ptr.*);
        try w.writeString(entry.value_ptr.*);
    }
    w.endArray(array);
}

fn writePropertyEntryStart(w: *wire.Writer, name: []const u8, signature: []const u8) !void {
    try w.alignStruct();
    try w.writeString(name);
    try w.writeSignatureValue(signature);
}

fn writeSecret(gpa: Allocator, w: *wire.Writer, plaintext: []const u8, content_type: []const u8, session_path: []const u8, session: Session) !void {
    try w.alignStruct();
    try w.writeObjectPath(session_path);
    switch (session) {
        .plain => {
            try writeByteArray(w, &.{});
            try writeByteArray(w, plaintext);
        },
        .dh_ietf => |key| {
            var iv: [16]u8 = undefined;
            secureRandom(&iv);
            const ciphertext = try aesCbcEncrypt(gpa, key, iv, plaintext);
            defer gpa.free(ciphertext);
            try writeByteArray(w, &iv);
            try writeByteArray(w, ciphertext);
        },
    }
    try w.writeString(content_type);
}

fn decodeSecret(gpa: Allocator, encoded: EncodedSecret, session: Session) ![]u8 {
    return switch (session) {
        .plain => try gpa.dupe(u8, encoded.value),
        .dh_ietf => |key| blk: {
            if (encoded.parameters.len != 16) return DispatchError.InvalidArgs;
            var iv: [16]u8 = undefined;
            @memcpy(&iv, encoded.parameters);
            break :blk try aesCbcDecrypt(gpa, key, iv, encoded.value);
        },
    };
}

fn cloneVaultItem(gpa: Allocator, source: vault.VaultItem) !ItemRecord {
    const id = try gpa.dupe(u8, source.id);
    errdefer gpa.free(id);
    const label = try gpa.dupe(u8, source.label);
    errdefer gpa.free(label);
    const secret = try base64DecodeAlloc(gpa, source.secret_b64);
    errdefer {
        std.crypto.secureZero(u8, secret);
        gpa.free(secret);
    }
    const content_type = try gpa.dupe(u8, source.content_type);
    errdefer gpa.free(content_type);
    var attributes: std.StringHashMapUnmanaged([]u8) = .empty;
    errdefer deinitAttributes(gpa, &attributes);
    var iterator = source.attributes.map.iterator();
    while (iterator.next()) |entry| {
        const key = try gpa.dupe(u8, entry.key_ptr.*);
        errdefer gpa.free(key);
        const value = try gpa.dupe(u8, entry.value_ptr.*);
        errdefer gpa.free(value);
        try attributes.put(gpa, key, value);
    }
    return .{
        .id = id,
        .label = label,
        .secret = secret,
        .content_type = content_type,
        .attributes = attributes,
        .created = source.created,
        .modified = source.modified,
    };
}

fn makeItem(
    gpa: Allocator,
    id: []u8,
    label_source: []const u8,
    secret_source: []const u8,
    content_type_source: []const u8,
    attributes_source: *const std.StringHashMapUnmanaged([]u8),
    now: u64,
) !ItemRecord {
    const label = try gpa.dupe(u8, label_source);
    errdefer gpa.free(label);
    const secret = try gpa.dupe(u8, secret_source);
    errdefer {
        std.crypto.secureZero(u8, secret);
        gpa.free(secret);
    }
    const content_type = try gpa.dupe(u8, content_type_source);
    errdefer gpa.free(content_type);
    const attributes = try cloneAttributes(gpa, attributes_source);
    return .{
        .id = id,
        .label = label,
        .secret = secret,
        .content_type = content_type,
        .attributes = attributes,
        .created = now,
        .modified = now,
    };
}

fn cloneAttributes(gpa: Allocator, source: *const std.StringHashMapUnmanaged([]u8)) !std.StringHashMapUnmanaged([]u8) {
    var result: std.StringHashMapUnmanaged([]u8) = .empty;
    errdefer deinitAttributes(gpa, &result);
    var iterator = source.iterator();
    while (iterator.next()) |entry| {
        const key = try gpa.dupe(u8, entry.key_ptr.*);
        errdefer gpa.free(key);
        const value = try gpa.dupe(u8, entry.value_ptr.*);
        errdefer gpa.free(value);
        try result.put(gpa, key, value);
    }
    return result;
}

fn deinitItem(gpa: Allocator, item: *ItemRecord) void {
    gpa.free(item.id);
    gpa.free(item.label);
    std.crypto.secureZero(u8, item.secret);
    gpa.free(item.secret);
    gpa.free(item.content_type);
    deinitAttributes(gpa, &item.attributes);
    item.* = undefined;
}

fn deinitAttributes(gpa: Allocator, attributes: *std.StringHashMapUnmanaged([]u8)) void {
    var iterator = attributes.iterator();
    while (iterator.next()) |entry| {
        gpa.free(entry.key_ptr.*);
        gpa.free(entry.value_ptr.*);
    }
    attributes.deinit(gpa);
    attributes.* = .empty;
}

fn attributesContain(haystack: *const std.StringHashMapUnmanaged([]u8), needle: *const std.StringHashMapUnmanaged([]u8)) bool {
    var iterator = needle.iterator();
    while (iterator.next()) |entry| {
        const value = haystack.get(entry.key_ptr.*) orelse return false;
        if (!std.mem.eql(u8, value, entry.value_ptr.*)) return false;
    }
    return true;
}

fn attributesEqual(a: *const std.StringHashMapUnmanaged([]u8), b: *const std.StringHashMapUnmanaged([]u8)) bool {
    return a.count() == b.count() and attributesContain(a, b);
}

fn replaceOwned(gpa: Allocator, destination: *[]u8, source: []const u8) !void {
    const replacement = try gpa.dupe(u8, source);
    gpa.free(destination.*);
    destination.* = replacement;
}

fn secureReplaceOwned(gpa: Allocator, destination: *[]u8, source: []const u8) !void {
    const replacement = try gpa.dupe(u8, source);
    std.crypto.secureZero(u8, destination.*);
    gpa.free(destination.*);
    destination.* = replacement;
}

fn isCollectionPath(path: []const u8) bool {
    return std.mem.eql(u8, path, collection_path) or std.mem.eql(u8, path, collection_alias_path);
}

fn itemIdFromPath(path: []const u8) ?[]const u8 {
    const prefix = collection_path ++ "/";
    if (!std.mem.startsWith(u8, path, prefix)) return null;
    const id = path[prefix.len..];
    return if (id.len == 0 or std.mem.indexOfScalar(u8, id, '/') != null) null else id;
}

fn sessionIdFromPath(path: []const u8) ?u32 {
    const prefix = "/org/freedesktop/secrets/session/s";
    if (!std.mem.startsWith(u8, path, prefix)) return null;
    return std.fmt.parseInt(u32, path[prefix.len..], 10) catch null;
}

fn itemPathAlloc(gpa: Allocator, id: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "{s}/{s}", .{ collection_path, id });
}

fn parseStoreId(encoded: []const u8) ![vault.store_id_len]u8 {
    if (encoded.len != vault.store_id_len * 2) return error.InvalidVault;
    var result: [vault.store_id_len]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch return error.InvalidVault;
    return result;
}

fn base64EncodeAlloc(gpa: Allocator, bytes: []const u8) ![]u8 {
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const output = try gpa.alloc(u8, encoder.calcSize(bytes.len));
    _ = encoder.encode(output, bytes);
    return output;
}

fn base64DecodeAlloc(gpa: Allocator, encoded: []const u8) ![]u8 {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const length = decoder.calcSizeForSlice(encoded) catch return error.InvalidVault;
    const output = try gpa.alloc(u8, length);
    errdefer gpa.free(output);
    decoder.decode(output, encoded) catch return error.InvalidVault;
    return output;
}

fn unixNow() u64 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return @intCast(@max(@as(i64, 0), std.Io.Clock.real.now(io).toSeconds()));
}

fn secureRandom(output: []u8) void {
    const io = std.Io.Threaded.global_single_threaded.io();
    io.randomSecure(output) catch io.random(output);
}

fn aesCbcEncrypt(gpa: Allocator, key: [16]u8, iv: [16]u8, plaintext: []const u8) ![]u8 {
    const padding: u8 = @intCast(16 - (plaintext.len % 16));
    const output = try gpa.alloc(u8, plaintext.len + padding);
    @memcpy(output[0..plaintext.len], plaintext);
    @memset(output[plaintext.len..], padding);
    const context = Aes128.initEnc(key);
    var previous = iv;
    var offset: usize = 0;
    while (offset < output.len) : (offset += 16) {
        var block: [16]u8 = undefined;
        for (0..16) |index| block[index] = output[offset + index] ^ previous[index];
        context.encrypt(output[offset..][0..16], &block);
        @memcpy(&previous, output[offset..][0..16]);
    }
    return output;
}

fn aesCbcDecrypt(gpa: Allocator, key: [16]u8, iv: [16]u8, ciphertext: []const u8) ![]u8 {
    if (ciphertext.len == 0 or ciphertext.len % 16 != 0) return DispatchError.InvalidArgs;
    const output = try gpa.dupe(u8, ciphertext);
    errdefer gpa.free(output);
    const context = Aes128.initDec(key);
    var previous = iv;
    var offset: usize = 0;
    while (offset < output.len) : (offset += 16) {
        var carry: [16]u8 = undefined;
        @memcpy(&carry, output[offset..][0..16]);
        var block: [16]u8 = undefined;
        context.decrypt(&block, output[offset..][0..16]);
        for (0..16) |index| output[offset + index] = block[index] ^ previous[index];
        previous = carry;
    }
    const padding = output[output.len - 1];
    if (padding == 0 or padding > 16 or padding > output.len) return DispatchError.InvalidArgs;
    var mismatch: u8 = 0;
    for (0..16) |index| {
        const check: u8 = @intFromBool(index + padding >= 16);
        mismatch |= (output[output.len - 16 + index] ^ padding) & (0 -% check);
    }
    if (mismatch != 0) return DispatchError.InvalidArgs;
    const final_length = output.len - padding;
    if (gpa.resize(output, final_length)) return output[0..final_length];
    const trimmed = try gpa.dupe(u8, output[0..final_length]);
    std.crypto.secureZero(u8, output);
    gpa.free(output);
    return trimmed;
}

const dh_prime_bytes = 128;
const DhModulus = std.crypto.ff.Modulus(1024);
const DhFe = DhModulus.Fe;
const dh_prime: [dh_prime_bytes]u8 = .{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};
const dh_generator: [dh_prime_bytes]u8 = blk: {
    var value: [dh_prime_bytes]u8 = @splat(0);
    value[dh_prime_bytes - 1] = 2;
    break :blk value;
};

const DhKeyPair = struct {
    private: [dh_prime_bytes]u8,
    public: [dh_prime_bytes]u8,
};

fn generateDhKeyPair(random: std.Random) !DhKeyPair {
    var result: DhKeyPair = undefined;
    while (true) {
        random.bytes(&result.private);
        result.private[0] &= 0x7f;
        var nonzero: u8 = 0;
        for (result.private) |byte| nonzero |= byte;
        if (nonzero != 0) break;
    }
    const modulus = try DhModulus.fromBytes(&dh_prime, .big);
    const generator = try DhFe.fromBytes(modulus, &dh_generator, .big);
    const public = try modulus.powWithEncodedExponent(generator, &result.private, .big);
    try public.toBytes(&result.public, .big);
    return result;
}

fn deriveDhSharedKey(private: [dh_prime_bytes]u8, peer: []const u8) ![16]u8 {
    if (peer.len == 0 or peer.len > dh_prime_bytes) return DispatchError.InvalidArgs;
    var padded: [dh_prime_bytes]u8 = @splat(0);
    @memcpy(padded[dh_prime_bytes - peer.len ..], peer);
    var nonzero: u8 = 0;
    for (padded) |byte| nonzero |= byte;
    if (nonzero == 0) return DispatchError.InvalidArgs;
    const modulus = try DhModulus.fromBytes(&dh_prime, .big);
    const peer_value = try DhFe.fromBytes(modulus, &padded, .big);
    const shared = try modulus.powWithEncodedExponent(peer_value, &private, .big);
    var shared_bytes: [dh_prime_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &shared_bytes);
    try shared.toBytes(&shared_bytes, .big);
    var prk = HkdfSha256.extract(&.{}, &shared_bytes);
    defer std.crypto.secureZero(u8, &prk);
    var key: [16]u8 = undefined;
    HkdfSha256.expand(&key, &.{}, prk);
    return key;
}

const DaemonRuntimeState = union(enum) {
    not_running,
    locked,
    unlocked: u32,
};

const TestEnvironment = struct {
    home: ?[]const u8 = null,
    xdg_data_home: ?[]const u8 = null,
    xdg_config_home: ?[]const u8 = null,
    exe_path: ?[]const u8 = null,
    systemctl_fn: ?*const fn (argv: []const []const u8) bool = null,
    daemon_state: DaemonRuntimeState = .not_running,
};

var test_env_override: ?TestEnvironment = null;

pub fn resolveServicePathsFromDirs(
    gpa: Allocator,
    home: ?[]const u8,
    xdg_data_home: ?[]const u8,
    xdg_config_home: ?[]const u8,
) !ServicePaths {
    const dbus_service_path = blk: {
        if (xdg_data_home) |data_dir| {
            if (data_dir.len > 0 and std.fs.path.isAbsolute(data_dir)) {
                break :blk try std.fs.path.join(gpa, &.{ data_dir, "dbus-1", "services", "org.freedesktop.secrets.service" });
            }
        }
        const home_dir = home orelse return error.HomeNotFound;
        if (home_dir.len == 0) return error.HomeNotFound;
        break :blk try std.fs.path.join(gpa, &.{ home_dir, ".local", "share", "dbus-1", "services", "org.freedesktop.secrets.service" });
    };
    errdefer gpa.free(dbus_service_path);

    const systemd_unit_path = blk: {
        if (xdg_config_home) |config_dir| {
            if (config_dir.len > 0 and std.fs.path.isAbsolute(config_dir)) {
                break :blk try std.fs.path.join(gpa, &.{ config_dir, "systemd", "user", "keyring.service" });
            }
        }
        const home_dir = home orelse return error.HomeNotFound;
        if (home_dir.len == 0) return error.HomeNotFound;
        break :blk try std.fs.path.join(gpa, &.{ home_dir, ".config", "systemd", "user", "keyring.service" });
    };

    return .{
        .dbus_service_path = dbus_service_path,
        .systemd_unit_path = systemd_unit_path,
    };
}

fn resolveServicePaths(gpa: Allocator) !ServicePaths {
    if (test_env_override) |env| {
        return resolveServicePathsFromDirs(gpa, env.home, env.xdg_data_home, env.xdg_config_home);
    }
    const home = getEnvVarOwned(gpa, "HOME");
    defer if (home) |v| gpa.free(v);
    const xdg_data_home = getEnvVarOwned(gpa, "XDG_DATA_HOME");
    defer if (xdg_data_home) |v| gpa.free(v);
    const xdg_config_home = getEnvVarOwned(gpa, "XDG_CONFIG_HOME");
    defer if (xdg_config_home) |v| gpa.free(v);
    return resolveServicePathsFromDirs(gpa, home, xdg_data_home, xdg_config_home);
}

fn validateExecutablePath(exe_path: []const u8) !void {
    if (exe_path.len == 0 or std.mem.indexOfAny(u8, exe_path, "\r\n\x00") != null) {
        return error.InvalidExecutablePath;
    }
}

pub fn formatDbusServiceFile(gpa: Allocator, exe_path: []const u8) ![]u8 {
    try validateExecutablePath(exe_path);
    var out = std.Io.Writer.Allocating.init(gpa);
    errdefer out.deinit();

    try out.writer.writeAll(managed_marker ++ "\n[D-BUS Service]\nName=org.freedesktop.secrets\nExec=");
    if (std.mem.indexOfAny(u8, exe_path, " \t\"'\\$`") != null) {
        try out.writer.writeByte('"');
        for (exe_path) |c| {
            if (c == '\\' or c == '"' or c == '$' or c == '`') {
                try out.writer.writeByte('\\');
            }
            try out.writer.writeByte(c);
        }
        try out.writer.writeByte('"');
    } else {
        try out.writer.writeAll(exe_path);
    }
    try out.writer.writeAll(" service\nSystemdService=keyring.service\n");
    return out.toOwnedSlice();
}

pub fn formatSystemdUnitFile(gpa: Allocator, exe_path: []const u8) ![]u8 {
    try validateExecutablePath(exe_path);
    var out = std.Io.Writer.Allocating.init(gpa);
    errdefer out.deinit();

    try out.writer.writeAll(
        managed_marker ++
            "\n[Unit]\nDescription=Keyring Secret Service\n\n[Service]\nType=dbus\nBusName=org.freedesktop.secrets\nExecStart=",
    );
    if (std.mem.indexOfAny(u8, exe_path, " \t\"'\\;") != null) {
        try out.writer.writeByte('"');
        for (exe_path) |c| {
            if (c == '\\' or c == '"') {
                try out.writer.writeByte('\\');
                try out.writer.writeByte(c);
            } else if (c == '%') {
                try out.writer.writeAll("%%");
            } else if (c == '$') {
                try out.writer.writeAll("$$");
            } else {
                try out.writer.writeByte(c);
            }
        }
        try out.writer.writeByte('"');
    } else {
        for (exe_path) |c| {
            if (c == '%') {
                try out.writer.writeAll("%%");
            } else if (c == '$') {
                try out.writer.writeAll("$$");
            } else {
                try out.writer.writeByte(c);
            }
        }
    }
    try out.writer.writeAll(" service\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n");
    return out.toOwnedSlice();
}

pub fn isManagedUnitContent(contents: []const u8) bool {
    if (std.mem.indexOf(u8, contents, managed_marker) != null) return true;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;
        const rhs = if (std.mem.startsWith(u8, line, "Exec="))
            line["Exec=".len..]
        else if (std.mem.startsWith(u8, line, "ExecStart="))
            line["ExecStart=".len..]
        else
            continue;
        if (execInvokesKeyringService(rhs)) return true;
    }
    return false;
}

fn execInvokesKeyringService(raw_rhs: []const u8) bool {
    var rhs = std.mem.trimStart(u8, raw_rhs, " \t");
    while (rhs.len > 0 and std.mem.indexOfScalar(u8, "-@:+!", rhs[0]) != null) {
        rhs = rhs[1..];
    }
    rhs = std.mem.trimStart(u8, rhs, " \t");
    if (rhs.len == 0) return false;

    var exe_token: []const u8 = "";
    var rest: []const u8 = "";
    if (rhs[0] == '"') {
        var idx: usize = 1;
        while (idx < rhs.len) : (idx += 1) {
            if (rhs[idx] == '\\' and idx + 1 < rhs.len) {
                idx += 1;
                continue;
            }
            if (rhs[idx] == '"') break;
        }
        if (idx >= rhs.len) return false;
        exe_token = rhs[1..idx];
        rest = std.mem.trimStart(u8, rhs[idx + 1 ..], " \t");
    } else if (rhs[0] == '\'') {
        const close_idx = std.mem.indexOfScalarPos(u8, rhs, 1, '\'') orelse return false;
        exe_token = rhs[1..close_idx];
        rest = std.mem.trimStart(u8, rhs[close_idx + 1 ..], " \t");
    } else {
        const split_idx = std.mem.indexOfAny(u8, rhs, " \t") orelse return false;
        exe_token = rhs[0..split_idx];
        rest = std.mem.trimStart(u8, rhs[split_idx..], " \t");
    }

    var base = exe_token;
    if (std.mem.lastIndexOfAny(u8, base, "/\\")) |sep| {
        base = base[sep + 1 ..];
    }
    if (!std.mem.eql(u8, base, "keyring") and !std.ascii.eqlIgnoreCase(base, "keyring.exe")) {
        return false;
    }

    const arg_end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
    return std.mem.eql(u8, rest[0..arg_end], "service");
}

pub fn resolveInstallExecutablePath(gpa: Allocator, io: std.Io, home: ?[]const u8) ![]u8 {
    if (test_env_override) |env| {
        if (env.exe_path) |override_exe| {
            return gpa.dupe(u8, override_exe);
        }
    }
    if (home) |home_dir| {
        if (home_dir.len > 0) {
            const local_bin_exe = try std.fs.path.join(gpa, &.{ home_dir, ".local", "bin", "keyring" });
            if (regularFileExists(io, local_bin_exe)) return local_bin_exe;
            gpa.free(local_bin_exe);
        }
    }
    return std.process.executablePathAlloc(io, gpa);
}

fn regularFileExists(io: std.Io, path: []const u8) bool {
    const st = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return st.kind == .file;
}

fn readUnitFileIfExists(gpa: Allocator, io: std.Io, path: []const u8) !?[]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(256 * 1024)) catch |err| switch (err) {
        error.FileNotFound => null,
        else => err,
    };
}

fn writeUnitFileAtomic(gpa: Allocator, io: std.Io, path: []const u8, contents: []const u8) !void {
    if (std.fs.path.dirname(path)) |parent| {
        if (parent.len > 0) {
            _ = try std.Io.Dir.cwd().createDirPathStatus(io, parent, .default_dir);
        }
    }
    var random_suffix: [8]u8 = undefined;
    secureRandom(&random_suffix);
    const suffix_hex = std.fmt.bytesToHex(random_suffix, .lower);
    const tmp_path = try std.fmt.allocPrint(gpa, "{s}.tmp.{s}", .{ path, suffix_hex });
    defer gpa.free(tmp_path);

    var renamed = false;
    defer if (!renamed) std.Io.Dir.cwd().deleteFile(io, tmp_path) catch {};
    {
        var file = try std.Io.Dir.cwd().createFile(io, tmp_path, .{
            .read = true,
            .truncate = true,
            .exclusive = true,
            .permissions = .default_file,
        });
        defer file.close(io);
        try file.writeStreamingAll(io, contents);
        try file.sync(io);
    }
    try std.Io.Dir.cwd().rename(tmp_path, std.Io.Dir.cwd(), path, io);
    renamed = true;
}

fn checkForeignConflict(gpa: Allocator, io: std.Io, path: []const u8) !bool {
    const existing = (try readUnitFileIfExists(gpa, io, path)) orelse return false;
    defer gpa.free(existing);
    return !isManagedUnitContent(existing);
}

fn currentProcessEnviron() std.process.Environ {
    if (builtin.os.tag == .windows) return .{ .block = .global };
    if (builtin.os.tag == .wasi) return .empty;
    var count: usize = 0;
    while (std.c.environ[count] != null) : (count += 1) {}
    return .{ .block = .{ .slice = @ptrCast(std.c.environ[0..count :null]) } };
}

fn getEnvVarOwned(gpa: Allocator, name: []const u8) ?[]u8 {
    if (builtin.os.tag == .wasi) return null;
    if (builtin.os.tag == .windows) {
        var map = std.process.Environ.createMap(.{ .block = .global }, gpa) catch return null;
        defer map.deinit();
        if (map.get(name)) |value| return gpa.dupe(u8, value) catch null;
        return null;
    }
    var index: usize = 0;
    while (std.c.environ[index]) |entry| : (index += 1) {
        const item = std.mem.span(entry);
        if (item.len > name.len and item[name.len] == '=' and std.mem.eql(u8, item[0..name.len], name)) {
            return gpa.dupe(u8, item[name.len + 1 ..]) catch null;
        }
    }
    return null;
}

fn runSystemctlUser(gpa: Allocator, args: []const []const u8) bool {
    if (test_env_override) |env| {
        if (env.systemctl_fn) |hook| return hook(args);
        return false;
    }
    var threaded = std.Io.Threaded.init(gpa, .{ .environ = currentProcessEnviron() });
    defer threaded.deinit();
    const io = threaded.io();

    var argv_list: std.ArrayList([]const u8) = .empty;
    defer argv_list.deinit(gpa);
    argv_list.appendSlice(gpa, &.{ "systemctl", "--user" }) catch return false;
    argv_list.appendSlice(gpa, args) catch return false;

    const result = std.process.run(gpa, io, .{
        .argv = argv_list.items,
        .stdout_limit = .limited(16 * 1024),
        .stderr_limit = .limited(16 * 1024),
    }) catch return false;
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn isVaultEnrolled(gpa: Allocator) bool {
    if (vault.loadVaultEnvelope(gpa)) |document_value| {
        var document = document_value;
        document.deinit();
        return true;
    } else |_| {
        return false;
    }
}

pub fn runInstall(gpa: Allocator, opts: InstallOptions, stdout: *std.Io.Writer, stderr: *std.Io.Writer) !u8 {
    if (builtin.os.tag != .linux and test_env_override == null) {
        try stderr.writeAll(unsupported_platform_message);
        try stderr.flush();
        return 1;
    }

    const io = std.Io.Threaded.global_single_threaded.io();
    var paths = resolveServicePaths(gpa) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            try stderr.writeAll("keyring: service install: HOME is not set\n");
            try stderr.flush();
            return 1;
        },
    };
    defer paths.deinit(gpa);

    if (!opts.force) {
        for ([_][]const u8{ paths.dbus_service_path, paths.systemd_unit_path }) |target_path| {
            if (try checkForeignConflict(gpa, io, target_path)) {
                try stderr.print(
                    "keyring: service install: refusing to overwrite foreign service file {s} (re-run with --force to override)\n",
                    .{target_path},
                );
                try stderr.flush();
                return 1;
            }
        }
    }

    const home_owned = if (test_env_override) |env|
        (if (env.home) |h| try gpa.dupe(u8, h) else null)
    else
        getEnvVarOwned(gpa, "HOME");
    defer if (home_owned) |h| gpa.free(h);

    const exe_path = try resolveInstallExecutablePath(gpa, io, home_owned);
    defer gpa.free(exe_path);

    const dbus_contents = try formatDbusServiceFile(gpa, exe_path);
    defer gpa.free(dbus_contents);
    const systemd_contents = try formatSystemdUnitFile(gpa, exe_path);
    defer gpa.free(systemd_contents);

    try writeUnitFileAtomic(gpa, io, paths.dbus_service_path, dbus_contents);
    try writeUnitFileAtomic(gpa, io, paths.systemd_unit_path, systemd_contents);

    const reloaded = runSystemctlUser(gpa, &.{"daemon-reload"});
    const enabled = reloaded and runSystemctlUser(gpa, &.{ "enable", "--now", "keyring.service" });

    try stdout.print("Installed D-Bus activation: {s}\n", .{paths.dbus_service_path});
    try stdout.print("Installed systemd user unit: {s}\n", .{paths.systemd_unit_path});
    if (enabled) {
        try stdout.writeAll("Enabled and started keyring.service via systemctl --user.\n");
    } else {
        try stdout.writeAll("Note: systemctl --user unavailable; D-Bus activation will start keyring service on demand.\n");
    }
    if (isVaultEnrolled(gpa)) {
        try stdout.writeAll("Next step: run 'keyring unlock' to unlock the Secret Service.\n");
    } else {
        try stdout.writeAll("Next steps: run 'keyring enroll' to initialize the vault, then 'keyring unlock' to unlock.\n");
    }
    try stdout.flush();
    return 0;
}

pub fn runUninstall(gpa: Allocator, opts: UninstallOptions, stdout: *std.Io.Writer, stderr: *std.Io.Writer) !u8 {
    if (builtin.os.tag != .linux and test_env_override == null) {
        try stderr.writeAll(unsupported_platform_message);
        try stderr.flush();
        return 1;
    }

    const io = std.Io.Threaded.global_single_threaded.io();
    var paths = resolveServicePaths(gpa) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            try stderr.writeAll("keyring: service uninstall: HOME is not set\n");
            try stderr.flush();
            return 1;
        },
    };
    defer paths.deinit(gpa);

    if (!opts.force) {
        for ([_][]const u8{ paths.dbus_service_path, paths.systemd_unit_path }) |target_path| {
            if (try checkForeignConflict(gpa, io, target_path)) {
                try stderr.print(
                    "keyring: service uninstall: refusing to remove foreign service file {s} (re-run with --force to override)\n",
                    .{target_path},
                );
                try stderr.flush();
                return 1;
            }
        }
    }

    _ = runSystemctlUser(gpa, &.{ "disable", "--now", "keyring.service" });
    _ = runSystemctlUser(gpa, &.{"daemon-reload"});

    var removed_any = false;
    for ([_][]const u8{ paths.dbus_service_path, paths.systemd_unit_path }) |target_path| {
        var removed = true;
        std.Io.Dir.cwd().deleteFile(io, target_path) catch |err| switch (err) {
            error.FileNotFound => removed = false,
            else => return err,
        };
        if (removed) {
            removed_any = true;
            try stdout.print("Removed {s}\n", .{target_path});
        }
    }
    if (!removed_any) {
        try stdout.writeAll("Keyring Secret Service units were not installed.\n");
    }
    try stdout.flush();
    return 0;
}

pub fn runStatus(gpa: Allocator, stdout: *std.Io.Writer, stderr: *std.Io.Writer) !u8 {
    if (builtin.os.tag != .linux and test_env_override == null) {
        try stderr.writeAll(unsupported_platform_message);
        try stderr.flush();
        return 1;
    }

    const io = std.Io.Threaded.global_single_threaded.io();
    const store_path = vault.vaultPath(gpa) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            try stderr.writeAll("keyring: service status: HOME is not set\n");
            try stderr.flush();
            return 1;
        },
    };
    defer gpa.free(store_path);

    var paths = resolveServicePaths(gpa) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            try stderr.writeAll("keyring: service status: HOME is not set\n");
            try stderr.flush();
            return 1;
        },
    };
    defer paths.deinit(gpa);

    if (vault.loadVaultEnvelope(gpa)) |document_value| {
        var document = document_value;
        defer document.deinit();
        try stdout.print("vault: enrolled ({d} keys) ({s})\n", .{ document.value.prf_slots.len, store_path });
    } else |err| switch (err) {
        error.VaultNotFound => try stdout.print("vault: not enrolled ({s})\n", .{store_path}),
        else => return err,
    }

    try writeUnitInstallStatus(gpa, io, stdout, "dbus activation", paths.dbus_service_path);
    try writeUnitInstallStatus(gpa, io, stdout, "systemd user unit", paths.systemd_unit_path);

    const daemon_state: DaemonRuntimeState = if (test_env_override) |env|
        env.daemon_state
    else if (builtin.os.tag == .linux) blk: {
        if (Linux.queryRunningStatus(gpa)) |status_val| {
            var st = status_val;
            defer st.deinit(gpa);
            break :blk if (st.locked) .locked else .{ .unlocked = st.item_count };
        }
        break :blk .not_running;
    } else .not_running;

    switch (daemon_state) {
        .unlocked => |count| try stdout.print("daemon: running (unlocked, {d} items)\n", .{count}),
        .locked => try stdout.writeAll("daemon: running (locked)\n"),
        .not_running => try stdout.writeAll("daemon: not running\n"),
    }

    try stdout.flush();
    return 0;
}

fn writeUnitInstallStatus(
    gpa: Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    label: []const u8,
    path: []const u8,
) !void {
    if (try readUnitFileIfExists(gpa, io, path)) |contents| {
        defer gpa.free(contents);
        if (isManagedUnitContent(contents)) {
            try stdout.print("{s}: installed ({s})\n", .{ label, path });
        } else {
            try stdout.print("{s}: installed (foreign: {s})\n", .{ label, path });
        }
    } else {
        try stdout.print("{s}: not installed\n", .{label});
    }
}

pub fn runDaemon(gpa: Allocator, replace: bool, lock_timeout_seconds: ?u32) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
    return Linux.runDaemon(gpa, replace, lock_timeout_seconds);
}

pub fn clientUnlockWithMasterKey(gpa: Allocator, master_key_value: [vault.dek_len]u8) !bool {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
    return Linux.clientUnlockWithMasterKey(gpa, master_key_value);
}

pub fn clientLockAll(gpa: Allocator) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
    return Linux.clientLockAll(gpa);
}

pub fn clientGetStatus(gpa: Allocator) !Status {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
    return Linux.clientGetStatus(gpa);
}

const Linux = if (builtin.os.tag == .linux) struct {
    const linux = std.os.linux;
    const connection = dbus.connection;

    fn runDaemon(gpa: Allocator, replace: bool, lock_timeout_seconds: ?u32) !void {
        var conn = try connection.connectSession(gpa);
        defer conn.deinit();

        var request_body: std.ArrayList(u8) = .empty;
        defer request_body.deinit(gpa);
        var writer = wire.Writer.init(gpa, &request_body);
        try writer.writeString(service_destination);
        try writer.writeU32(if (replace) 0x7 else 0x4);
        var request_reply = try connection.call(&conn, .{
            .destination = "org.freedesktop.DBus",
            .path = "/org/freedesktop/DBus",
            .interface = "org.freedesktop.DBus",
            .member = "RequestName",
            .signature = "su",
            .body = request_body.items,
        });
        defer request_reply.deinit();
        if (request_reply.err != null) return error.RequestNameFailed;
        var reply_reader = wire.Reader.init(request_reply.body);
        const request_result = reply_reader.readU32() catch return error.RequestNameFailed;
        if (request_result != 1 and request_result != 4) return error.NameAlreadyOwned;

        var state = try ServiceState.init(gpa);
        defer state.deinit();
        state.next_serial = conn.next_serial;
        var last_activity_sec: u64 = unixNow();
        while (true) {
            if (state.unlocked) {
                if (lock_timeout_seconds) |timeout_s| {
                    const now = unixNow();
                    if (state.checkIdleTimeout(now, last_activity_sec, timeout_s)) {
                        continue;
                    }
                    const deadline = last_activity_sec +| @as(u64, timeout_s);
                    const rem_sec = deadline - now;
                    const timeout_ms: i32 = @intCast(@min(rem_sec *| 1000, @as(u64, std.math.maxInt(i32))));
                    var pfd = [1]std.posix.pollfd{.{
                        .fd = conn.fd,
                        .events = std.posix.POLL.IN,
                        .revents = 0,
                    }};
                    const ready = std.posix.poll(&pfd, timeout_ms) catch return error.ReadFailed;
                    if (ready == 0) continue;
                }
            }
            const frame = try readFrame(gpa, conn.fd);
            defer {
                std.crypto.secureZero(u8, frame);
                gpa.free(frame);
            }
            const parsed = message.parse(frame) catch continue;
            if (parsed.header.msg_type != .method_call) continue;
            if (parsed.header.destination) |destination| {
                const for_service = std.mem.eql(u8, destination, service_destination);
                const for_unique = conn.unique_name != null and std.mem.eql(u8, destination, conn.unique_name.?);
                if (!for_service and !for_unique) continue;
            }
            _ = state.checkIdleTimeout(unixNow(), last_activity_sec, lock_timeout_seconds);
            var outbound = try state.handleMessage(parsed);
            defer outbound.deinit();
            for (outbound.frames.items) |response| try writeAll(conn.fd, response);
            last_activity_sec = unixNow();
        }
    }

    fn clientUnlockWithMasterKey(gpa: Allocator, master_key_value: [vault.dek_len]u8) !bool {
        var master_key = master_key_value;
        defer std.crypto.secureZero(u8, &master_key);
        var conn = try connection.connectSession(gpa);
        defer conn.deinit();
        var body: std.ArrayList(u8) = .empty;
        defer {
            std.crypto.secureZero(u8, body.items);
            body.deinit(gpa);
        }
        var writer = wire.Writer.init(gpa, &body);
        try writeByteArray(&writer, &master_key);
        var reply = try connection.call(&conn, .{
            .destination = service_destination,
            .path = service_path,
            .interface = control_interface,
            .member = "UnlockWithMasterKey",
            .signature = "ay",
            .body = body.items,
        });
        defer reply.deinit();
        if (reply.err != null) return error.ServiceCallFailed;
        var reader = wire.Reader.init(reply.body);
        return reader.readBool() catch error.ServiceCallFailed;
    }

    fn clientLockAll(gpa: Allocator) !void {
        var conn = try connection.connectSession(gpa);
        defer conn.deinit();
        var reply = try connection.call(&conn, .{
            .destination = service_destination,
            .path = service_path,
            .interface = control_interface,
            .member = "LockAll",
            .signature = null,
            .body = &.{},
        });
        defer reply.deinit();
        if (reply.err != null) return error.ServiceCallFailed;
    }

    fn clientGetStatus(gpa: Allocator) !Status {
        var conn = try connection.connectSession(gpa);
        defer conn.deinit();
        var reply = try connection.call(&conn, .{
            .destination = service_destination,
            .path = service_path,
            .interface = control_interface,
            .member = "GetStatus",
            .signature = null,
            .body = &.{},
        });
        defer reply.deinit();
        if (reply.err != null) return error.ServiceCallFailed;
        var reader = wire.Reader.init(reply.body);
        const initialized = reader.readBool() catch return error.ServiceCallFailed;
        const locked = reader.readBool() catch return error.ServiceCallFailed;
        const item_count = reader.readU32() catch return error.ServiceCallFailed;
        const path = reader.readString() catch return error.ServiceCallFailed;
        return .{
            .initialized = initialized,
            .locked = locked,
            .item_count = item_count,
            .store_path = try gpa.dupe(u8, path),
        };
    }

    fn queryRunningStatus(gpa: Allocator) ?Status {
        var conn = connection.connectSession(gpa) catch return null;
        defer conn.deinit();

        var owner_body: std.ArrayList(u8) = .empty;
        defer owner_body.deinit(gpa);
        var writer = wire.Writer.init(gpa, &owner_body);
        writer.writeString(service_destination) catch return null;
        var owner_reply = connection.call(&conn, .{
            .destination = "org.freedesktop.DBus",
            .path = "/org/freedesktop/DBus",
            .interface = "org.freedesktop.DBus",
            .member = "GetNameOwner",
            .signature = "s",
            .body = owner_body.items,
        }) catch return null;
        defer owner_reply.deinit();
        if (owner_reply.err != null) return null;
        var owner_reader = wire.Reader.init(owner_reply.body);
        const owner_unique_name = owner_reader.readString() catch return null;
        if (owner_unique_name.len == 0) return null;

        var reply = connection.call(&conn, .{
            .destination = owner_unique_name,
            .path = service_path,
            .interface = control_interface,
            .member = "GetStatus",
            .signature = null,
            .body = &.{},
        }) catch return null;
        defer reply.deinit();
        if (reply.err != null) return null;
        var reader = wire.Reader.init(reply.body);
        const initialized = reader.readBool() catch return null;
        const locked = reader.readBool() catch return null;
        const item_count = reader.readU32() catch return null;
        const path = reader.readString() catch return null;
        const owned_path = gpa.dupe(u8, path) catch return null;
        return .{
            .initialized = initialized,
            .locked = locked,
            .item_count = item_count,
            .store_path = owned_path,
        };
    }

    fn readFrame(gpa: Allocator, fd: linux.fd_t) ![]u8 {
        var prefix: [message.min_header_bytes]u8 = undefined;
        try readExact(fd, &prefix);
        const total = try message.totalLength(prefix);
        if (total < prefix.len or total > 64 * 1024 * 1024) return error.InvalidFrame;
        const frame = try gpa.alloc(u8, total);
        errdefer gpa.free(frame);
        @memcpy(frame[0..prefix.len], &prefix);
        try readExact(fd, frame[prefix.len..]);
        return frame;
    }

    fn readExact(fd: linux.fd_t, output: []u8) !void {
        var offset: usize = 0;
        while (offset < output.len) {
            const result = linux.read(fd, output[offset..].ptr, output.len - offset);
            switch (linux.errno(result)) {
                .SUCCESS => {
                    if (result == 0) return error.ReadFailed;
                    offset += result;
                },
                .INTR => continue,
                else => return error.ReadFailed,
            }
        }
    }

    fn writeAll(fd: linux.fd_t, bytes: []const u8) !void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            const result = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
            switch (linux.errno(result)) {
                .SUCCESS => {
                    if (result == 0) return error.WriteFailed;
                    offset += result;
                },
                .INTR => continue,
                else => return error.WriteFailed,
            }
        }
    }
} else struct {};

fn testVaultPath(tmp: *std.testing.TmpDir, gpa: Allocator) ![]u8 {
    var root: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(std.Io.Threaded.global_single_threaded.io(), &root);
    return std.fs.path.join(gpa, &.{ root[0..length], "vault.json" });
}

fn testDispatch(
    state: *ServiceState,
    path: []const u8,
    interface: []const u8,
    member: []const u8,
    signature: ?[]const u8,
    body: []const u8,
) !OutboundMessages {
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(std.testing.allocator);
    try message.serialize(std.testing.allocator, &frame, .{
        .msg_type = .method_call,
        .serial = 42,
        .path = path,
        .interface = interface,
        .member = member,
        .destination = service_destination,
        .sender = ":1.99",
        .signature = signature,
    }, body);
    return state.handleMessage(try message.parse(frame.items));
}

fn testReply(out: *OutboundMessages) !message.Parsed {
    try std.testing.expect(out.frames.items.len >= 1);
    return message.parse(out.frames.items[0]);
}

fn expectReplyType(out: *OutboundMessages, expected: message.MessageType) !message.Parsed {
    const parsed = try testReply(out);
    try std.testing.expectEqual(expected, parsed.header.msg_type);
    return parsed;
}

fn writeTestAttributes(w: *wire.Writer, service_name: []const u8, username: []const u8, include_schema: bool) !void {
    const array = try w.beginArray(8);
    try w.alignStruct();
    try w.writeString("service");
    try w.writeString(service_name);
    try w.alignStruct();
    try w.writeString("username");
    try w.writeString(username);
    if (include_schema) {
        try w.alignStruct();
        try w.writeString("xdg:schema");
        try w.writeString(generic_item_type);
    }
    w.endArray(array);
}

fn writeTestSecret(w: *wire.Writer, session_path: []const u8, parameters: []const u8, value: []const u8) !void {
    try w.alignStruct();
    try w.writeObjectPath(session_path);
    try writeByteArray(w, parameters);
    try writeByteArray(w, value);
    try w.writeString("text/plain");
}

fn writeTestCreateItemBody(gpa: Allocator, body: *std.ArrayList(u8), session_path: []const u8, secret: []const u8) !void {
    var w = wire.Writer.init(gpa, body);
    const properties = try w.beginArray(8);
    try w.alignStruct();
    try w.writeString("org.freedesktop.Secret.Item.Label");
    try w.writeSignatureValue("s");
    try w.writeString("Example");
    try w.alignStruct();
    try w.writeString("org.freedesktop.Secret.Item.Attributes");
    try w.writeSignatureValue("a{ss}");
    try writeTestAttributes(&w, "example.test", "alice", true);
    w.endArray(properties);
    try writeTestSecret(&w, session_path, &.{}, secret);
    try w.writeBool(true);
}

test "service dispatch unlocks, serves both session algorithms, persists CRUD, and locks" {
    const gpa = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testVaultPath(&tmp, gpa);
    defer gpa.free(path);
    vault.vault_path_override = path;
    defer vault.vault_path_override = null;

    const prf_output: [vault.prf_salt_len]u8 = @splat(0x41);
    var enrolled = try vault.enrollInitialVault(gpa, io, .{
        .label = "primary",
        .credential_id = "service-test-credential",
        .cose_alg = -8,
        .public_key = &@as([32]u8, @splat(0x22)),
        .prf_output = prf_output,
        .created_at = 1_700_000_000,
    }, .{
        .payload_created = 1_700_000_000,
        .argon2_t = 1,
        .argon2_m = 1024,
        .argon2_p = 1,
    });
    defer enrolled.deinit();
    try vault.saveVaultEnvelope(gpa, &enrolled.document.value);

    var state = try ServiceState.init(gpa);
    defer state.deinit();

    {
        var out = try testDispatch(&state, service_path, control_interface, "GetStatus", null, &.{});
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expect(try r.readBool());
        try std.testing.expect(try r.readBool());
        try std.testing.expectEqual(@as(u32, 0), try r.readU32());
        try std.testing.expectEqualStrings(path, try r.readString());
    }

    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try writeTestAttributes(&w, "example.test", "alice", false);
        var out = try testDispatch(&state, service_path, service_interface, "SearchItems", "a{ss}", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        const unlocked = try r.beginArray(4);
        try std.testing.expect(!r.arrayHasMore(unlocked));
        r.pos = unlocked.end;
        const locked = try r.beginArray(4);
        try std.testing.expect(r.arrayHasMore(locked));
        try std.testing.expectEqualStrings(collection_path, try r.readObjectPath());
    }

    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        try writeTestCreateItemBody(gpa, &body, "/org/freedesktop/secrets/session/s1", "blocked");
        var out = try testDispatch(&state, collection_path, collection_interface, "CreateItem", "a{sv}(oayays)b", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .error_reply);
        try std.testing.expectEqualStrings("org.freedesktop.Secret.Error.IsLocked", reply.header.error_name.?);
    }

    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try writeObjectPathArray(&w, &.{collection_path});
        var out = try testDispatch(&state, service_path, service_interface, "Unlock", "ao", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        const objects = try r.beginArray(4);
        try std.testing.expect(!r.arrayHasMore(objects));
        r.pos = objects.end;
        try std.testing.expectEqualStrings(prompt_locked_path, try r.readObjectPath());
    }

    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString("");
        var out = try testDispatch(&state, prompt_locked_path, prompt_interface, "Prompt", "s", body.items);
        defer out.deinit();
        try std.testing.expectEqual(@as(usize, 2), out.frames.items.len);
        _ = try expectReplyType(&out, .method_return);
        const completed = try message.parse(out.frames.items[1]);
        try std.testing.expectEqual(message.MessageType.signal, completed.header.msg_type);
        try std.testing.expectEqualStrings("Completed", completed.header.member.?);
        var r = wire.Reader.init(completed.body);
        try std.testing.expect(try r.readBool());
        try std.testing.expectEqualStrings("ao", try r.readSignatureValue());
        const results = try r.beginArray(4);
        try std.testing.expect(!r.arrayHasMore(results));
    }

    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try writeByteArray(&w, &enrolled.dek);
        var out = try testDispatch(&state, service_path, control_interface, "UnlockWithMasterKey", "ay", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expect(try r.readBool());
        try std.testing.expect(state.unlocked);
    }

    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString("default");
        var out = try testDispatch(&state, service_path, service_interface, "ReadAlias", "s", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expectEqualStrings(collection_path, try r.readObjectPath());
    }

    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        const properties = try w.beginArray(8);
        w.endArray(properties);
        try w.writeString("default");
        var out = try testDispatch(&state, service_path, service_interface, "CreateCollection", "a{sv}s", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expectEqualStrings(collection_path, try r.readObjectPath());
        try std.testing.expectEqualStrings("/", try r.readObjectPath());
    }

    {
        var out = try testDispatch(&state, collection_alias_path, collection_interface, "Delete", null, &.{});
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expectEqualStrings("/", try r.readObjectPath());
    }

    var plain_session_path: []u8 = undefined;
    defer gpa.free(plain_session_path);
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString("plain");
        try w.writeSignatureValue("s");
        try w.writeString("");
        var out = try testDispatch(&state, service_path, service_interface, "OpenSession", "sv", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expectEqualStrings("s", try r.readSignatureValue());
        try std.testing.expectEqualStrings("", try r.readString());
        plain_session_path = try gpa.dupe(u8, try r.readObjectPath());
    }

    var dh_session_path: []u8 = undefined;
    defer gpa.free(dh_session_path);
    var client_dh_key: [16]u8 = undefined;
    defer std.crypto.secureZero(u8, &client_dh_key);
    {
        var prng = std.Random.DefaultPrng.init(0x12345678);
        var client_pair = try generateDhKeyPair(prng.random());
        defer std.crypto.secureZero(u8, &client_pair.private);
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString(dh_algorithm);
        try w.writeSignatureValue("ay");
        try writeByteArray(&w, &client_pair.public);
        var out = try testDispatch(&state, service_path, service_interface, "OpenSession", "sv", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expectEqualStrings("ay", try r.readSignatureValue());
        const server_public = try readByteArray(&r);
        client_dh_key = try deriveDhSharedKey(client_pair.private, server_public);
        dh_session_path = try gpa.dupe(u8, try r.readObjectPath());
    }

    var item_path: []u8 = undefined;
    defer gpa.free(item_path);
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        try writeTestCreateItemBody(gpa, &body, plain_session_path, "first-secret");
        var out = try testDispatch(&state, collection_path, collection_interface, "CreateItem", "a{sv}(oayays)b", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        item_path = try gpa.dupe(u8, try r.readObjectPath());
        try std.testing.expectEqualStrings("/", try r.readObjectPath());
    }

    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try writeTestAttributes(&w, "example.test", "alice", false);
        var out = try testDispatch(&state, service_path, service_interface, "SearchItems", "a{ss}", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        const unlocked = try r.beginArray(4);
        try std.testing.expect(r.arrayHasMore(unlocked));
        try std.testing.expectEqualStrings(item_path, try r.readObjectPath());
    }

    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try writeTestAttributes(&w, "example.test", "alice", false);
        var out = try testDispatch(&state, collection_alias_path, collection_interface, "SearchItems", "a{ss}", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        const matches = try r.beginArray(4);
        try std.testing.expect(r.arrayHasMore(matches));
        try std.testing.expectEqualStrings(item_path, try r.readObjectPath());
    }

    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try writeObjectPathArray(&w, &.{item_path});
        try w.writeObjectPath(plain_session_path);
        var out = try testDispatch(&state, service_path, service_interface, "GetSecrets", "aoo", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        const secrets = try r.beginArray(8);
        try std.testing.expect(r.arrayHasMore(secrets));
        try r.alignStruct();
        try std.testing.expectEqualStrings(item_path, try r.readObjectPath());
        const secret = try readSecretTuple(&r);
        try std.testing.expectEqualStrings("first-secret", secret.value);
    }

    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeObjectPath(plain_session_path);
        var out = try testDispatch(&state, item_path, item_interface, "GetSecret", "o", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        const secret = try readSecretTuple(&r);
        try std.testing.expectEqualStrings("first-secret", secret.value);
    }

    {
        const iv: [16]u8 = @splat(0x37);
        const ciphertext = try aesCbcEncrypt(gpa, client_dh_key, iv, "updated-secret");
        defer gpa.free(ciphertext);
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try writeTestSecret(&w, dh_session_path, &iv, ciphertext);
        var out = try testDispatch(&state, item_path, item_interface, "SetSecret", "(oayays)", body.items);
        defer out.deinit();
        _ = try expectReplyType(&out, .method_return);
    }

    {
        const session_id = sessionIdFromPath(dh_session_path).?;
        var out = try testDispatch(&state, dh_session_path, session_interface, "Close", null, &.{});
        defer out.deinit();
        _ = try expectReplyType(&out, .method_return);
        try std.testing.expect(state.sessions.get(session_id) == null);
    }

    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString(service_interface);
        try w.writeString("Collections");
        var out = try testDispatch(&state, service_path, properties_interface, "Get", "ss", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expectEqualStrings("ao", try r.readSignatureValue());
        const collections = try r.beginArray(4);
        try std.testing.expectEqualStrings(collection_path, try r.readObjectPath());
        try std.testing.expect(!r.arrayHasMore(collections));
    }

    inline for ([_]struct { path: []const u8, interface: []const u8, property: []const u8, expected_signature: []const u8 }{
        .{ .path = collection_path, .interface = collection_interface, .property = "Label", .expected_signature = "s" },
        .{ .path = item_path, .interface = item_interface, .property = "Type", .expected_signature = "s" },
    }) |target| {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString(target.interface);
        try w.writeString(target.property);
        var out = try testDispatch(&state, target.path, properties_interface, "Get", "ss", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expectEqualStrings(target.expected_signature, try r.readSignatureValue());
        _ = try r.readString();
    }

    inline for ([_]struct { path: []const u8, interface: []const u8 }{
        .{ .path = service_path, .interface = service_interface },
        .{ .path = collection_path, .interface = collection_interface },
        .{ .path = item_path, .interface = item_interface },
    }) |target| {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString(target.interface);
        var out = try testDispatch(&state, target.path, properties_interface, "GetAll", "s", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        const properties = try r.beginArray(8);
        try std.testing.expect(r.arrayHasMore(properties));
    }

    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try writeObjectPathArray(&w, &.{collection_path});
        var out = try testDispatch(&state, service_path, service_interface, "Lock", "ao", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        const locked = try r.beginArray(4);
        try std.testing.expectEqualStrings(collection_path, try r.readObjectPath());
        try std.testing.expect(!r.arrayHasMore(locked));
        r.pos = locked.end;
        try std.testing.expectEqualStrings("/", try r.readObjectPath());
        try std.testing.expect(!state.unlocked);
        try std.testing.expect(state.dek == null);
        try std.testing.expectEqual(@as(usize, 0), state.items.items.len);
    }

    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try writeByteArray(&w, &enrolled.dek);
        var out = try testDispatch(&state, service_path, control_interface, "UnlockWithMasterKey", "ay", body.items);
        defer out.deinit();
        _ = try expectReplyType(&out, .method_return);
        try std.testing.expectEqual(@as(usize, 1), state.items.items.len);
    }

    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeObjectPath(plain_session_path);
        var out = try testDispatch(&state, item_path, item_interface, "GetSecret", "o", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        const secret = try readSecretTuple(&r);
        try std.testing.expectEqualStrings("updated-secret", secret.value);
    }

    {
        var out = try testDispatch(&state, service_path, control_interface, "LockAll", null, &.{});
        defer out.deinit();
        _ = try expectReplyType(&out, .method_return);
        try std.testing.expect(!state.unlocked);
        try std.testing.expect(state.dek == null);
        try std.testing.expectEqual(@as(usize, 0), state.items.items.len);
    }

    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try writeByteArray(&w, &enrolled.dek);
        var out = try testDispatch(&state, service_path, control_interface, "UnlockWithMasterKey", "ay", body.items);
        defer out.deinit();
        _ = try expectReplyType(&out, .method_return);
    }

    {
        var out = try testDispatch(&state, item_path, item_interface, "Delete", null, &.{});
        defer out.deinit();
        _ = try expectReplyType(&out, .method_return);
        try std.testing.expectEqual(@as(usize, 0), state.items.items.len);
    }

    var document = try vault.loadVaultEnvelope(gpa);
    defer document.deinit();
    const store_id = try parseStoreId(document.value.store_id_hex);
    var payload = try vault.decryptPayload(
        gpa,
        enrolled.dek,
        store_id,
        document.value.payload_nonce_b64,
        document.value.payload_ciphertext_b64,
    );
    defer payload.deinit();
    try std.testing.expectEqual(@as(usize, 0), payload.value.items.len);
}

test "standard D-Bus interfaces and prompt dismissal reply immediately" {
    var state = try ServiceState.init(std.testing.allocator);
    defer state.deinit();

    {
        var out = try testDispatch(&state, service_path, peer_interface, "Ping", null, &.{});
        defer out.deinit();
        _ = try expectReplyType(&out, .method_return);
    }
    {
        var out = try testDispatch(&state, service_path, peer_interface, "GetMachineId", null, &.{});
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expectEqualStrings("00000000000000000000000000000000", try r.readString());
    }
    {
        var out = try testDispatch(&state, collection_path, introspectable_interface, "Introspect", null, &.{});
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expectEqualStrings("<node/>", try r.readString());
    }
    {
        var out = try testDispatch(&state, prompt_locked_path, prompt_interface, "Dismiss", null, &.{});
        defer out.deinit();
        try std.testing.expectEqual(@as(usize, 2), out.frames.items.len);
        const signal = try message.parse(out.frames.items[1]);
        var r = wire.Reader.init(signal.body);
        try std.testing.expect(try r.readBool());
    }
}

fn testDispatchFull(
    state: *ServiceState,
    flags: message.Flags,
    path: []const u8,
    interface: ?[]const u8,
    member: []const u8,
    signature: ?[]const u8,
    body: []const u8,
) !OutboundMessages {
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(std.testing.allocator);
    try message.serialize(std.testing.allocator, &frame, .{
        .msg_type = .method_call,
        .flags = flags,
        .serial = 42,
        .path = path,
        .interface = interface,
        .member = member,
        .destination = service_destination,
        .sender = ":1.99",
        .signature = signature,
    }, body);
    return state.handleMessage(try message.parse(frame.items));
}

fn expectCollectionSignal(raw_frame: []const u8, expected_member: []const u8, expected_item_path: []const u8) !void {
    const parsed = try message.parse(raw_frame);
    try std.testing.expectEqual(message.MessageType.signal, parsed.header.msg_type);
    try std.testing.expectEqualStrings(collection_path, parsed.header.path.?);
    try std.testing.expectEqualStrings(collection_interface, parsed.header.interface.?);
    try std.testing.expectEqualStrings(expected_member, parsed.header.member.?);
    try std.testing.expectEqualStrings("o", parsed.header.signature.?);
    var r = wire.Reader.init(parsed.body);
    try std.testing.expectEqualStrings(expected_item_path, try r.readObjectPath());
}

fn writeCopilotCreateItemBody(
    gpa: Allocator,
    body: *std.ArrayList(u8),
    label: []const u8,
    service_name: []const u8,
    username: []const u8,
    session_path: []const u8,
    iv: []const u8,
    ciphertext: []const u8,
    content_type: []const u8,
    replace: bool,
) !void {
    var w = wire.Writer.init(gpa, body);
    const properties = try w.beginArray(8);
    try w.alignStruct();
    try w.writeString("org.freedesktop.Secret.Item.Label");
    try w.writeSignatureValue("s");
    try w.writeString(label);
    try w.alignStruct();
    try w.writeString("org.freedesktop.Secret.Item.Attributes");
    try w.writeSignatureValue("a{ss}");
    try writeTestAttributes(&w, service_name, username, false);
    w.endArray(properties);

    try w.alignStruct();
    try w.writeObjectPath(session_path);
    try writeByteArray(&w, iv);
    try writeByteArray(&w, ciphertext);
    try w.writeString(content_type);
    try w.writeBool(replace);
}

test "zbus secret-service Copilot CLI flow: empty-interface Properties, SetAlias, replace=false, signals, and no_reply_expected" {
    const gpa = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testVaultPath(&tmp, gpa);
    defer gpa.free(path);
    vault.vault_path_override = path;
    defer vault.vault_path_override = null;

    const prf_output: [vault.prf_salt_len]u8 = @splat(0x55);
    var enrolled = try vault.enrollInitialVault(gpa, io, .{
        .label = "copilot-test-key",
        .credential_id = "copilot-credential-id",
        .cose_alg = -8,
        .public_key = &@as([32]u8, @splat(0x33)),
        .prf_output = prf_output,
        .created_at = 1_700_000_000,
    }, .{
        .payload_created = 1_700_000_000,
        .argon2_t = 1,
        .argon2_m = 1024,
        .argon2_p = 1,
    });
    defer enrolled.deinit();
    try vault.saveVaultEnvelope(gpa, &enrolled.document.value);

    var state = try ServiceState.init(gpa);
    defer state.deinit();

    // Unlock via omitted INTERFACE header on control method.
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try writeByteArray(&w, &enrolled.dek);
        var out = try testDispatchFull(&state, .{}, service_path, null, "UnlockWithMasterKey", "ay", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expect(try r.readBool());
    }

    // 1. Properties.GetAll on service_path with empty interface "" (and omitted header interface).
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString("");
        var out = try testDispatchFull(&state, .{}, service_path, null, "GetAll", "s", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        const props = try r.beginArray(8);
        try std.testing.expect(r.arrayHasMore(props));
        try r.alignStruct();
        try std.testing.expectEqualStrings("Collections", try r.readString());
        try std.testing.expectEqualStrings("ao", try r.readSignatureValue());
        const cols = try r.beginArray(4);
        try std.testing.expectEqualStrings(collection_path, try r.readObjectPath());
        try std.testing.expect(!r.arrayHasMore(cols));
    }

    // 2. OpenSession with dh-ietf1024-sha256-aes128-cbc-pkcs7 (with omitted header interface).
    var dh_session_path: []u8 = undefined;
    defer gpa.free(dh_session_path);
    var client_dh_key: [16]u8 = undefined;
    defer std.crypto.secureZero(u8, &client_dh_key);
    {
        var prng = std.Random.DefaultPrng.init(0xCAFEBABE);
        var client_pair = try generateDhKeyPair(prng.random());
        defer std.crypto.secureZero(u8, &client_pair.private);
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString(dh_algorithm);
        try w.writeSignatureValue("ay");
        try writeByteArray(&w, &client_pair.public);
        var out = try testDispatchFull(&state, .{}, service_path, null, "OpenSession", "sv", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expectEqualStrings("ay", try r.readSignatureValue());
        const server_public = try readByteArray(&r);
        client_dh_key = try deriveDhSharedKey(client_pair.private, server_public);
        dh_session_path = try gpa.dupe(u8, try r.readObjectPath());
    }

    // 3. Service.SearchItems({"service": "copilot-cli", "username": "https://github.com:alice"}) -> empty.
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try writeTestAttributes(&w, "copilot-cli", "https://github.com:alice", false);
        var out = try testDispatch(&state, service_path, service_interface, "SearchItems", "a{ss}", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        const unlocked = try r.beginArray(4);
        try std.testing.expect(!r.arrayHasMore(unlocked));
        r.pos = unlocked.end;
        const locked = try r.beginArray(4);
        try std.testing.expect(!r.arrayHasMore(locked));
    }

    // 4. Service.ReadAlias("default") and Service.SetAlias("default", ...).
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString("default");
        var out = try testDispatch(&state, service_path, service_interface, "ReadAlias", "s", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expectEqualStrings(collection_path, try r.readObjectPath());
    }
    for ([_][]const u8{ collection_path, collection_alias_path }) |target| {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString("default");
        try w.writeObjectPath(target);
        var out = try testDispatch(&state, service_path, service_interface, "SetAlias", "so", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        try std.testing.expectEqual(@as(usize, 0), reply.body.len);
    }
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString("default");
        try w.writeObjectPath("/");
        var out = try testDispatch(&state, service_path, service_interface, "SetAlias", "so", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .error_reply);
        try std.testing.expectEqualStrings("org.freedesktop.DBus.Error.NotSupported", reply.header.error_name.?);
    }
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString("default");
        try w.writeObjectPath("/org/freedesktop/secrets/collection/missing");
        var out = try testDispatch(&state, service_path, service_interface, "SetAlias", "so", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .error_reply);
        try std.testing.expectEqualStrings("org.freedesktop.Secret.Error.NoSuchObject", reply.header.error_name.?);
    }

    // 5. Properties.Get with "" and "org.freedesktop.Secret.Collection" for "Locked" -> false.
    for ([_][]const u8{ "", collection_interface }) |iface| {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString(iface);
        try w.writeString("Locked");
        var out = try testDispatch(&state, collection_path, properties_interface, "Get", "ss", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expectEqualStrings("b", try r.readSignatureValue());
        try std.testing.expectEqual(false, try r.readBool());
    }
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString("");
        try w.writeString("Locked");
        var out = try testDispatch(&state, "/org/freedesktop/secrets/unknown", properties_interface, "Get", "ss", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .error_reply);
        try std.testing.expectEqualStrings("org.freedesktop.Secret.Error.NoSuchObject", reply.header.error_name.?);
    }

    // 6. Collection.CreateItem with application/octet-stream, replace=true -> ItemCreated signal.
    const iv1: [16]u8 = @splat(0x11);
    var item1_path: []u8 = undefined;
    defer gpa.free(item1_path);
    {
        const ct1 = try aesCbcEncrypt(gpa, client_dh_key, iv1, "ghu_copilot_token_v1");
        defer gpa.free(ct1);
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        try writeCopilotCreateItemBody(
            gpa,
            &body,
            "keyring:https://github.com:alice@copilot-cli",
            "copilot-cli",
            "https://github.com:alice",
            dh_session_path,
            &iv1,
            ct1,
            "application/octet-stream",
            true,
        );
        var out = try testDispatchFull(&state, .{}, collection_path, null, "CreateItem", "a{sv}(oayays)b", body.items);
        defer out.deinit();
        try std.testing.expectEqual(@as(usize, 2), out.frames.items.len);
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        item1_path = try gpa.dupe(u8, try r.readObjectPath());
        try std.testing.expectEqualStrings("/", try r.readObjectPath());
        try expectCollectionSignal(out.frames.items[1], "ItemCreated", item1_path);
    }

    // 7. CreateItem with replace=false creates a second item (ItemCreated); replace=true updates in-place (ItemChanged).
    var item2_path: []u8 = undefined;
    defer gpa.free(item2_path);
    {
        const ct2 = try aesCbcEncrypt(gpa, client_dh_key, iv1, "ghu_duplicate_token");
        defer gpa.free(ct2);
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        try writeCopilotCreateItemBody(
            gpa,
            &body,
            "keyring:https://github.com:alice@copilot-cli",
            "copilot-cli",
            "https://github.com:alice",
            dh_session_path,
            &iv1,
            ct2,
            "application/octet-stream",
            false,
        );
        var out = try testDispatch(&state, collection_path, collection_interface, "CreateItem", "a{sv}(oayays)b", body.items);
        defer out.deinit();
        try std.testing.expectEqual(@as(usize, 2), out.frames.items.len);
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        item2_path = try gpa.dupe(u8, try r.readObjectPath());
        try std.testing.expect(!std.mem.eql(u8, item1_path, item2_path));
        try std.testing.expectEqual(@as(usize, 2), state.items.items.len);
        try expectCollectionSignal(out.frames.items[1], "ItemCreated", item2_path);
    }
    {
        const ct3 = try aesCbcEncrypt(gpa, client_dh_key, iv1, "ghu_copilot_token_v2");
        defer gpa.free(ct3);
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        try writeCopilotCreateItemBody(
            gpa,
            &body,
            "keyring:https://github.com:alice@copilot-cli",
            "copilot-cli",
            "https://github.com:alice",
            dh_session_path,
            &iv1,
            ct3,
            "application/octet-stream",
            true,
        );
        var out = try testDispatch(&state, collection_path, collection_interface, "CreateItem", "a{sv}(oayays)b", body.items);
        defer out.deinit();
        try std.testing.expectEqual(@as(usize, 2), out.frames.items.len);
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expectEqualStrings(item1_path, try r.readObjectPath());
        try std.testing.expectEqual(@as(usize, 2), state.items.items.len);
        try expectCollectionSignal(out.frames.items[1], "ItemChanged", item1_path);
    }

    // 8. Properties.Get / Set with empty interface "" on item1_path emits ItemChanged.
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString("");
        try w.writeString("Label");
        try w.writeSignatureValue("s");
        try w.writeString("Updated Copilot Token");
        var out = try testDispatch(&state, item1_path, properties_interface, "Set", "ssv", body.items);
        defer out.deinit();
        try std.testing.expectEqual(@as(usize, 2), out.frames.items.len);
        _ = try expectReplyType(&out, .method_return);
        try expectCollectionSignal(out.frames.items[1], "ItemChanged", item1_path);
    }
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString("");
        try w.writeString("Label");
        var out = try testDispatch(&state, item1_path, properties_interface, "Get", "ss", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expectEqualStrings("s", try r.readSignatureValue());
        try std.testing.expectEqualStrings("Updated Copilot Token", try r.readString());
    }

    // 9. Item.GetSecret & Item.SetSecret (ItemChanged) & Item.Delete (ItemDeleted).
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeObjectPath(dh_session_path);
        var out = try testDispatchFull(&state, .{}, item1_path, null, "GetSecret", "o", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        const secret = try readSecretTuple(&r);
        try std.testing.expectEqualStrings("application/octet-stream", secret.content_type);
        var reply_iv: [16]u8 = undefined;
        @memcpy(&reply_iv, secret.parameters);
        const decrypted = try aesCbcDecrypt(gpa, client_dh_key, reply_iv, secret.value);
        defer gpa.free(decrypted);
        try std.testing.expectEqualStrings("ghu_copilot_token_v2", decrypted);
    }
    {
        const iv2: [16]u8 = @splat(0x29);
        const ct4 = try aesCbcEncrypt(gpa, client_dh_key, iv2, "ghu_copilot_token_v3");
        defer gpa.free(ct4);
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.alignStruct();
        try w.writeObjectPath(dh_session_path);
        try writeByteArray(&w, &iv2);
        try writeByteArray(&w, ct4);
        try w.writeString("application/octet-stream");
        var out = try testDispatch(&state, item1_path, item_interface, "SetSecret", "(oayays)", body.items);
        defer out.deinit();
        try std.testing.expectEqual(@as(usize, 2), out.frames.items.len);
        _ = try expectReplyType(&out, .method_return);
        try expectCollectionSignal(out.frames.items[1], "ItemChanged", item1_path);
    }
    {
        var out = try testDispatch(&state, item2_path, item_interface, "Delete", null, &.{});
        defer out.deinit();
        try std.testing.expectEqual(@as(usize, 2), out.frames.items.len);
        const reply = try expectReplyType(&out, .method_return);
        var r = wire.Reader.init(reply.body);
        try std.testing.expectEqualStrings("/", try r.readObjectPath());
        try expectCollectionSignal(out.frames.items[1], "ItemDeleted", item2_path);
        try std.testing.expectEqual(@as(usize, 1), state.items.items.len);
    }

    // 10. Flags.no_reply_expected = true suppresses method_return / error_reply while preserving signals.
    {
        var out = try testDispatchFull(
            &state,
            .{ .no_reply_expected = true },
            item1_path,
            item_interface,
            "Delete",
            null,
            &.{},
        );
        defer out.deinit();
        try std.testing.expectEqual(@as(usize, 1), out.frames.items.len);
        try expectCollectionSignal(out.frames.items[0], "ItemDeleted", item1_path);
        try std.testing.expectEqual(@as(usize, 0), state.items.items.len);
    }
    {
        var out = try testDispatchFull(&state, .{ .no_reply_expected = true }, service_path, peer_interface, "Ping", null, &.{});
        defer out.deinit();
        try std.testing.expectEqual(@as(usize, 0), out.frames.items.len);
    }
    {
        var out = try testDispatchFull(&state, .{ .no_reply_expected = true }, service_path, service_interface, "NoSuchMethod", null, &.{});
        defer out.deinit();
        try std.testing.expectEqual(@as(usize, 0), out.frames.items.len);
    }
}

test "parseArgs handles run, install, uninstall, status, and rejects invalid arguments" {
    const default_run = parseArgs(&.{}).?;
    try std.testing.expectEqual(Action{ .run = .{} }, default_run);

    const custom_run = parseArgs(&.{ "--replace", "--lock-timeout", "180" }).?;
    try std.testing.expectEqual(Action{ .run = .{ .replace = true, .lock_timeout_seconds = 180 } }, custom_run);

    try std.testing.expectEqual(Action{ .install = .{ .force = false } }, parseArgs(&.{"install"}).?);
    try std.testing.expectEqual(Action{ .install = .{ .force = true } }, parseArgs(&.{ "install", "--force" }).?);
    try std.testing.expectEqual(Action{ .uninstall = .{ .force = false } }, parseArgs(&.{"uninstall"}).?);
    try std.testing.expectEqual(Action{ .uninstall = .{ .force = true } }, parseArgs(&.{ "uninstall", "--force" }).?);
    try std.testing.expectEqual(Action.status, parseArgs(&.{"status"}).?);

    try std.testing.expect(parseArgs(&.{ "--lock-timeout", "0" }) == null);
    try std.testing.expect(parseArgs(&.{"--lock-timeout"}) == null);
    try std.testing.expect(parseArgs(&.{ "--lock-timeout", "abc" }) == null);
    try std.testing.expect(parseArgs(&.{"--force"}) == null);
    try std.testing.expect(parseArgs(&.{ "install", "--replace" }) == null);
    try std.testing.expect(parseArgs(&.{ "install", "extra" }) == null);
    try std.testing.expect(parseArgs(&.{ "uninstall", "--unknown" }) == null);
    try std.testing.expect(parseArgs(&.{ "status", "--force" }) == null);
    try std.testing.expect(parseArgs(&.{ "--replace", "install" }) == null);
    try std.testing.expect(parseArgs(&.{"bogus"}) == null);
}

test "service unit formatting escapes spaces and rejects control characters" {
    const gpa = std.testing.allocator;

    const plain_dbus = try formatDbusServiceFile(gpa, "/home/alice/.local/bin/keyring");
    defer gpa.free(plain_dbus);
    try std.testing.expectEqualStrings(
        "# Managed by cataggar/keyring\n" ++
            "[D-BUS Service]\n" ++
            "Name=org.freedesktop.secrets\n" ++
            "Exec=/home/alice/.local/bin/keyring service\n" ++
            "SystemdService=keyring.service\n",
        plain_dbus,
    );

    const plain_systemd = try formatSystemdUnitFile(gpa, "/home/alice/.local/bin/keyring");
    defer gpa.free(plain_systemd);
    try std.testing.expectEqualStrings(
        "# Managed by cataggar/keyring\n" ++
            "[Unit]\n" ++
            "Description=Keyring Secret Service\n\n" ++
            "[Service]\n" ++
            "Type=dbus\n" ++
            "BusName=org.freedesktop.secrets\n" ++
            "ExecStart=/home/alice/.local/bin/keyring service\n" ++
            "Restart=on-failure\n\n" ++
            "[Install]\n" ++
            "WantedBy=default.target\n",
        plain_systemd,
    );

    const spaced_dbus = try formatDbusServiceFile(gpa, "/home/alice/My Apps/keyring");
    defer gpa.free(spaced_dbus);
    try std.testing.expect(std.mem.indexOf(u8, spaced_dbus, "Exec=\"/home/alice/My Apps/keyring\" service\n") != null);
    try std.testing.expect(isManagedUnitContent(spaced_dbus));

    const spaced_systemd = try formatSystemdUnitFile(gpa, "/home/alice/My Apps/keyring");
    defer gpa.free(spaced_systemd);
    try std.testing.expect(std.mem.indexOf(u8, spaced_systemd, "ExecStart=\"/home/alice/My Apps/keyring\" service\n") != null);
    try std.testing.expect(isManagedUnitContent(spaced_systemd));

    try std.testing.expectError(error.InvalidExecutablePath, formatDbusServiceFile(gpa, "/bad\npath/keyring"));
    try std.testing.expectError(error.InvalidExecutablePath, formatSystemdUnitFile(gpa, "/bad\rpath/keyring"));
    try std.testing.expectError(error.InvalidExecutablePath, formatDbusServiceFile(gpa, ""));

    try std.testing.expect(isManagedUnitContent("[D-BUS Service]\nName=org.freedesktop.secrets\nExec=/usr/local/bin/keyring service\n"));
    try std.testing.expect(!isManagedUnitContent("[D-BUS Service]\nName=org.freedesktop.secrets\nExec=/usr/bin/gnome-keyring-daemon --start --components=secrets\n"));
    try std.testing.expect(!isManagedUnitContent("[D-BUS Service]\nName=org.freedesktop.secrets\nExec=/usr/bin/oo7-daemon\n"));
}

test "service install, status, foreign-unit protection, and uninstall lifecycle" {
    const gpa = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const root = root_buf[0..root_len];

    const home_dir = try std.fs.path.join(gpa, &.{ root, "home" });
    defer gpa.free(home_dir);
    const xdg_data = try std.fs.path.join(gpa, &.{ root, "xdg-data" });
    defer gpa.free(xdg_data);
    const xdg_config = try std.fs.path.join(gpa, &.{ root, "xdg-config" });
    defer gpa.free(xdg_config);
    const vpath = try std.fs.path.join(gpa, &.{ xdg_data, "keyring", "vault.json" });
    defer gpa.free(vpath);

    // Create ~/.local/bin/keyring shim to verify resolveInstallExecutablePath prefers it.
    const local_bin_dir = try std.fs.path.join(gpa, &.{ home_dir, ".local", "bin" });
    defer gpa.free(local_bin_dir);
    try std.Io.Dir.cwd().createDirPath(io, local_bin_dir);
    const local_bin_keyring = try std.fs.path.join(gpa, &.{ local_bin_dir, "keyring" });
    defer gpa.free(local_bin_keyring);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = local_bin_keyring, .data = "shim" });

    vault.vault_path_override = vpath;
    defer vault.vault_path_override = null;

    const SystemctlRecorder = struct {
        var calls: usize = 0;
        var succeed: bool = true;
        fn run(_: []const []const u8) bool {
            calls += 1;
            return succeed;
        }
    };
    SystemctlRecorder.calls = 0;
    SystemctlRecorder.succeed = false;

    test_env_override = .{
        .home = home_dir,
        .xdg_data_home = xdg_data,
        .xdg_config_home = xdg_config,
        .exe_path = null,
        .systemctl_fn = SystemctlRecorder.run,
        .daemon_state = .not_running,
    };
    defer test_env_override = null;

    var paths = try resolveServicePathsFromDirs(gpa, home_dir, xdg_data, xdg_config);
    defer paths.deinit(gpa);

    // 1. Initial status before install or enrollment.
    {
        var stdout = std.Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = std.Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try std.testing.expectEqual(@as(u8, 0), try runStatus(gpa, &stdout.writer, &stderr.writer));
        try std.testing.expect(std.mem.indexOf(u8, stdout.written(), "vault: not enrolled") != null);
        try std.testing.expect(std.mem.indexOf(u8, stdout.written(), "dbus activation: not installed\n") != null);
        try std.testing.expect(std.mem.indexOf(u8, stdout.written(), "systemd user unit: not installed\n") != null);
        try std.testing.expect(std.mem.indexOf(u8, stdout.written(), "daemon: not running\n") != null);
    }

    // 2. Install succeeds even when systemctl --user is unavailable, preferring ~/.local/bin/keyring.
    {
        var stdout = std.Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = std.Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try std.testing.expectEqual(@as(u8, 0), try runInstall(gpa, .{}, &stdout.writer, &stderr.writer));
        try std.testing.expectEqual(@as(usize, 0), stderr.written().len);
        try std.testing.expect(std.mem.indexOf(u8, stdout.written(), "keyring enroll") != null);
        try std.testing.expect(std.mem.indexOf(u8, stdout.written(), "keyring unlock") != null);

        const dbus_file = (try readUnitFileIfExists(gpa, io, paths.dbus_service_path)).?;
        defer gpa.free(dbus_file);
        try std.testing.expect(std.mem.indexOf(u8, dbus_file, managed_marker) != null);
        try std.testing.expect(std.mem.indexOf(u8, dbus_file, ".local") != null);

        const unit_file = (try readUnitFileIfExists(gpa, io, paths.systemd_unit_path)).?;
        defer gpa.free(unit_file);
        try std.testing.expect(std.mem.indexOf(u8, unit_file, managed_marker) != null);
    }

    // 3. Idempotent re-install with systemctl succeeding.
    SystemctlRecorder.calls = 0;
    SystemctlRecorder.succeed = true;
    test_env_override.?.exe_path = "/usr/local/bin/keyring";
    {
        var stdout = std.Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = std.Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try std.testing.expectEqual(@as(u8, 0), try runInstall(gpa, .{}, &stdout.writer, &stderr.writer));
        try std.testing.expectEqual(@as(usize, 2), SystemctlRecorder.calls);
    }

    // 4. Foreign D-Bus service file (gnome-keyring) refuses install & uninstall without --force, reported as foreign in status.
    try writeUnitFileAtomic(
        gpa,
        io,
        paths.dbus_service_path,
        "[D-BUS Service]\nName=org.freedesktop.secrets\nExec=/usr/bin/gnome-keyring-daemon --start --components=secrets\n",
    );
    {
        var stdout = std.Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = std.Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try std.testing.expectEqual(@as(u8, 1), try runInstall(gpa, .{ .force = false }, &stdout.writer, &stderr.writer));
        try std.testing.expect(std.mem.indexOf(u8, stderr.written(), "--force") != null);
    }
    {
        var stdout = std.Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = std.Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try std.testing.expectEqual(@as(u8, 1), try runUninstall(gpa, .{ .force = false }, &stdout.writer, &stderr.writer));
        try std.testing.expect(std.mem.indexOf(u8, stderr.written(), "--force") != null);
    }

    // Enroll vault and check status with foreign dbus activation + unlocked daemon.
    const prf_output: [vault.prf_salt_len]u8 = @splat(0x77);
    var enrolled = try vault.enrollInitialVault(gpa, io, .{
        .label = "yubikey",
        .credential_id = "status-credential",
        .cose_alg = -8,
        .public_key = &@as([32]u8, @splat(0x44)),
        .prf_output = prf_output,
        .created_at = 1_700_000_000,
    }, .{
        .payload_created = 1_700_000_000,
        .argon2_t = 1,
        .argon2_m = 1024,
        .argon2_p = 1,
    });
    defer enrolled.deinit();
    try vault.saveVaultEnvelope(gpa, &enrolled.document.value);
    test_env_override.?.daemon_state = .{ .unlocked = 3 };
    {
        var stdout = std.Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = std.Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try std.testing.expectEqual(@as(u8, 0), try runStatus(gpa, &stdout.writer, &stderr.writer));
        try std.testing.expect(std.mem.indexOf(u8, stdout.written(), "vault: enrolled (1 keys)") != null);
        try std.testing.expect(std.mem.indexOf(u8, stdout.written(), "dbus activation: installed (foreign: ") != null);
        try std.testing.expect(std.mem.indexOf(u8, stdout.written(), "systemd user unit: installed (") != null);
        try std.testing.expect(std.mem.indexOf(u8, stdout.written(), "daemon: running (unlocked, 3 items)\n") != null);
    }

    // 5. --force install overwrites foreign file, and uninstall removes both files cleanly.
    {
        var stdout = std.Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = std.Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try std.testing.expectEqual(@as(u8, 0), try runInstall(gpa, .{ .force = true }, &stdout.writer, &stderr.writer));
        try std.testing.expect(std.mem.indexOf(u8, stdout.written(), "keyring enroll") == null);
        try std.testing.expect(std.mem.indexOf(u8, stdout.written(), "keyring unlock") != null);
    }
    {
        var stdout = std.Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = std.Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try std.testing.expectEqual(@as(u8, 0), try runUninstall(gpa, .{}, &stdout.writer, &stderr.writer));
        try std.testing.expect((try readUnitFileIfExists(gpa, io, paths.dbus_service_path)) == null);
        try std.testing.expect((try readUnitFileIfExists(gpa, io, paths.systemd_unit_path)) == null);
    }
}

test "ServiceState.checkIdleTimeout locks at deadline and SetAlias rejects clearing default or custom aliases" {
    const gpa = std.testing.allocator;
    var state = try ServiceState.init(gpa);
    defer state.deinit();

    // Simulate unlocked state with a dummy DEK.
    state.unlocked = true;
    state.dek = @splat(0xAB);

    // No timeout configured -> stays unlocked.
    try std.testing.expect(!state.checkIdleTimeout(1_000, 100, null));
    try std.testing.expect(state.unlocked);

    // Before deadline (`100 + 60 = 160`) -> stays unlocked.
    try std.testing.expect(!state.checkIdleTimeout(159, 100, 60));
    try std.testing.expect(state.unlocked);

    // At deadline (`160 >= 160`) -> locks and zeroes DEK.
    try std.testing.expect(state.checkIdleTimeout(160, 100, 60));
    try std.testing.expect(!state.unlocked);
    try std.testing.expect(state.dek == null);

    // Once locked, subsequent checks return false.
    try std.testing.expect(!state.checkIdleTimeout(500, 100, 60));

    // SetAlias("default", "/") -> NotSupported; SetAlias("login", collection_path) -> NotSupported.
    for ([_]struct { name: []const u8, target: []const u8 }{
        .{ .name = "default", .target = "/" },
        .{ .name = "login", .target = collection_path },
        .{ .name = "login", .target = "/" },
    }) |tc| {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        var w = wire.Writer.init(gpa, &body);
        try w.writeString(tc.name);
        try w.writeObjectPath(tc.target);
        var out = try testDispatch(&state, service_path, service_interface, "SetAlias", "so", body.items);
        defer out.deinit();
        const reply = try expectReplyType(&out, .error_reply);
        try std.testing.expectEqualStrings("org.freedesktop.DBus.Error.NotSupported", reply.header.error_name.?);
    }
}

test "resolveServicePathsFromDirs ignores relative XDG_DATA_HOME and XDG_CONFIG_HOME" {
    const gpa = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const root = root_buf[0..root_len];

    const home_dir = try std.fs.path.join(gpa, &.{ root, "home" });
    defer gpa.free(home_dir);
    const expected_dbus = try std.fs.path.join(gpa, &.{ home_dir, ".local", "share", "dbus-1", "services", "org.freedesktop.secrets.service" });
    defer gpa.free(expected_dbus);
    const expected_systemd = try std.fs.path.join(gpa, &.{ home_dir, ".config", "systemd", "user", "keyring.service" });
    defer gpa.free(expected_systemd);

    var rel_paths = try resolveServicePathsFromDirs(gpa, home_dir, "relative/xdg-data", "./relative-config");
    defer rel_paths.deinit(gpa);
    try std.testing.expectEqualStrings(expected_dbus, rel_paths.dbus_service_path);
    try std.testing.expectEqualStrings(expected_systemd, rel_paths.systemd_unit_path);
}

test "non-Linux daemon and client helpers report unsupported platform" {
    if (builtin.os.tag == .linux) return;
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.UnsupportedPlatform, runDaemon(gpa, false, null));
    try std.testing.expectError(error.UnsupportedPlatform, clientUnlockWithMasterKey(gpa, @splat(0)));
    try std.testing.expectError(error.UnsupportedPlatform, clientLockAll(gpa));
    try std.testing.expectError(error.UnsupportedPlatform, clientGetStatus(gpa));

    {
        var stdout = std.Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = std.Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try std.testing.expectEqual(@as(u8, 1), try runInstall(gpa, .{}, &stdout.writer, &stderr.writer));
        try std.testing.expectEqualStrings(unsupported_platform_message, stderr.written());
    }
    {
        var stdout = std.Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = std.Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try std.testing.expectEqual(@as(u8, 1), try runUninstall(gpa, .{}, &stdout.writer, &stderr.writer));
        try std.testing.expectEqualStrings(unsupported_platform_message, stderr.written());
    }
    {
        var stdout = std.Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = std.Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        try std.testing.expectEqual(@as(u8, 1), try runStatus(gpa, &stdout.writer, &stderr.writer));
        try std.testing.expectEqualStrings(unsupported_platform_message, stderr.written());
    }
}

test "Linux daemon and client entry points compile" {
    if (builtin.os.tag != .linux) return;
    const gpa = std.testing.allocator;
    const now = std.Io.Clock.real.now(std.Io.Threaded.global_single_threaded.io()).toSeconds();
    if (now == std.math.minInt(i64)) {
        try runDaemon(gpa, false, null);
        var stdout = std.Io.Writer.Allocating.init(gpa);
        defer stdout.deinit();
        var stderr = std.Io.Writer.Allocating.init(gpa);
        defer stderr.deinit();
        _ = try runInstall(gpa, .{}, &stdout.writer, &stderr.writer);
        _ = try runUninstall(gpa, .{}, &stdout.writer, &stderr.writer);
        _ = try runStatus(gpa, &stdout.writer, &stderr.writer);
    }
    if (clientGetStatus(gpa)) |status_value| {
        var status = status_value;
        status.deinit(gpa);
    } else |_| {}
}
