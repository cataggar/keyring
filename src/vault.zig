const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const dek_len: usize = 32;
pub const store_id_len: usize = 16;
pub const prf_salt_len: usize = 32;
pub const recovery_salt_len: usize = 16;
pub const gcm_nonce_len: usize = 12;
pub const gcm_tag_len: usize = 16;

const version: u32 = 1;
const max_vault_size: u64 = 64 * 1024 * 1024;
const max_credential_id_len: usize = 1023;
const recovery_key_chars: usize = 24;
const crockford_alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const prf_kek_info_prefix = "keyring-webauthn-prf-kek-v1:";
const prf_slot_aad_prefix = "keyring-prf-slot-v1:";
const recovery_slot_aad_prefix = "keyring-recovery-slot-v1:";
const payload_aad_prefix = "keyring-vault-payload-v1:";

pub const Error = error{
    OutOfMemory,
    VaultNotFound,
    VaultPathUnavailable,
    InsecurePermissions,
    InvalidVault,
    UnsupportedVersion,
    InvalidCredential,
    InvalidRecoveryKey,
    DecryptionFailed,
    DuplicateSlot,
    SlotNotFound,
    LastPrfSlot,
    InvalidSignCount,
    PlatformFailure,
};

pub var vault_path_override: ?[]const u8 = null;

pub const PrfKeySlot = struct {
    id: []const u8,
    label: []const u8,
    credential_id_b64: []const u8,
    cose_alg: i32,
    public_key_b64: []const u8,
    sign_count: u32,
    prf_salt_b64: []const u8,
    wrap_nonce_b64: []const u8,
    wrapped_dek_b64: []const u8,
    created_at: i64,
    last_used_at: ?i64 = null,
};

pub const RecoveryKeySlot = struct {
    kdf_salt_b64: []const u8,
    argon2_t: u32 = 3,
    argon2_m: u32 = 65536,
    argon2_p: u32 = 1,
    wrap_nonce_b64: []const u8,
    wrapped_dek_b64: []const u8,
};

pub const VaultItem = struct {
    id: []const u8,
    label: []const u8,
    secret_b64: []const u8,
    content_type: []const u8 = "text/plain",
    attributes: std.json.ArrayHashMap([]const u8) = .{},
    created: u64,
    modified: u64,
};

pub const VaultPayload = struct {
    label: []const u8 = "Default",
    created: u64,
    modified: u64,
    next_item_id: u64 = 1,
    items: []VaultItem,
};

pub const VaultFile = struct {
    version: u32 = version,
    store_id_hex: []const u8,
    rp_id: []const u8 = "localhost",
    prf_slots: []PrfKeySlot,
    recovery_slot: RecoveryKeySlot,
    payload_nonce_b64: []const u8,
    payload_ciphertext_b64: []const u8,
};

/// Owns every allocation reachable from `value`.
pub const VaultDocument = struct {
    backing_allocator: Allocator,
    arena: *std.heap.ArenaAllocator,
    value: VaultFile,

    pub fn allocator(self: *VaultDocument) Allocator {
        return self.arena.allocator();
    }

    pub fn deinit(self: *VaultDocument) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub const WrappedDek = struct {
    wrap_nonce_b64: []u8,
    wrapped_dek_b64: []u8,

    pub fn deinit(self: *WrappedDek, gpa: Allocator) void {
        gpa.free(self.wrap_nonce_b64);
        gpa.free(self.wrapped_dek_b64);
        self.* = undefined;
    }
};

pub const EncryptedPayload = struct {
    nonce_b64: []u8,
    ciphertext_b64: []u8,

    pub fn deinit(self: *EncryptedPayload, gpa: Allocator) void {
        gpa.free(self.nonce_b64);
        gpa.free(self.ciphertext_b64);
        self.* = undefined;
    }
};

pub const PrfEnrollment = struct {
    label: []const u8,
    credential_id: []const u8,
    cose_alg: i32,
    public_key: []const u8,
    sign_count: u32 = 0,
    prf_output: [prf_salt_len]u8,
    prf_salt: ?[prf_salt_len]u8 = null,
    created_at: i64,
};

pub const EnrollmentOptions = struct {
    rp_id: []const u8 = "localhost",
    payload_label: []const u8 = "Default",
    payload_created: ?u64 = null,
    argon2_t: u32 = 3,
    argon2_m: u32 = 65536,
    argon2_p: u32 = 1,
    store_id: ?[store_id_len]u8 = null,
    prf_salt: ?[prf_salt_len]u8 = null,
};

pub const EnrollmentResult = struct {
    document: VaultDocument,
    dek: [dek_len]u8,
    recovery_key: [29]u8,

    pub fn deinit(self: *EnrollmentResult) void {
        std.crypto.secureZero(u8, &self.dek);
        std.crypto.secureZero(u8, &self.recovery_key);
        self.document.deinit();
        self.* = undefined;
    }
};

pub fn derivePrfKek(
    prf_output_value: [prf_salt_len]u8,
    prf_salt: [prf_salt_len]u8,
    store_id: [store_id_len]u8,
    credential_id: []const u8,
) [dek_len]u8 {
    std.debug.assert(credential_id.len <= max_credential_id_len);

    var prf_output = prf_output_value;
    defer std.crypto.secureZero(u8, &prf_output);
    var prk = HkdfSha256.extract(&prf_salt, &prf_output);
    defer std.crypto.secureZero(u8, &prk);

    const store_hex = std.fmt.bytesToHex(store_id, .lower);
    var info_buf: [prf_kek_info_prefix.len + 32 + 1 + max_credential_id_len]u8 = undefined;
    var cursor: usize = 0;
    @memcpy(info_buf[cursor..][0..prf_kek_info_prefix.len], prf_kek_info_prefix);
    cursor += prf_kek_info_prefix.len;
    @memcpy(info_buf[cursor..][0..store_hex.len], &store_hex);
    cursor += store_hex.len;
    info_buf[cursor] = ':';
    cursor += 1;
    @memcpy(info_buf[cursor..][0..credential_id.len], credential_id);
    cursor += credential_id.len;

    var kek: [dek_len]u8 = undefined;
    HkdfSha256.expand(&kek, info_buf[0..cursor], prk);
    return kek;
}

pub fn wrapDekWithPrf(
    gpa: Allocator,
    io: std.Io,
    dek_value: [dek_len]u8,
    prf_output_value: [prf_salt_len]u8,
    prf_salt: [prf_salt_len]u8,
    store_id: [store_id_len]u8,
    credential_id: []const u8,
) Error!WrappedDek {
    if (credential_id.len == 0 or credential_id.len > max_credential_id_len) {
        return error.InvalidCredential;
    }

    var dek = dek_value;
    defer std.crypto.secureZero(u8, &dek);
    var prf_output = prf_output_value;
    defer std.crypto.secureZero(u8, &prf_output);
    var kek = derivePrfKek(prf_output, prf_salt, store_id, credential_id);
    defer std.crypto.secureZero(u8, &kek);

    const credential_id_b64 = try base64EncodeAlloc(gpa, credential_id);
    defer gpa.free(credential_id_b64);
    const aad = try prfSlotAad(gpa, store_id, credential_id_b64);
    defer gpa.free(aad);

    var nonce: [gcm_nonce_len]u8 = undefined;
    secureRandom(io, &nonce);
    var ciphertext: [dek_len]u8 = undefined;
    var tag: [gcm_tag_len]u8 = undefined;
    Aes256Gcm.encrypt(&ciphertext, &tag, &dek, aad, nonce, kek);

    var combined: [dek_len + gcm_tag_len]u8 = undefined;
    @memcpy(combined[0..dek_len], &ciphertext);
    @memcpy(combined[dek_len..], &tag);

    const nonce_b64 = try base64EncodeAlloc(gpa, &nonce);
    errdefer gpa.free(nonce_b64);
    const wrapped_b64 = try base64EncodeAlloc(gpa, &combined);
    return .{
        .wrap_nonce_b64 = nonce_b64,
        .wrapped_dek_b64 = wrapped_b64,
    };
}

pub fn unwrapDekWithPrf(
    gpa: Allocator,
    prf_output_value: [prf_salt_len]u8,
    store_id: [store_id_len]u8,
    slot: *const PrfKeySlot,
) Error![dek_len]u8 {
    var prf_output = prf_output_value;
    defer std.crypto.secureZero(u8, &prf_output);

    var credential_id: [max_credential_id_len]u8 = undefined;
    const credential_len = try base64DecodeInto(slot.credential_id_b64, &credential_id);
    if (credential_len == 0) return error.InvalidCredential;
    var prf_salt: [prf_salt_len]u8 = undefined;
    try base64DecodeExact(slot.prf_salt_b64, &prf_salt);
    var nonce: [gcm_nonce_len]u8 = undefined;
    try base64DecodeExact(slot.wrap_nonce_b64, &nonce);
    var combined: [dek_len + gcm_tag_len]u8 = undefined;
    try base64DecodeExact(slot.wrapped_dek_b64, &combined);

    var kek = derivePrfKek(prf_output, prf_salt, store_id, credential_id[0..credential_len]);
    defer std.crypto.secureZero(u8, &kek);
    const aad = try prfSlotAad(gpa, store_id, slot.credential_id_b64);
    defer gpa.free(aad);

    var tag: [gcm_tag_len]u8 = undefined;
    @memcpy(&tag, combined[dek_len..]);
    var dek: [dek_len]u8 = undefined;
    Aes256Gcm.decrypt(&dek, combined[0..dek_len], tag, aad, nonce, kek) catch {
        std.crypto.secureZero(u8, &dek);
        return error.DecryptionFailed;
    };
    return dek;
}

pub fn generateRecoveryKey(io: std.Io) [29]u8 {
    var random: [20]u8 = undefined;
    defer std.crypto.secureZero(u8, &random);
    secureRandom(io, &random);

    var out: [29]u8 = undefined;
    var accumulator: u32 = 0;
    var available_bits: u5 = 0;
    var random_index: usize = 0;
    var character_index: usize = 0;
    var out_index: usize = 0;
    while (character_index < recovery_key_chars) : (character_index += 1) {
        while (available_bits < 5) {
            accumulator = (accumulator << 8) | random[random_index];
            random_index += 1;
            available_bits += 8;
        }
        available_bits -= 5;
        const alphabet_index: usize = @intCast((accumulator >> available_bits) & 0x1f);
        out[out_index] = crockford_alphabet[alphabet_index];
        out_index += 1;
        if (available_bits == 0) {
            accumulator = 0;
        } else {
            accumulator &= (@as(u32, 1) << available_bits) - 1;
        }
        if ((character_index + 1) % 4 == 0 and character_index + 1 != recovery_key_chars) {
            out[out_index] = '-';
            out_index += 1;
        }
    }
    std.debug.assert(out_index == out.len);
    return out;
}

pub fn normalizeRecoveryKey(input: []const u8) Error![recovery_key_chars]u8 {
    var normalized: [recovery_key_chars]u8 = undefined;
    var len: usize = 0;
    for (input) |raw| {
        if (raw == '-' or std.ascii.isWhitespace(raw)) continue;
        if (len == normalized.len) return error.InvalidRecoveryKey;
        const upper = std.ascii.toUpper(raw);
        const mapped = switch (upper) {
            'O' => '0',
            'I', 'L' => '1',
            else => upper,
        };
        if (std.mem.indexOfScalar(u8, crockford_alphabet, mapped) == null) {
            return error.InvalidRecoveryKey;
        }
        normalized[len] = mapped;
        len += 1;
    }
    if (len != normalized.len) return error.InvalidRecoveryKey;
    return normalized;
}

pub fn deriveRecoveryKek(
    gpa: Allocator,
    normalized_key: *const [recovery_key_chars]u8,
    salt: [recovery_salt_len]u8,
    t: u32,
    m: u32,
    p: u32,
) Error![dek_len]u8 {
    if (p == 0 or p > std.math.maxInt(u24)) return error.InvalidVault;
    var kek: [dek_len]u8 = undefined;
    std.crypto.pwhash.argon2.kdf(
        gpa,
        &kek,
        normalized_key,
        &salt,
        .{ .t = t, .m = m, .p = @intCast(p) },
        .argon2id,
        std.Io.Threaded.global_single_threaded.io(),
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.PlatformFailure,
    };
    return kek;
}

pub fn wrapDekWithRecovery(
    gpa: Allocator,
    io: std.Io,
    dek_value: [dek_len]u8,
    normalized_key: *const [recovery_key_chars]u8,
    salt: [recovery_salt_len]u8,
    store_id: [store_id_len]u8,
    t: u32,
    m: u32,
    p: u32,
) Error!WrappedDek {
    var dek = dek_value;
    defer std.crypto.secureZero(u8, &dek);
    var kek = try deriveRecoveryKek(gpa, normalized_key, salt, t, m, p);
    defer std.crypto.secureZero(u8, &kek);

    const aad = try storeBoundAad(gpa, recovery_slot_aad_prefix, store_id);
    defer gpa.free(aad);
    var nonce: [gcm_nonce_len]u8 = undefined;
    secureRandom(io, &nonce);
    var ciphertext: [dek_len]u8 = undefined;
    var tag: [gcm_tag_len]u8 = undefined;
    Aes256Gcm.encrypt(&ciphertext, &tag, &dek, aad, nonce, kek);

    var combined: [dek_len + gcm_tag_len]u8 = undefined;
    @memcpy(combined[0..dek_len], &ciphertext);
    @memcpy(combined[dek_len..], &tag);
    const nonce_b64 = try base64EncodeAlloc(gpa, &nonce);
    errdefer gpa.free(nonce_b64);
    const wrapped_b64 = try base64EncodeAlloc(gpa, &combined);
    return .{
        .wrap_nonce_b64 = nonce_b64,
        .wrapped_dek_b64 = wrapped_b64,
    };
}

pub fn unwrapDekWithRecovery(
    gpa: Allocator,
    normalized_key: *const [recovery_key_chars]u8,
    store_id: [store_id_len]u8,
    slot: *const RecoveryKeySlot,
) Error![dek_len]u8 {
    var salt: [recovery_salt_len]u8 = undefined;
    try base64DecodeExact(slot.kdf_salt_b64, &salt);
    var nonce: [gcm_nonce_len]u8 = undefined;
    try base64DecodeExact(slot.wrap_nonce_b64, &nonce);
    var combined: [dek_len + gcm_tag_len]u8 = undefined;
    try base64DecodeExact(slot.wrapped_dek_b64, &combined);
    var kek = try deriveRecoveryKek(
        gpa,
        normalized_key,
        salt,
        slot.argon2_t,
        slot.argon2_m,
        slot.argon2_p,
    );
    defer std.crypto.secureZero(u8, &kek);
    const aad = try storeBoundAad(gpa, recovery_slot_aad_prefix, store_id);
    defer gpa.free(aad);

    var tag: [gcm_tag_len]u8 = undefined;
    @memcpy(&tag, combined[dek_len..]);
    var dek: [dek_len]u8 = undefined;
    Aes256Gcm.decrypt(&dek, combined[0..dek_len], tag, aad, nonce, kek) catch {
        std.crypto.secureZero(u8, &dek);
        return error.DecryptionFailed;
    };
    return dek;
}

pub fn encryptPayload(
    gpa: Allocator,
    io: std.Io,
    dek_value: [dek_len]u8,
    store_id: [store_id_len]u8,
    payload: *const VaultPayload,
) Error!EncryptedPayload {
    var dek = dek_value;
    defer std.crypto.secureZero(u8, &dek);
    const plaintext = std.json.Stringify.valueAlloc(gpa, payload.*, .{}) catch return error.OutOfMemory;
    defer {
        std.crypto.secureZero(u8, plaintext);
        gpa.free(plaintext);
    }
    const aad = try storeBoundAad(gpa, payload_aad_prefix, store_id);
    defer gpa.free(aad);

    var nonce: [gcm_nonce_len]u8 = undefined;
    secureRandom(io, &nonce);
    const ciphertext = try gpa.alloc(u8, plaintext.len);
    defer gpa.free(ciphertext);
    var tag: [gcm_tag_len]u8 = undefined;
    Aes256Gcm.encrypt(ciphertext, &tag, plaintext, aad, nonce, dek);

    const combined = try gpa.alloc(u8, ciphertext.len + tag.len);
    defer gpa.free(combined);
    @memcpy(combined[0..ciphertext.len], ciphertext);
    @memcpy(combined[ciphertext.len..], &tag);

    const nonce_b64 = try base64EncodeAlloc(gpa, &nonce);
    errdefer gpa.free(nonce_b64);
    const ciphertext_b64 = try base64EncodeAlloc(gpa, combined);
    return .{ .nonce_b64 = nonce_b64, .ciphertext_b64 = ciphertext_b64 };
}

pub fn decryptPayload(
    gpa: Allocator,
    dek_value: [dek_len]u8,
    store_id: [store_id_len]u8,
    nonce_b64: []const u8,
    ciphertext_b64: []const u8,
) Error!std.json.Parsed(VaultPayload) {
    var dek = dek_value;
    defer std.crypto.secureZero(u8, &dek);
    var nonce: [gcm_nonce_len]u8 = undefined;
    try base64DecodeExact(nonce_b64, &nonce);

    const combined = try base64DecodeAlloc(gpa, ciphertext_b64);
    defer gpa.free(combined);
    if (combined.len < gcm_tag_len) return error.InvalidVault;
    const ciphertext = combined[0 .. combined.len - gcm_tag_len];
    var tag: [gcm_tag_len]u8 = undefined;
    @memcpy(&tag, combined[combined.len - gcm_tag_len ..]);

    const plaintext = try gpa.alloc(u8, ciphertext.len);
    defer {
        std.crypto.secureZero(u8, plaintext);
        gpa.free(plaintext);
    }
    const aad = try storeBoundAad(gpa, payload_aad_prefix, store_id);
    defer gpa.free(aad);
    Aes256Gcm.decrypt(plaintext, ciphertext, tag, aad, nonce, dek) catch {
        return error.DecryptionFailed;
    };
    return std.json.parseFromSlice(VaultPayload, gpa, plaintext, .{
        .allocate = .alloc_always,
    }) catch return error.InvalidVault;
}

pub fn enrollInitialVault(
    gpa: Allocator,
    io: std.Io,
    enrollment: PrfEnrollment,
    options: EnrollmentOptions,
) Error!EnrollmentResult {
    try validateCredential(enrollment.credential_id, enrollment.cose_alg, enrollment.public_key);
    if (options.rp_id.len == 0) return error.InvalidVault;

    const arena = gpa.create(std.heap.ArenaAllocator) catch return error.OutOfMemory;
    arena.* = .init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();

    var store_id: [store_id_len]u8 = options.store_id orelse undefined;
    if (options.store_id == null) secureRandom(io, &store_id);
    var dek: [dek_len]u8 = undefined;
    secureRandom(io, &dek);
    errdefer std.crypto.secureZero(u8, &dek);
    var prf_output = enrollment.prf_output;
    defer std.crypto.secureZero(u8, &prf_output);
    var prf_salt: [prf_salt_len]u8 = options.prf_salt orelse enrollment.prf_salt orelse undefined;
    if (options.prf_salt == null and enrollment.prf_salt == null) secureRandom(io, &prf_salt);
    var recovery_salt: [recovery_salt_len]u8 = undefined;
    secureRandom(io, &recovery_salt);

    const recovery_key = generateRecoveryKey(io);
    var normalized_recovery_key = try normalizeRecoveryKey(&recovery_key);
    defer std.crypto.secureZero(u8, &normalized_recovery_key);

    const prf_wrapped = try wrapDekWithPrf(
        a,
        io,
        dek,
        prf_output,
        prf_salt,
        store_id,
        enrollment.credential_id,
    );
    const recovery_wrapped = try wrapDekWithRecovery(
        a,
        io,
        dek,
        &normalized_recovery_key,
        recovery_salt,
        store_id,
        options.argon2_t,
        options.argon2_m,
        options.argon2_p,
    );

    const now: u64 = options.payload_created orelse @intCast(
        @max(@as(i64, 0), std.Io.Clock.real.now(io).toSeconds()),
    );
    const items = a.alloc(VaultItem, 0) catch return error.OutOfMemory;
    const payload: VaultPayload = .{
        .label = options.payload_label,
        .created = now,
        .modified = now,
        .items = items,
    };
    const encrypted_payload = try encryptPayload(a, io, dek, store_id, &payload);

    const slots = a.alloc(PrfKeySlot, 1) catch return error.OutOfMemory;
    slots[0] = .{
        .id = try slotIdAlloc(a, enrollment.credential_id),
        .label = a.dupe(u8, enrollment.label) catch return error.OutOfMemory,
        .credential_id_b64 = try base64EncodeAlloc(a, enrollment.credential_id),
        .cose_alg = enrollment.cose_alg,
        .public_key_b64 = try base64EncodeAlloc(a, enrollment.public_key),
        .sign_count = enrollment.sign_count,
        .prf_salt_b64 = try base64EncodeAlloc(a, &prf_salt),
        .wrap_nonce_b64 = prf_wrapped.wrap_nonce_b64,
        .wrapped_dek_b64 = prf_wrapped.wrapped_dek_b64,
        .created_at = enrollment.created_at,
    };
    const store_hex = std.fmt.bytesToHex(store_id, .lower);
    const store_id_hex = a.dupe(u8, &store_hex) catch return error.OutOfMemory;
    const document: VaultDocument = .{
        .backing_allocator = gpa,
        .arena = arena,
        .value = .{
            .store_id_hex = store_id_hex,
            .rp_id = a.dupe(u8, options.rp_id) catch return error.OutOfMemory,
            .prf_slots = slots,
            .recovery_slot = .{
                .kdf_salt_b64 = try base64EncodeAlloc(a, &recovery_salt),
                .argon2_t = options.argon2_t,
                .argon2_m = options.argon2_m,
                .argon2_p = options.argon2_p,
                .wrap_nonce_b64 = recovery_wrapped.wrap_nonce_b64,
                .wrapped_dek_b64 = recovery_wrapped.wrapped_dek_b64,
            },
            .payload_nonce_b64 = encrypted_payload.nonce_b64,
            .payload_ciphertext_b64 = encrypted_payload.ciphertext_b64,
        },
    };
    try validateEnvelope(&document.value);
    return .{
        .document = document,
        .dek = dek,
        .recovery_key = recovery_key,
    };
}

pub fn addPrfSlot(
    document: *VaultDocument,
    io: std.Io,
    dek_value: [dek_len]u8,
    enrollment: PrfEnrollment,
) Error!void {
    try validateCredential(enrollment.credential_id, enrollment.cose_alg, enrollment.public_key);
    var dek = dek_value;
    defer std.crypto.secureZero(u8, &dek);
    var prf_output = enrollment.prf_output;
    defer std.crypto.secureZero(u8, &prf_output);
    const a = document.allocator();
    const id = try slotIdAlloc(a, enrollment.credential_id);
    for (document.value.prf_slots) |slot| {
        if (std.mem.eql(u8, slot.id, id)) return error.DuplicateSlot;
    }

    const store_id = try parseStoreId(document.value.store_id_hex);
    var prf_salt: [prf_salt_len]u8 = enrollment.prf_salt orelse undefined;
    if (enrollment.prf_salt == null) secureRandom(io, &prf_salt);
    const wrapped = try wrapDekWithPrf(
        a,
        io,
        dek,
        prf_output,
        prf_salt,
        store_id,
        enrollment.credential_id,
    );

    const old = document.value.prf_slots;
    const slots = a.alloc(PrfKeySlot, old.len + 1) catch return error.OutOfMemory;
    @memcpy(slots[0..old.len], old);
    slots[old.len] = .{
        .id = id,
        .label = a.dupe(u8, enrollment.label) catch return error.OutOfMemory,
        .credential_id_b64 = try base64EncodeAlloc(a, enrollment.credential_id),
        .cose_alg = enrollment.cose_alg,
        .public_key_b64 = try base64EncodeAlloc(a, enrollment.public_key),
        .sign_count = enrollment.sign_count,
        .prf_salt_b64 = try base64EncodeAlloc(a, &prf_salt),
        .wrap_nonce_b64 = wrapped.wrap_nonce_b64,
        .wrapped_dek_b64 = wrapped.wrapped_dek_b64,
        .created_at = enrollment.created_at,
    };
    document.value.prf_slots = slots;
}

pub fn revokePrfSlot(document: *VaultDocument, id: []const u8) Error!void {
    const old = document.value.prf_slots;
    if (old.len <= 1) return error.LastPrfSlot;
    var remove_index: ?usize = null;
    for (old, 0..) |slot, index| {
        if (std.mem.eql(u8, slot.id, id)) {
            remove_index = index;
            break;
        }
    }
    const index = remove_index orelse return error.SlotNotFound;
    const slots = document.allocator().alloc(PrfKeySlot, old.len - 1) catch return error.OutOfMemory;
    @memcpy(slots[0..index], old[0..index]);
    @memcpy(slots[index..], old[index + 1 ..]);
    document.value.prf_slots = slots;
}

pub fn updateSlotSignCount(
    vault: *VaultFile,
    id: []const u8,
    new_sign_count: u32,
    last_used_at: i64,
) Error!void {
    const slot = findPrfSlotMut(vault, id) orelse return error.SlotNotFound;
    if ((slot.sign_count != 0 or new_sign_count != 0) and new_sign_count <= slot.sign_count) {
        return error.InvalidSignCount;
    }
    slot.sign_count = new_sign_count;
    slot.last_used_at = last_used_at;
}

pub fn findPrfSlot(vault: *const VaultFile, id: []const u8) ?*const PrfKeySlot {
    for (vault.prf_slots) |*slot| {
        if (std.mem.eql(u8, slot.id, id)) return slot;
    }
    return null;
}

pub fn loadVaultEnvelope(gpa: Allocator) Error!VaultDocument {
    const io = std.Io.Threaded.global_single_threaded.io();
    const path = try vaultPath(gpa);
    defer gpa.free(path);
    try ensureParentDir(io, path);
    var lock = try acquireLock(gpa, io, path);
    defer lock.deinit(io);

    var file = std.Io.Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.VaultNotFound,
        else => return error.PlatformFailure,
    };
    defer file.close(io);
    const stat = file.stat(io) catch return error.PlatformFailure;
    if (comptime isPosix()) {
        if (stat.permissions.toMode() & 0o077 != 0) {
            return error.InsecurePermissions;
        }
    }
    if (stat.size == 0 or stat.size > max_vault_size) return error.InvalidVault;
    const bytes = gpa.alloc(u8, @intCast(stat.size)) catch return error.OutOfMemory;
    defer gpa.free(bytes);
    const read = file.readPositionalAll(io, bytes, 0) catch return error.PlatformFailure;
    if (read != bytes.len) return error.InvalidVault;

    const arena = gpa.create(std.heap.ArenaAllocator) catch return error.OutOfMemory;
    arena.* = .init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const parsed = std.json.parseFromSliceLeaky(VaultFile, arena.allocator(), bytes, .{
        .allocate = .alloc_always,
    }) catch return error.InvalidVault;
    try validateEnvelope(&parsed);
    return .{
        .backing_allocator = gpa,
        .arena = arena,
        .value = parsed,
    };
}

pub fn saveVaultEnvelope(gpa: Allocator, vault: *const VaultFile) Error!void {
    try validateEnvelope(vault);
    const io = std.Io.Threaded.global_single_threaded.io();
    const path = try vaultPath(gpa);
    defer gpa.free(path);
    try ensureParentDir(io, path);
    var lock = try acquireLock(gpa, io, path);
    defer lock.deinit(io);

    const json = std.json.Stringify.valueAlloc(gpa, vault.*, .{
        .whitespace = .indent_2,
    }) catch return error.OutOfMemory;
    defer gpa.free(json);
    try writeAtomic(gpa, io, path, json);
}

pub fn vaultPath(gpa: Allocator) Error![]u8 {
    if (vault_path_override) |path| {
        if (path.len == 0) return error.VaultPathUnavailable;
        return gpa.dupe(u8, path) catch error.OutOfMemory;
    }
    if (getEnvVarOwned(gpa, "KEYRING_VAULT_PATH")) |path| {
        if (path.len != 0) return path;
        gpa.free(path);
    }
    if (getEnvVarOwned(gpa, "XDG_DATA_HOME")) |xdg| {
        defer gpa.free(xdg);
        if (xdg.len != 0) {
            return std.fs.path.join(gpa, &.{ xdg, "keyring", "vault.json" }) catch error.OutOfMemory;
        }
    }
    const home = getEnvVarOwned(gpa, "HOME") orelse return error.VaultPathUnavailable;
    defer gpa.free(home);
    if (home.len == 0) return error.VaultPathUnavailable;
    return std.fs.path.join(gpa, &.{ home, ".local", "share", "keyring", "vault.json" }) catch error.OutOfMemory;
}

pub fn validateEnvelope(vault: *const VaultFile) Error!void {
    if (vault.version != version) return error.UnsupportedVersion;
    _ = try parseStoreId(vault.store_id_hex);
    if (vault.rp_id.len == 0) return error.InvalidVault;
    var nonce: [gcm_nonce_len]u8 = undefined;
    try base64DecodeExact(vault.payload_nonce_b64, &nonce);
    const payload_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(
        vault.payload_ciphertext_b64,
    ) catch return error.InvalidVault;
    if (payload_len < gcm_tag_len) return error.InvalidVault;

    var seen_ids: std.StringHashMapUnmanaged(void) = .empty;
    defer seen_ids.deinit(std.heap.page_allocator);
    for (vault.prf_slots) |slot| {
        if (slot.id.len != 8 or slot.label.len == 0) return error.InvalidVault;
        if (slot.cose_alg != -7 and slot.cose_alg != -8) return error.InvalidVault;
        var credential_id: [max_credential_id_len]u8 = undefined;
        const credential_len = try base64DecodeInto(slot.credential_id_b64, &credential_id);
        if (credential_len == 0) return error.InvalidVault;
        var public_key: [65]u8 = undefined;
        const public_key_len = try base64DecodeInto(slot.public_key_b64, &public_key);
        if ((slot.cose_alg == -7 and public_key_len != 65) or
            (slot.cose_alg == -8 and public_key_len != 32))
        {
            return error.InvalidVault;
        }
        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(credential_id[0..credential_len], &digest, .{});
        const expected_id = std.fmt.bytesToHex(digest[0..4].*, .lower);
        if (!std.mem.eql(u8, slot.id, &expected_id)) return error.InvalidVault;
        var salt: [prf_salt_len]u8 = undefined;
        try base64DecodeExact(slot.prf_salt_b64, &salt);
        try base64DecodeExact(slot.wrap_nonce_b64, &nonce);
        var wrapped: [dek_len + gcm_tag_len]u8 = undefined;
        try base64DecodeExact(slot.wrapped_dek_b64, &wrapped);
        const result = seen_ids.getOrPut(std.heap.page_allocator, slot.id) catch return error.OutOfMemory;
        if (result.found_existing) return error.InvalidVault;
    }
    var recovery_salt: [recovery_salt_len]u8 = undefined;
    try base64DecodeExact(vault.recovery_slot.kdf_salt_b64, &recovery_salt);
    if (vault.recovery_slot.argon2_t == 0 or
        vault.recovery_slot.argon2_m == 0 or
        vault.recovery_slot.argon2_p == 0 or
        vault.recovery_slot.argon2_p > std.math.maxInt(u24))
    {
        return error.InvalidVault;
    }
    try base64DecodeExact(vault.recovery_slot.wrap_nonce_b64, &nonce);
    var recovery_wrapped: [dek_len + gcm_tag_len]u8 = undefined;
    try base64DecodeExact(vault.recovery_slot.wrapped_dek_b64, &recovery_wrapped);
}

fn findPrfSlotMut(vault: *VaultFile, id: []const u8) ?*PrfKeySlot {
    for (vault.prf_slots) |*slot| {
        if (std.mem.eql(u8, slot.id, id)) return slot;
    }
    return null;
}

fn validateCredential(credential_id: []const u8, cose_alg: i32, public_key: []const u8) Error!void {
    if (credential_id.len == 0 or credential_id.len > max_credential_id_len) {
        return error.InvalidCredential;
    }
    if ((cose_alg == -7 and public_key.len != 65) or
        (cose_alg == -8 and public_key.len != 32))
    {
        return error.InvalidCredential;
    }
}

fn slotIdAlloc(gpa: Allocator, credential_id: []const u8) Error![]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(credential_id, &digest, .{});
    const hex = std.fmt.bytesToHex(digest[0..4].*, .lower);
    return gpa.dupe(u8, &hex) catch error.OutOfMemory;
}

fn parseStoreId(encoded: []const u8) Error![store_id_len]u8 {
    if (encoded.len != store_id_len * 2) return error.InvalidVault;
    var out: [store_id_len]u8 = undefined;
    for (0..store_id_len) |index| {
        const high = std.fmt.charToDigit(encoded[index * 2], 16) catch return error.InvalidVault;
        const low = std.fmt.charToDigit(encoded[index * 2 + 1], 16) catch return error.InvalidVault;
        if (std.ascii.isUpper(encoded[index * 2]) or std.ascii.isUpper(encoded[index * 2 + 1])) {
            return error.InvalidVault;
        }
        out[index] = @intCast((high << 4) | low);
    }
    return out;
}

fn prfSlotAad(gpa: Allocator, store_id: [store_id_len]u8, credential_id_b64: []const u8) Error![]u8 {
    const store_hex = std.fmt.bytesToHex(store_id, .lower);
    return std.fmt.allocPrint(gpa, "{s}{s}:{s}", .{
        prf_slot_aad_prefix,
        store_hex,
        credential_id_b64,
    }) catch error.OutOfMemory;
}

fn storeBoundAad(gpa: Allocator, prefix: []const u8, store_id: [store_id_len]u8) Error![]u8 {
    const store_hex = std.fmt.bytesToHex(store_id, .lower);
    return std.fmt.allocPrint(gpa, "{s}{s}", .{ prefix, store_hex }) catch error.OutOfMemory;
}

fn base64EncodeAlloc(gpa: Allocator, bytes: []const u8) Error![]u8 {
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const out = gpa.alloc(u8, encoder.calcSize(bytes.len)) catch return error.OutOfMemory;
    _ = encoder.encode(out, bytes);
    return out;
}

fn base64DecodeAlloc(gpa: Allocator, encoded: []const u8) Error![]u8 {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const len = decoder.calcSizeForSlice(encoded) catch return error.InvalidVault;
    const out = gpa.alloc(u8, len) catch return error.OutOfMemory;
    errdefer gpa.free(out);
    decoder.decode(out, encoded) catch return error.InvalidVault;
    return out;
}

fn base64DecodeInto(encoded: []const u8, out: []u8) Error!usize {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const len = decoder.calcSizeForSlice(encoded) catch return error.InvalidVault;
    if (len > out.len) return error.InvalidVault;
    decoder.decode(out[0..len], encoded) catch return error.InvalidVault;
    return len;
}

fn base64DecodeExact(encoded: []const u8, out: []u8) Error!void {
    const len = try base64DecodeInto(encoded, out);
    if (len != out.len) return error.InvalidVault;
}

fn secureRandom(io: std.Io, out: []u8) void {
    io.randomSecure(out) catch io.random(out);
}

const LockFile = struct {
    file: std.Io.File,

    fn deinit(self: *LockFile, io: std.Io) void {
        self.file.unlock(io);
        self.file.close(io);
        self.* = undefined;
    }
};

fn acquireLock(gpa: Allocator, io: std.Io, path: []const u8) Error!LockFile {
    const lock_path = std.fmt.allocPrint(gpa, "{s}.lock", .{path}) catch return error.OutOfMemory;
    defer gpa.free(lock_path);
    const file = std.Io.Dir.cwd().createFile(io, lock_path, .{
        .read = true,
        .truncate = false,
        .lock = .exclusive,
        .permissions = privateFilePermissions(),
    }) catch return error.PlatformFailure;
    errdefer {
        file.unlock(io);
        file.close(io);
    }
    if (comptime isPosix()) {
        file.setPermissions(io, privateFilePermissions()) catch return error.PlatformFailure;
    }
    return .{ .file = file };
}

fn writeAtomic(gpa: Allocator, io: std.Io, path: []const u8, contents: []const u8) Error!void {
    var random_suffix: [8]u8 = undefined;
    secureRandom(io, &random_suffix);
    const suffix_hex = std.fmt.bytesToHex(random_suffix, .lower);
    const tmp_path = std.fmt.allocPrint(gpa, "{s}.tmp.{d}.{s}", .{
        path,
        processId(),
        suffix_hex,
    }) catch return error.OutOfMemory;
    defer gpa.free(tmp_path);

    var renamed = false;
    defer if (!renamed) std.Io.Dir.cwd().deleteFile(io, tmp_path) catch {};
    {
        var file = std.Io.Dir.cwd().createFile(io, tmp_path, .{
            .read = true,
            .truncate = true,
            .exclusive = true,
            .permissions = privateFilePermissions(),
        }) catch return error.PlatformFailure;
        defer file.close(io);
        if (comptime isPosix()) {
            file.setPermissions(io, privateFilePermissions()) catch return error.PlatformFailure;
        }
        file.writeStreamingAll(io, contents) catch return error.PlatformFailure;
        file.sync(io) catch return error.PlatformFailure;
    }
    std.Io.Dir.cwd().rename(tmp_path, std.Io.Dir.cwd(), path, io) catch return error.PlatformFailure;
    renamed = true;
}

fn ensureParentDir(io: std.Io, path: []const u8) Error!void {
    const parent = std.fs.path.dirname(path) orelse return;
    if (parent.len == 0) return;
    _ = std.Io.Dir.cwd().createDirPathStatus(io, parent, privateDirPermissions()) catch {
        return error.PlatformFailure;
    };
}

fn privateFilePermissions() std.Io.File.Permissions {
    return if (comptime isPosix()) .fromMode(0o600) else .default_file;
}

fn privateDirPermissions() std.Io.File.Permissions {
    return if (comptime isPosix()) .fromMode(0o700) else .default_dir;
}

fn isPosix() bool {
    return builtin.os.tag != .windows and builtin.os.tag != .wasi;
}

fn processId() u32 {
    return switch (builtin.os.tag) {
        .windows => std.os.windows.GetCurrentProcessId(),
        .wasi => 0,
        else => @intCast(std.c.getpid()),
    };
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

fn testVaultPath(tmp: *std.testing.TmpDir, gpa: Allocator) ![]u8 {
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(std.Io.Threaded.global_single_threaded.io(), &root_buf);
    return std.fs.path.join(gpa, &.{ root_buf[0..root_len], "vault.json" });
}

fn testEnrollment(prf_output: [prf_salt_len]u8, credential_id: []const u8, label: []const u8) PrfEnrollment {
    return .{
        .label = label,
        .credential_id = credential_id,
        .cose_alg = -8,
        .public_key = &@as([32]u8, @splat(0x42)),
        .sign_count = 0,
        .prf_output = prf_output,
        .created_at = 1_700_000_000,
    };
}

const fast_enrollment_options: EnrollmentOptions = .{
    .payload_created = 1_700_000_000,
    .argon2_t = 1,
    .argon2_m = 1024,
    .argon2_p = 1,
};

test "recovery key generation and normalization use Crockford Base32" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const key = generateRecoveryKey(io);
    try std.testing.expectEqual(@as(usize, 29), key.len);
    for (key, 0..) |character, index| {
        if ((index + 1) % 5 == 0) {
            try std.testing.expectEqual(@as(u8, '-'), character);
        } else {
            try std.testing.expect(std.mem.indexOfScalar(u8, crockford_alphabet, character) != null);
        }
    }
    const normalized = try normalizeRecoveryKey("o1il-2345-6789-abcd-efgh-jkmn");
    try std.testing.expectEqualStrings("011123456789ABCDEFGHJKMN", &normalized);
    try std.testing.expectError(error.InvalidRecoveryKey, normalizeRecoveryKey("too-short"));
    try std.testing.expectError(error.InvalidRecoveryKey, normalizeRecoveryKey("ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZU"));
}

test "initial enrollment unwraps the DEK through PRF and recovery slots" {
    const gpa = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    const prf_output: [prf_salt_len]u8 = @splat(0x11);
    var enrolled = try enrollInitialVault(
        gpa,
        io,
        testEnrollment(prf_output, "credential-primary", "primary"),
        fast_enrollment_options,
    );
    defer enrolled.deinit();
    const store_id = try parseStoreId(enrolled.document.value.store_id_hex);

    var via_prf = try unwrapDekWithPrf(
        gpa,
        prf_output,
        store_id,
        &enrolled.document.value.prf_slots[0],
    );
    defer std.crypto.secureZero(u8, &via_prf);
    try std.testing.expectEqualSlices(u8, &enrolled.dek, &via_prf);

    var normalized = try normalizeRecoveryKey(&enrolled.recovery_key);
    defer std.crypto.secureZero(u8, &normalized);
    var via_recovery = try unwrapDekWithRecovery(
        gpa,
        &normalized,
        store_id,
        &enrolled.document.value.recovery_slot,
    );
    defer std.crypto.secureZero(u8, &via_recovery);
    try std.testing.expectEqualSlices(u8, &enrolled.dek, &via_recovery);

    var wrong_recovery_key = normalized;
    defer std.crypto.secureZero(u8, &wrong_recovery_key);
    wrong_recovery_key[0] = if (wrong_recovery_key[0] == '0') '1' else '0';
    try std.testing.expectError(
        error.DecryptionFailed,
        unwrapDekWithRecovery(
            gpa,
            &wrong_recovery_key,
            store_id,
            &enrolled.document.value.recovery_slot,
        ),
    );
}

test "initial enrollment preserves ceremony store ID and PRF salt" {
    const gpa = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    const store_id: [store_id_len]u8 = @splat(0x91);
    const prf_salt: [prf_salt_len]u8 = @splat(0xa2);
    const prf_output: [prf_salt_len]u8 = @splat(0xb3);
    var enrolled = try enrollInitialVault(
        gpa,
        io,
        testEnrollment(prf_output, "credential-ceremony", "primary"),
        .{
            .payload_created = 1_700_000_000,
            .argon2_t = 1,
            .argon2_m = 1024,
            .argon2_p = 1,
            .store_id = store_id,
            .prf_salt = prf_salt,
        },
    );
    defer enrolled.deinit();

    const stored_store_id = try parseStoreId(enrolled.document.value.store_id_hex);
    try std.testing.expectEqualSlices(u8, &store_id, &stored_store_id);
    var stored_prf_salt: [prf_salt_len]u8 = undefined;
    try base64DecodeExact(enrolled.document.value.prf_slots[0].prf_salt_b64, &stored_prf_salt);
    try std.testing.expectEqualSlices(u8, &prf_salt, &stored_prf_salt);

    var unwrapped = try unwrapDekWithPrf(
        gpa,
        prf_output,
        stored_store_id,
        &enrolled.document.value.prf_slots[0],
    );
    defer std.crypto.secureZero(u8, &unwrapped);
    try std.testing.expectEqualSlices(u8, &enrolled.dek, &unwrapped);
}

test "adding a backup PRF slot and revoking the primary preserves access" {
    const gpa = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    const primary_prf: [prf_salt_len]u8 = @splat(0x21);
    const backup_prf: [prf_salt_len]u8 = @splat(0x31);
    var enrolled = try enrollInitialVault(
        gpa,
        io,
        testEnrollment(primary_prf, "credential-primary", "primary"),
        fast_enrollment_options,
    );
    defer enrolled.deinit();
    const primary_id = enrolled.document.value.prf_slots[0].id;
    try addPrfSlot(
        &enrolled.document,
        io,
        enrolled.dek,
        testEnrollment(backup_prf, "credential-backup", "backup"),
    );
    try std.testing.expectEqual(@as(usize, 2), enrolled.document.value.prf_slots.len);
    const backup_id = enrolled.document.value.prf_slots[1].id;
    const store_id = try parseStoreId(enrolled.document.value.store_id_hex);
    var via_backup = try unwrapDekWithPrf(
        gpa,
        backup_prf,
        store_id,
        &enrolled.document.value.prf_slots[1],
    );
    defer std.crypto.secureZero(u8, &via_backup);
    try std.testing.expectEqualSlices(u8, &enrolled.dek, &via_backup);

    try revokePrfSlot(&enrolled.document, primary_id);
    try std.testing.expect(findPrfSlot(&enrolled.document.value, primary_id) == null);
    try std.testing.expect(findPrfSlot(&enrolled.document.value, backup_id) != null);
    var after_revoke = try unwrapDekWithPrf(
        gpa,
        backup_prf,
        store_id,
        findPrfSlot(&enrolled.document.value, backup_id).?,
    );
    defer std.crypto.secureZero(u8, &after_revoke);
    try std.testing.expectEqualSlices(u8, &enrolled.dek, &after_revoke);
}

test "PRF unwrap rejects wrong output tampering and wrong store AAD" {
    const gpa = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    const prf_output: [prf_salt_len]u8 = @splat(0x41);
    var enrolled = try enrollInitialVault(
        gpa,
        io,
        testEnrollment(prf_output, "credential-primary", "primary"),
        fast_enrollment_options,
    );
    defer enrolled.deinit();
    const slot = &enrolled.document.value.prf_slots[0];
    const store_id = try parseStoreId(enrolled.document.value.store_id_hex);
    try std.testing.expectError(
        error.DecryptionFailed,
        unwrapDekWithPrf(gpa, @as([prf_salt_len]u8, @splat(0x42)), store_id, slot),
    );

    const original_wrapped = slot.wrapped_dek_b64;
    const tampered = try enrolled.document.allocator().dupe(u8, original_wrapped);
    tampered[0] = if (tampered[0] == 'A') 'B' else 'A';
    slot.wrapped_dek_b64 = tampered;
    try std.testing.expectError(
        error.DecryptionFailed,
        unwrapDekWithPrf(gpa, prf_output, store_id, slot),
    );
    slot.wrapped_dek_b64 = original_wrapped;

    var wrong_store_id = store_id;
    wrong_store_id[0] ^= 0xff;
    try std.testing.expectError(
        error.DecryptionFailed,
        unwrapDekWithPrf(gpa, prf_output, wrong_store_id, slot),
    );
}

test "payload encryption round-trips binary-safe items" {
    const gpa = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    const dek: [dek_len]u8 = @splat(0x51);
    const store_id: [store_id_len]u8 = @splat(0x61);
    var attributes: std.json.ArrayHashMap([]const u8) = .{};
    defer attributes.deinit(gpa);
    try attributes.map.put(gpa, "service", "example");
    var items = [_]VaultItem{.{
        .id = "item_1",
        .label = "example",
        .secret_b64 = "AP8Q",
        .attributes = attributes,
        .created = 1,
        .modified = 2,
    }};
    const payload: VaultPayload = .{
        .created = 1,
        .modified = 2,
        .next_item_id = 2,
        .items = &items,
    };
    var encrypted = try encryptPayload(gpa, io, dek, store_id, &payload);
    defer encrypted.deinit(gpa);
    var decrypted = try decryptPayload(
        gpa,
        dek,
        store_id,
        encrypted.nonce_b64,
        encrypted.ciphertext_b64,
    );
    defer decrypted.deinit();
    try std.testing.expectEqual(@as(usize, 1), decrypted.value.items.len);
    try std.testing.expectEqualStrings("AP8Q", decrypted.value.items[0].secret_b64);
    try std.testing.expectEqualStrings(
        "example",
        decrypted.value.items[0].attributes.map.get("service").?,
    );
}

test "vault envelope persists atomically and loads through a test path override" {
    const gpa = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testVaultPath(&tmp, gpa);
    defer gpa.free(path);
    vault_path_override = path;
    defer vault_path_override = null;

    const prf_output: [prf_salt_len]u8 = @splat(0x71);
    var enrolled = try enrollInitialVault(
        gpa,
        io,
        testEnrollment(prf_output, "credential-primary", "primary"),
        fast_enrollment_options,
    );
    defer enrolled.deinit();
    try saveVaultEnvelope(gpa, &enrolled.document.value);
    var loaded = try loadVaultEnvelope(gpa);
    defer loaded.deinit();
    try std.testing.expectEqualStrings(
        enrolled.document.value.store_id_hex,
        loaded.value.store_id_hex,
    );
    try std.testing.expectEqual(@as(usize, 1), loaded.value.prf_slots.len);
}

test "vault loader rejects group-readable permissions" {
    if (comptime !isPosix()) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testVaultPath(&tmp, gpa);
    defer gpa.free(path);
    vault_path_override = path;
    defer vault_path_override = null;

    const prf_output: [prf_salt_len]u8 = @splat(0x81);
    var enrolled = try enrollInitialVault(
        gpa,
        io,
        testEnrollment(prf_output, "credential-primary", "primary"),
        fast_enrollment_options,
    );
    defer enrolled.deinit();
    try saveVaultEnvelope(gpa, &enrolled.document.value);
    var file = try std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o644));
    try std.testing.expectError(error.InsecurePermissions, loadVaultEnvelope(gpa));
}
