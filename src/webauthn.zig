const std = @import("std");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Ed25519 = std.crypto.sign.Ed25519;

pub const Error = error{
    InvalidCbor,
    InvalidAttestationObject,
    InvalidAuthenticatorData,
    InvalidCoseKey,
    UnsupportedAlgorithm,
    InvalidClientData,
    ChallengeMismatch,
    OriginMismatch,
    RpIdMismatch,
    UserNotPresent,
    AttestedCredentialDataMissing,
    PrfUnsupported,
    SignatureInvalid,
    ClonedAuthenticator,
};

pub const ParsedAuthenticatorData = struct {
    rp_id_hash: [32]u8,
    flags: u8,
    up: bool,
    uv: bool,
    at: bool,
    sign_count: u32,
    aaguid: ?[16]u8 = null,
    credential_id: ?[]u8 = null,
    cose_alg: ?i32 = null,
    public_key: ?[]u8 = null,

    pub fn deinit(self: *ParsedAuthenticatorData, gpa: Allocator) void {
        if (self.credential_id) |value| gpa.free(value);
        if (self.public_key) |value| gpa.free(value);
        self.* = undefined;
    }
};

pub const VerifiedRegistration = struct {
    credential_id: []u8,
    cose_alg: i32,
    public_key: []u8,
    sign_count: u32,
    prf_output: [32]u8,

    pub fn deinit(self: *VerifiedRegistration, gpa: Allocator) void {
        gpa.free(self.credential_id);
        gpa.free(self.public_key);
        std.crypto.secureZero(u8, &self.prf_output);
        self.* = undefined;
    }
};

pub const VerifiedAssertion = struct {
    credential_id: []u8,
    new_sign_count: u32,
    prf_output: [32]u8,

    pub fn deinit(self: *VerifiedAssertion, gpa: Allocator) void {
        gpa.free(self.credential_id);
        std.crypto.secureZero(u8, &self.prf_output);
        self.* = undefined;
    }
};

const CborHead = struct {
    major: u3,
    value: u64,
};

const CborReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn remaining(self: *const CborReader) usize {
        return self.bytes.len - self.pos;
    }

    fn take(self: *CborReader, len: usize) Error![]const u8 {
        if (len > self.remaining()) return error.InvalidCbor;
        const result = self.bytes[self.pos .. self.pos + len];
        self.pos += len;
        return result;
    }

    fn byte(self: *CborReader) Error!u8 {
        return (try self.take(1))[0];
    }

    fn uintBytes(self: *CborReader, len: usize) Error!u64 {
        const raw = try self.take(len);
        var result: u64 = 0;
        for (raw) |b| result = (result << 8) | b;
        return result;
    }

    fn head(self: *CborReader) Error!CborHead {
        const first = try self.byte();
        const additional = first & 0x1f;
        const value: u64 = switch (additional) {
            0...23 => additional,
            24 => try self.uintBytes(1),
            25 => try self.uintBytes(2),
            26 => try self.uintBytes(4),
            27 => try self.uintBytes(8),
            else => return error.InvalidCbor,
        };
        return .{ .major = @intCast(first >> 5), .value = value };
    }

    fn length(value: u64) Error!usize {
        return std.math.cast(usize, value) orelse error.InvalidCbor;
    }

    fn unsigned(self: *CborReader) Error!u64 {
        const item = try self.head();
        if (item.major != 0) return error.InvalidCbor;
        return item.value;
    }

    fn integer(self: *CborReader) Error!i64 {
        const item = try self.head();
        return switch (item.major) {
            0 => std.math.cast(i64, item.value) orelse error.InvalidCbor,
            1 => if (item.value <= std.math.maxInt(i64))
                -1 - @as(i64, @intCast(item.value))
            else
                error.InvalidCbor,
            else => error.InvalidCbor,
        };
    }

    fn bytestring(self: *CborReader) Error![]const u8 {
        const item = try self.head();
        if (item.major != 2) return error.InvalidCbor;
        return self.take(try length(item.value));
    }

    fn text(self: *CborReader) Error![]const u8 {
        const item = try self.head();
        if (item.major != 3) return error.InvalidCbor;
        return self.take(try length(item.value));
    }

    fn containerLength(self: *CborReader, expected_major: u3) Error!usize {
        const item = try self.head();
        if (item.major != expected_major) return error.InvalidCbor;
        return length(item.value);
    }

    fn skip(self: *CborReader, depth: usize) Error!void {
        if (depth > 16) return error.InvalidCbor;
        const item = try self.head();
        const len = try length(item.value);
        switch (item.major) {
            0, 1 => {},
            2, 3 => _ = try self.take(len),
            4 => for (0..len) |_| try self.skip(depth + 1),
            5 => for (0..len) |_| {
                try self.skip(depth + 1);
                try self.skip(depth + 1);
            },
            else => return error.InvalidCbor,
        }
    }
};

pub fn parseAttestationObject(gpa: Allocator, cbor_bytes: []const u8) (Error || Allocator.Error)![]u8 {
    if (cbor_bytes.len == 0) return error.InvalidAttestationObject;

    const first_major: u3 = @intCast(cbor_bytes[0] >> 5);
    if (first_major == 5) {
        if (extractAttestationAuthData(gpa, cbor_bytes)) |auth_data| {
            return auth_data;
        } else |_| {}
    }

    if (cbor_bytes.len < 37) return error.InvalidAuthenticatorData;
    return gpa.dupe(u8, cbor_bytes);
}

fn extractAttestationAuthData(gpa: Allocator, cbor_bytes: []const u8) (Error || Allocator.Error)![]u8 {
    var reader: CborReader = .{ .bytes = cbor_bytes };
    const map_len = reader.containerLength(5) catch return error.InvalidAttestationObject;
    for (0..map_len) |_| {
        const key = reader.text() catch return error.InvalidAttestationObject;
        if (std.mem.eql(u8, key, "authData")) {
            const auth_data = reader.bytestring() catch return error.InvalidAttestationObject;
            if (auth_data.len < 37) return error.InvalidAuthenticatorData;
            return gpa.dupe(u8, auth_data);
        }
        reader.skip(0) catch return error.InvalidAttestationObject;
    }
    return error.InvalidAttestationObject;
}

const ParsedCoseKey = struct {
    alg: i32,
    public_key: []u8,
};

fn parseCoseKey(gpa: Allocator, encoded: []const u8) (Error || Allocator.Error)!ParsedCoseKey {
    var reader: CborReader = .{ .bytes = encoded };
    const map_len = reader.containerLength(5) catch return error.InvalidCoseKey;

    var kty: ?i64 = null;
    var alg: ?i64 = null;
    var crv: ?i64 = null;
    var x: ?[]const u8 = null;
    var y: ?[]const u8 = null;

    for (0..map_len) |_| {
        const label = reader.integer() catch return error.InvalidCoseKey;
        switch (label) {
            1 => kty = std.math.cast(i64, reader.unsigned() catch return error.InvalidCoseKey) orelse return error.InvalidCoseKey,
            3 => alg = reader.integer() catch return error.InvalidCoseKey,
            -1 => crv = std.math.cast(i64, reader.unsigned() catch return error.InvalidCoseKey) orelse return error.InvalidCoseKey,
            -2 => x = reader.bytestring() catch return error.InvalidCoseKey,
            -3 => y = reader.bytestring() catch return error.InvalidCoseKey,
            else => reader.skip(0) catch return error.InvalidCoseKey,
        }
    }

    if (reader.pos > encoded.len) return error.InvalidCoseKey;
    const algorithm = alg orelse return error.InvalidCoseKey;
    if (algorithm == -7) {
        if (kty != 2 or crv != 1) return error.InvalidCoseKey;
        const x_bytes = x orelse return error.InvalidCoseKey;
        const y_bytes = y orelse return error.InvalidCoseKey;
        if (x_bytes.len != 32 or y_bytes.len != 32) return error.InvalidCoseKey;
        const public_key = try gpa.alloc(u8, 65);
        errdefer gpa.free(public_key);
        public_key[0] = 0x04;
        @memcpy(public_key[1..33], x_bytes);
        @memcpy(public_key[33..65], y_bytes);
        _ = EcdsaP256Sha256.PublicKey.fromSec1(public_key) catch return error.InvalidCoseKey;
        return .{ .alg = -7, .public_key = public_key };
    }
    if (algorithm == -8) {
        if (kty != 1 or crv != 6) return error.InvalidCoseKey;
        const x_bytes = x orelse return error.InvalidCoseKey;
        if (x_bytes.len != 32) return error.InvalidCoseKey;
        _ = Ed25519.PublicKey.fromBytes(x_bytes[0..32].*) catch return error.InvalidCoseKey;
        return .{ .alg = -8, .public_key = try gpa.dupe(u8, x_bytes) };
    }
    return error.UnsupportedAlgorithm;
}

pub fn parseAuthenticatorData(gpa: Allocator, auth_data: []const u8) (Error || Allocator.Error)!ParsedAuthenticatorData {
    if (auth_data.len < 37) return error.InvalidAuthenticatorData;

    var parsed: ParsedAuthenticatorData = .{
        .rp_id_hash = auth_data[0..32].*,
        .flags = auth_data[32],
        .up = (auth_data[32] & 0x01) != 0,
        .uv = (auth_data[32] & 0x04) != 0,
        .at = (auth_data[32] & 0x40) != 0,
        .sign_count = std.mem.readInt(u32, auth_data[33..37], .big),
    };
    errdefer parsed.deinit(gpa);

    if (!parsed.at) return parsed;
    if (auth_data.len < 55) return error.InvalidAuthenticatorData;
    parsed.aaguid = auth_data[37..53].*;
    const credential_id_len = std.mem.readInt(u16, auth_data[53..55], .big);
    const credential_end = std.math.add(usize, 55, credential_id_len) catch return error.InvalidAuthenticatorData;
    if (credential_end >= auth_data.len) return error.InvalidAuthenticatorData;
    parsed.credential_id = try gpa.dupe(u8, auth_data[55..credential_end]);

    const cose = try parseCoseKey(gpa, auth_data[credential_end..]);
    parsed.cose_alg = cose.alg;
    parsed.public_key = cose.public_key;
    return parsed;
}

const ClientData = struct {
    type: ?[]const u8 = null,
    challenge: ?[]const u8 = null,
    origin: ?[]const u8 = null,
};

fn timingSafeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    if (a.len == 43) return std.crypto.timing_safe.eql([43]u8, a[0..43].*, b[0..43].*);
    var difference: u8 = 0;
    for (a, b) |left, right| difference |= left ^ right;
    return difference == 0;
}

pub fn verifyClientDataJson(
    gpa: Allocator,
    client_data_bytes: []const u8,
    expected_type: []const u8,
    expected_challenge_b64: []const u8,
    expected_origin: []const u8,
) (Error || Allocator.Error)!void {
    var parsed = std.json.parseFromSlice(ClientData, gpa, client_data_bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.InvalidClientData;
    defer parsed.deinit();

    const actual_type = parsed.value.type orelse return error.InvalidClientData;
    const challenge = parsed.value.challenge orelse return error.InvalidClientData;
    const origin = parsed.value.origin orelse return error.InvalidClientData;
    if (!std.mem.eql(u8, actual_type, expected_type)) return error.InvalidClientData;
    if (!timingSafeEql(challenge, expected_challenge_b64)) return error.ChallengeMismatch;
    if (!std.mem.eql(u8, origin, expected_origin)) return error.OriginMismatch;
}

fn verifyRpId(auth_data: ParsedAuthenticatorData, expected_rp_id: []const u8) Error!void {
    var expected_hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(expected_rp_id, &expected_hash, .{});
    if (!std.crypto.timing_safe.eql([32]u8, auth_data.rp_id_hash, expected_hash)) return error.RpIdMismatch;
}

fn decodePrfOutput(encoded: ?[]const u8) Error![32]u8 {
    const source = encoded orelse return error.PrfUnsupported;
    const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(source) catch return error.PrfUnsupported;
    if (decoded_len != 32) return error.PrfUnsupported;
    var result: [32]u8 = undefined;
    std.base64.url_safe_no_pad.Decoder.decode(&result, source) catch return error.PrfUnsupported;
    var any_nonzero: u8 = 0;
    for (result) |b| any_nonzero |= b;
    if (any_nonzero == 0) return error.PrfUnsupported;
    return result;
}

pub fn verifyRegistration(
    gpa: Allocator,
    attestation_or_auth_data: []const u8,
    client_data_json: []const u8,
    expected_challenge_b64: []const u8,
    expected_origin: []const u8,
    expected_rp_id: []const u8,
    prf_output_b64: ?[]const u8,
) (Error || Allocator.Error)!VerifiedRegistration {
    try verifyClientDataJson(gpa, client_data_json, "webauthn.create", expected_challenge_b64, expected_origin);
    const auth_data_bytes = try parseAttestationObject(gpa, attestation_or_auth_data);
    defer gpa.free(auth_data_bytes);
    var auth_data = try parseAuthenticatorData(gpa, auth_data_bytes);
    defer auth_data.deinit(gpa);

    try verifyRpId(auth_data, expected_rp_id);
    if (!auth_data.up) return error.UserNotPresent;
    if (!auth_data.at) return error.AttestedCredentialDataMissing;
    const credential_id = auth_data.credential_id orelse return error.InvalidAuthenticatorData;
    const public_key = auth_data.public_key orelse return error.InvalidCoseKey;
    const cose_alg = auth_data.cose_alg orelse return error.InvalidCoseKey;
    const prf_output = try decodePrfOutput(prf_output_b64);

    const owned_credential_id = try gpa.dupe(u8, credential_id);
    errdefer gpa.free(owned_credential_id);
    const owned_public_key = try gpa.dupe(u8, public_key);
    return .{
        .credential_id = owned_credential_id,
        .cose_alg = cose_alg,
        .public_key = owned_public_key,
        .sign_count = auth_data.sign_count,
        .prf_output = prf_output,
    };
}

pub fn verifyAssertion(
    gpa: Allocator,
    credential_id: []const u8,
    authenticator_data: []const u8,
    client_data_json: []const u8,
    signature: []const u8,
    expected_challenge_b64: []const u8,
    expected_origin: []const u8,
    expected_rp_id: []const u8,
    cose_alg: i32,
    public_key: []const u8,
    stored_sign_count: u32,
    prf_output_b64: ?[]const u8,
) (Error || Allocator.Error)!VerifiedAssertion {
    try verifyClientDataJson(gpa, client_data_json, "webauthn.get", expected_challenge_b64, expected_origin);
    var auth_data = try parseAuthenticatorData(gpa, authenticator_data);
    defer auth_data.deinit(gpa);
    try verifyRpId(auth_data, expected_rp_id);
    if (!auth_data.up) return error.UserNotPresent;

    var client_hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(client_data_json, &client_hash, .{});
    const signed_data = try gpa.alloc(u8, authenticator_data.len + client_hash.len);
    defer gpa.free(signed_data);
    @memcpy(signed_data[0..authenticator_data.len], authenticator_data);
    @memcpy(signed_data[authenticator_data.len..], &client_hash);

    switch (cose_alg) {
        -7 => {
            const key = EcdsaP256Sha256.PublicKey.fromSec1(public_key) catch return error.SignatureInvalid;
            const sig = if (signature.len == EcdsaP256Sha256.Signature.encoded_length)
                EcdsaP256Sha256.Signature.fromBytes(signature[0..EcdsaP256Sha256.Signature.encoded_length].*)
            else
                EcdsaP256Sha256.Signature.fromDer(signature) catch return error.SignatureInvalid;
            sig.verify(signed_data, key) catch return error.SignatureInvalid;
        },
        -8 => {
            if (public_key.len != Ed25519.PublicKey.encoded_length or signature.len != Ed25519.Signature.encoded_length) return error.SignatureInvalid;
            const key = Ed25519.PublicKey.fromBytes(public_key[0..Ed25519.PublicKey.encoded_length].*) catch return error.SignatureInvalid;
            const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
            sig.verify(signed_data, key) catch return error.SignatureInvalid;
        },
        else => return error.UnsupportedAlgorithm,
    }

    if ((stored_sign_count > 0 or auth_data.sign_count > 0) and auth_data.sign_count <= stored_sign_count) {
        return error.ClonedAuthenticator;
    }
    const prf_output = try decodePrfOutput(prf_output_b64);
    return .{
        .credential_id = try gpa.dupe(u8, credential_id),
        .new_sign_count = auth_data.sign_count,
        .prf_output = prf_output,
    };
}

fn appendCborHead(out: *std.ArrayList(u8), gpa: Allocator, major: u3, value: usize) !void {
    const prefix: u8 = @as(u8, major) << 5;
    if (value < 24) {
        try out.append(gpa, prefix | @as(u8, @intCast(value)));
    } else if (value <= std.math.maxInt(u8)) {
        try out.appendSlice(gpa, &.{ prefix | 24, @intCast(value) });
    } else if (value <= std.math.maxInt(u16)) {
        try out.append(gpa, prefix | 25);
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, @intCast(value), .big);
        try out.appendSlice(gpa, &bytes);
    } else {
        return error.TestValueTooLarge;
    }
}

fn appendCborInt(out: *std.ArrayList(u8), gpa: Allocator, value: i64) !void {
    if (value >= 0) return appendCborHead(out, gpa, 0, @intCast(value));
    return appendCborHead(out, gpa, 1, @intCast(-1 - value));
}

fn appendCborBytes(out: *std.ArrayList(u8), gpa: Allocator, value: []const u8) !void {
    try appendCborHead(out, gpa, 2, value.len);
    try out.appendSlice(gpa, value);
}

fn appendCborText(out: *std.ArrayList(u8), gpa: Allocator, value: []const u8) !void {
    try appendCborHead(out, gpa, 3, value.len);
    try out.appendSlice(gpa, value);
}

fn buildCoseKey(gpa: Allocator, alg: i32, public_key: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    if (alg == -7) {
        try appendCborHead(&out, gpa, 5, 5);
        try appendCborInt(&out, gpa, 1);
        try appendCborInt(&out, gpa, 2);
        try appendCborInt(&out, gpa, 3);
        try appendCborInt(&out, gpa, -7);
        try appendCborInt(&out, gpa, -1);
        try appendCborInt(&out, gpa, 1);
        try appendCborInt(&out, gpa, -2);
        try appendCborBytes(&out, gpa, public_key[1..33]);
        try appendCborInt(&out, gpa, -3);
        try appendCborBytes(&out, gpa, public_key[33..65]);
    } else {
        try appendCborHead(&out, gpa, 5, 4);
        try appendCborInt(&out, gpa, 1);
        try appendCborInt(&out, gpa, 1);
        try appendCborInt(&out, gpa, 3);
        try appendCborInt(&out, gpa, -8);
        try appendCborInt(&out, gpa, -1);
        try appendCborInt(&out, gpa, 6);
        try appendCborInt(&out, gpa, -2);
        try appendCborBytes(&out, gpa, public_key);
    }
    return out.toOwnedSlice(gpa);
}

fn buildAuthData(gpa: Allocator, rp_id: []const u8, flags: u8, count: u32, credential_id: ?[]const u8, cose: ?[]const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var rp_hash: [32]u8 = undefined;
    Sha256.hash(rp_id, &rp_hash, .{});
    try out.appendSlice(gpa, &rp_hash);
    try out.append(gpa, flags);
    var count_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &count_bytes, count, .big);
    try out.appendSlice(gpa, &count_bytes);
    if (credential_id) |id| {
        try out.appendNTimes(gpa, 0, 16);
        var id_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &id_len, @intCast(id.len), .big);
        try out.appendSlice(gpa, &id_len);
        try out.appendSlice(gpa, id);
        try out.appendSlice(gpa, cose.?);
    }
    return out.toOwnedSlice(gpa);
}

fn clientJson(gpa: Allocator, ceremony_type: []const u8, challenge: []const u8, origin: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "{{\"type\":\"{s}\",\"challenge\":\"{s}\",\"origin\":\"{s}\"}}", .{
        ceremony_type,
        challenge,
        origin,
    });
}

fn prfB64(out: *[43]u8) []const u8 {
    const bytes: [32]u8 = @splat(0xa5);
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, &bytes);
    return out;
}

test "ES256 registration and assertion verification" {
    const gpa = std.testing.allocator;
    const key_pair = try EcdsaP256Sha256.KeyPair.generateDeterministic(@splat(7));
    const public_key = key_pair.public_key.toUncompressedSec1();
    const cose = try buildCoseKey(gpa, -7, &public_key);
    defer gpa.free(cose);
    const credential_id = "p256-credential";
    const registration_auth = try buildAuthData(gpa, "localhost", 0x41, 1, credential_id, cose);
    defer gpa.free(registration_auth);
    const challenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const origin = "http://localhost:12345";
    const create_json = try clientJson(gpa, "webauthn.create", challenge, origin);
    defer gpa.free(create_json);
    var prf_encoded: [43]u8 = undefined;

    var registration = try verifyRegistration(gpa, registration_auth, create_json, challenge, origin, "localhost", prfB64(&prf_encoded));
    defer registration.deinit(gpa);
    try std.testing.expectEqual(@as(i32, -7), registration.cose_alg);
    try std.testing.expectEqualSlices(u8, credential_id, registration.credential_id);
    try std.testing.expectEqualSlices(u8, &public_key, registration.public_key);

    const get_json = try clientJson(gpa, "webauthn.get", challenge, origin);
    defer gpa.free(get_json);
    const assertion_auth = try buildAuthData(gpa, "localhost", 0x01, 2, null, null);
    defer gpa.free(assertion_auth);
    var client_hash: [32]u8 = undefined;
    Sha256.hash(get_json, &client_hash, .{});
    const signed = try std.mem.concat(gpa, u8, &.{ assertion_auth, &client_hash });
    defer gpa.free(signed);
    const signature = try key_pair.sign(signed, null);
    var der: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der_slice = signature.toDer(&der);

    var assertion = try verifyAssertion(
        gpa,
        credential_id,
        assertion_auth,
        get_json,
        der_slice,
        challenge,
        origin,
        "localhost",
        -7,
        &public_key,
        1,
        prfB64(&prf_encoded),
    );
    defer assertion.deinit(gpa);
    try std.testing.expectEqual(@as(u32, 2), assertion.new_sign_count);
}

test "EdDSA registration and assertion verification" {
    const gpa = std.testing.allocator;
    const key_pair = try Ed25519.KeyPair.generateDeterministic(@splat(9));
    const public_key = key_pair.public_key.toBytes();
    const cose = try buildCoseKey(gpa, -8, &public_key);
    defer gpa.free(cose);
    const credential_id = "ed25519-credential";
    const registration_auth = try buildAuthData(gpa, "localhost", 0x45, 0, credential_id, cose);
    defer gpa.free(registration_auth);
    const challenge = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const origin = "http://localhost:23456";
    const create_json = try clientJson(gpa, "webauthn.create", challenge, origin);
    defer gpa.free(create_json);
    var prf_encoded: [43]u8 = undefined;
    var registration = try verifyRegistration(gpa, registration_auth, create_json, challenge, origin, "localhost", prfB64(&prf_encoded));
    defer registration.deinit(gpa);
    try std.testing.expectEqual(@as(i32, -8), registration.cose_alg);

    const get_json = try clientJson(gpa, "webauthn.get", challenge, origin);
    defer gpa.free(get_json);
    const assertion_auth = try buildAuthData(gpa, "localhost", 0x01, 0, null, null);
    defer gpa.free(assertion_auth);
    var client_hash: [32]u8 = undefined;
    Sha256.hash(get_json, &client_hash, .{});
    const signed = try std.mem.concat(gpa, u8, &.{ assertion_auth, &client_hash });
    defer gpa.free(signed);
    const signature = try key_pair.sign(signed, null);
    const signature_bytes = signature.toBytes();

    var assertion = try verifyAssertion(
        gpa,
        credential_id,
        assertion_auth,
        get_json,
        &signature_bytes,
        challenge,
        origin,
        "localhost",
        -8,
        &public_key,
        0,
        prfB64(&prf_encoded),
    );
    defer assertion.deinit(gpa);
    try std.testing.expectEqual(@as(u32, 0), assertion.new_sign_count);
}

test "attestation object extracts authData" {
    const gpa = std.testing.allocator;
    const raw = try buildAuthData(gpa, "localhost", 0x01, 0, null, null);
    defer gpa.free(raw);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(gpa);
    try appendCborHead(&encoded, gpa, 5, 2);
    try appendCborText(&encoded, gpa, "fmt");
    try appendCborText(&encoded, gpa, "none");
    try appendCborText(&encoded, gpa, "authData");
    try appendCborBytes(&encoded, gpa, raw);
    const parsed = try parseAttestationObject(gpa, encoded.items);
    defer gpa.free(parsed);
    try std.testing.expectEqualSlices(u8, raw, parsed);
}

test "verification rejects bad origin RP ID flags counter and PRF" {
    const gpa = std.testing.allocator;
    const key_pair = try Ed25519.KeyPair.generateDeterministic(@splat(3));
    const public_key = key_pair.public_key.toBytes();
    const challenge = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    const origin = "http://localhost:34567";
    const get_json = try clientJson(gpa, "webauthn.get", challenge, origin);
    defer gpa.free(get_json);
    const bad_origin_json = try clientJson(gpa, "webauthn.get", challenge, "http://evil.test");
    defer gpa.free(bad_origin_json);
    try std.testing.expectError(error.OriginMismatch, verifyClientDataJson(gpa, bad_origin_json, "webauthn.get", challenge, origin));

    const auth = try buildAuthData(gpa, "localhost", 0x01, 4, null, null);
    defer gpa.free(auth);
    var hash: [32]u8 = undefined;
    Sha256.hash(get_json, &hash, .{});
    const signed = try std.mem.concat(gpa, u8, &.{ auth, &hash });
    defer gpa.free(signed);
    const signature = try key_pair.sign(signed, null);
    const sig_bytes = signature.toBytes();
    var prf_encoded: [43]u8 = undefined;
    var bad_sig = sig_bytes;
    bad_sig[0] ^= 1;

    try std.testing.expectError(error.RpIdMismatch, verifyAssertion(
        gpa,
        "id",
        auth,
        get_json,
        &sig_bytes,
        challenge,
        origin,
        "other",
        -8,
        &public_key,
        3,
        prfB64(&prf_encoded),
    ));
    try std.testing.expectError(error.SignatureInvalid, verifyAssertion(
        gpa,
        "id",
        auth,
        get_json,
        &bad_sig,
        challenge,
        origin,
        "localhost",
        -8,
        &public_key,
        3,
        prfB64(&prf_encoded),
    ));
    try std.testing.expectError(error.ClonedAuthenticator, verifyAssertion(
        gpa,
        "id",
        auth,
        get_json,
        &sig_bytes,
        challenge,
        origin,
        "localhost",
        -8,
        &public_key,
        4,
        prfB64(&prf_encoded),
    ));
    try std.testing.expectError(error.PrfUnsupported, verifyAssertion(
        gpa,
        "id",
        auth,
        get_json,
        &sig_bytes,
        challenge,
        origin,
        "localhost",
        -8,
        &public_key,
        3,
        null,
    ));

    const no_up = try buildAuthData(gpa, "localhost", 0x00, 5, null, null);
    defer gpa.free(no_up);
    try std.testing.expectError(error.UserNotPresent, verifyAssertion(
        gpa,
        "id",
        no_up,
        get_json,
        &sig_bytes,
        challenge,
        origin,
        "localhost",
        -8,
        &public_key,
        3,
        prfB64(&prf_encoded),
    ));

    var zeros_encoded: [43]u8 = undefined;
    const zeros: [32]u8 = @splat(0);
    _ = std.base64.url_safe_no_pad.Encoder.encode(&zeros_encoded, &zeros);
    try std.testing.expectError(error.PrfUnsupported, verifyAssertion(
        gpa,
        "id",
        auth,
        get_json,
        &sig_bytes,
        challenge,
        origin,
        "localhost",
        -8,
        &public_key,
        3,
        &zeros_encoded,
    ));
}
