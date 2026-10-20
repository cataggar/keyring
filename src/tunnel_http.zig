const std = @import("std");
const builtin = @import("builtin");
const webauthn = @import("webauthn.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Error = error{
    Timeout,
    InvalidRequest,
    RequestTooLarge,
    Forbidden,
    Unauthorized,
    Gone,
    ChallengeConsumed,
    NetworkFailure,
    InvalidConfiguration,
    UnsupportedPlatform,
};

pub const Mode = enum {
    enroll,
    unlock,
};

pub const Credential = struct {
    credential_id_b64: []const u8,
    cose_alg: i32,
    public_key_b64: []const u8,
    sign_count: u32,
    prf_salt_b64: []const u8,
};

pub const Config = struct {
    mode: Mode,
    port: u16 = 0,
    timeout_ms: u32 = 120_000,
    store_id_b64: []const u8,
    enrollment_prf_salt_b64: []const u8 = "",
    credentials: []const Credential = &.{},
};

pub const Result = union(Mode) {
    enroll: webauthn.VerifiedRegistration,
    unlock: webauthn.VerifiedAssertion,

    pub fn deinit(self: *Result, gpa: Allocator) void {
        switch (self.*) {
            .enroll => |*value| value.deinit(gpa),
            .unlock => |*value| value.deinit(gpa),
        }
        self.* = undefined;
    }
};

const max_header_bytes = 32 * 1024;
const max_body_bytes = 1024 * 1024;

pub const Server = struct {
    gpa: Allocator,
    io: Io,
    listener: std.Io.net.Server,
    listener_open: bool = true,
    config: Config,
    bound_port: u16,
    session_token: [43]u8,
    challenge: [43]u8,
    options_issued: bool = false,
    challenge_consumed: bool = false,
    completed: bool = false,
    deadline_ms: i64 = 0,

    pub fn init(gpa: Allocator, io: Io, config: Config) !Server {
        if (config.timeout_ms == 0 or config.store_id_b64.len == 0) return error.InvalidConfiguration;
        if (config.mode == .enroll and config.enrollment_prf_salt_b64.len == 0) return error.InvalidConfiguration;
        if (config.mode == .unlock and config.credentials.len == 0) return error.InvalidConfiguration;

        var address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(config.port) };
        var listener = try std.Io.net.IpAddress.listen(&address, io, .{ .reuse_address = true });
        errdefer listener.deinit(io);

        var token_bytes: [32]u8 = undefined;
        var challenge_bytes: [32]u8 = undefined;
        io.random(&token_bytes);
        io.random(&challenge_bytes);
        var token: [43]u8 = undefined;
        var challenge: [43]u8 = undefined;
        _ = std.base64.url_safe_no_pad.Encoder.encode(&token, &token_bytes);
        _ = std.base64.url_safe_no_pad.Encoder.encode(&challenge, &challenge_bytes);
        std.crypto.secureZero(u8, &token_bytes);
        std.crypto.secureZero(u8, &challenge_bytes);

        return .{
            .gpa = gpa,
            .io = io,
            .listener = listener,
            .config = config,
            .bound_port = listener.socket.address.getPort(),
            .session_token = token,
            .challenge = challenge,
        };
    }

    pub fn deinit(self: *Server) void {
        self.closeListener();
        std.crypto.secureZero(u8, &self.session_token);
        std.crypto.secureZero(u8, &self.challenge);
        self.* = undefined;
    }

    fn closeListener(self: *Server) void {
        if (!self.listener_open) return;
        self.listener.deinit(self.io);
        self.listener_open = false;
    }

    pub fn originAlloc(self: *const Server, gpa: Allocator) ![]u8 {
        return std.fmt.allocPrint(gpa, "http://localhost:{d}", .{self.bound_port});
    }

    pub fn browserUrlAlloc(self: *const Server, gpa: Allocator) ![]u8 {
        return std.fmt.allocPrint(gpa, "http://localhost:{d}/#token={s}", .{ self.bound_port, self.session_token });
    }

    pub fn writeInstructions(self: *const Server, writer: *Io.Writer, ssh_target: []const u8) !void {
        try writer.print(
            "[keyring] Listening on 127.0.0.1:{d} (expires in {d}s)\n" ++
                "[keyring] 1. Forward the port from your local machine:\n" ++
                "    ssh -L {d}:127.0.0.1:{d} {s}\n" ++
                "[keyring] 2. Open this URL in your local browser and touch your security key:\n" ++
                "    http://localhost:{d}/#token={s}\n",
            .{
                self.bound_port,
                (self.config.timeout_ms + 999) / 1000,
                self.bound_port,
                self.bound_port,
                ssh_target,
                self.bound_port,
                self.session_token,
            },
        );
        try writer.flush();
    }

    pub fn run(self: *Server) !Result {
        self.deadline_ms = nowMs(self.io) + self.config.timeout_ms;
        while (true) {
            self.waitFor(self.listener.socket.handle, std.posix.POLL.IN) catch |err| {
                if (err == error.Timeout) self.closeListener();
                return err;
            };
            var stream = self.listener.accept(self.io) catch return error.NetworkFailure;
            defer stream.socket.close(self.io);

            var request = readRequest(self.gpa, self.io, stream, self.deadline_ms) catch |err| {
                sendJson(self.io, stream, self.deadline_ms, 400, "Bad Request", "{\"ok\":false}") catch {};
                if (err == error.Timeout) {
                    self.closeListener();
                    return error.Timeout;
                }
                continue;
            };
            defer request.deinit(self.gpa);

            if (!validHost(&request, self.bound_port)) {
                try sendJson(self.io, stream, self.deadline_ms, 403, "Forbidden", "{\"ok\":false}");
                continue;
            }

            if (request.is("GET", "/")) {
                try sendHtml(self.io, stream, self.deadline_ms, ceremony_html);
                continue;
            }
            if (request.is("POST", "/api/options")) {
                const security_status = self.apiSecurityStatus(&request);
                if (security_status != .ok) {
                    try sendSecurityFailure(self.io, stream, self.deadline_ms, security_status);
                    continue;
                }
                if (self.expired() or self.completed) {
                    try sendJson(self.io, stream, self.deadline_ms, 410, "Gone", "{\"ok\":false}");
                    continue;
                }
                self.options_issued = true;
                const options = try self.optionsJson();
                defer self.gpa.free(options);
                try sendJson(self.io, stream, self.deadline_ms, 200, "OK", options);
                continue;
            }
            if (request.is("POST", "/api/complete")) {
                const security_status = self.apiSecurityStatus(&request);
                if (security_status != .ok) {
                    try sendSecurityFailure(self.io, stream, self.deadline_ms, security_status);
                    continue;
                }
                if (self.expired() or self.completed) {
                    try sendJson(self.io, stream, self.deadline_ms, 410, "Gone", "{\"ok\":false}");
                    continue;
                }
                self.consumeChallenge() catch {
                    try sendJson(self.io, stream, self.deadline_ms, 400, "Bad Request", "{\"ok\":false}");
                    continue;
                };

                const verified = self.verifyCompletion(request.body()) catch |err| {
                    try sendJson(self.io, stream, self.deadline_ms, 400, "Bad Request", "{\"ok\":false}");
                    self.closeListener();
                    return err;
                };
                self.completed = true;
                try sendJson(self.io, stream, self.deadline_ms, 200, "OK", "{\"ok\":true,\"status\":\"verified\"}");
                self.closeListener();
                return verified;
            }

            try sendJson(self.io, stream, self.deadline_ms, 404, "Not Found", "{\"ok\":false}");
        }
    }

    fn expired(self: *const Server) bool {
        return nowMs(self.io) >= self.deadline_ms;
    }

    fn consumeChallenge(self: *Server) Error!void {
        if (!self.options_issued or self.challenge_consumed) return error.ChallengeConsumed;
        self.challenge_consumed = true;
    }

    fn waitFor(self: *const Server, fd: std.posix.fd_t, events: @FieldType(std.posix.pollfd, "events")) !void {
        try waitForFd(self.io, fd, events, self.deadline_ms);
    }

    fn apiSecurityStatus(self: *const Server, request: *const Request) SecurityStatus {
        const origin = request.uniqueHeader("Origin") orelse return .forbidden;
        var expected_origin_buffer: [64]u8 = undefined;
        const expected_origin = std.fmt.bufPrint(&expected_origin_buffer, "http://localhost:{d}", .{self.bound_port}) catch return .forbidden;
        if (!std.mem.eql(u8, origin, expected_origin)) return .forbidden;

        const token = request.uniqueHeader("X-Keyring-Token") orelse return .unauthorized;
        if (token.len != self.session_token.len or
            !std.crypto.timing_safe.eql([43]u8, token[0..43].*, self.session_token))
        {
            return .unauthorized;
        }

        const content_type = request.uniqueHeader("Content-Type") orelse return .bad_request;
        if (content_type.len < "application/json".len or
            !std.ascii.eqlIgnoreCase(content_type[0.."application/json".len], "application/json"))
        {
            return .bad_request;
        }
        return .ok;
    }

    fn optionsJson(self: *const Server) ![]u8 {
        var out = std.Io.Writer.Allocating.init(self.gpa);
        defer out.deinit();
        try out.writer.print(
            "{{\"mode\":\"{s}\",\"challenge\":\"{s}\",\"rpId\":\"localhost\",\"storeId\":\"{s}\"",
            .{ @tagName(self.config.mode), self.challenge, self.config.store_id_b64 },
        );
        switch (self.config.mode) {
            .enroll => try out.writer.print(
                ",\"prfSalt\":\"{s}\",\"userId\":\"{s}\",\"credentials\":[]}}",
                .{ self.config.enrollment_prf_salt_b64, self.config.store_id_b64 },
            ),
            .unlock => {
                try out.writer.writeAll(",\"credentials\":[");
                for (self.config.credentials, 0..) |credential, index| {
                    if (index != 0) try out.writer.writeByte(',');
                    try out.writer.print(
                        "{{\"credentialId\":\"{s}\",\"prfSalt\":\"{s}\"}}",
                        .{ credential.credential_id_b64, credential.prf_salt_b64 },
                    );
                }
                try out.writer.writeAll("]}");
            },
        }
        return self.gpa.dupe(u8, out.written());
    }

    fn verifyCompletion(self: *Server, body: []const u8) !Result {
        const CompletePayload = struct {
            credentialId: ?[]const u8 = null,
            clientDataJSON: ?[]const u8 = null,
            attestationObject: ?[]const u8 = null,
            authenticatorData: ?[]const u8 = null,
            signature: ?[]const u8 = null,
            prfOutput: ?[]const u8 = null,
        };
        var payload = std.json.parseFromSlice(CompletePayload, self.gpa, body, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch return error.InvalidRequest;
        defer payload.deinit();

        const client_data = try decodeB64Alloc(self.gpa, payload.value.clientDataJSON orelse return error.InvalidRequest);
        defer self.gpa.free(client_data);
        const origin = try self.originAlloc(self.gpa);
        defer self.gpa.free(origin);

        switch (self.config.mode) {
            .enroll => {
                const credential_id_b64 = payload.value.credentialId orelse return error.InvalidRequest;
                const expected_credential_id = try decodeB64Alloc(self.gpa, credential_id_b64);
                defer self.gpa.free(expected_credential_id);
                const attestation = try decodeB64Alloc(self.gpa, payload.value.attestationObject orelse return error.InvalidRequest);
                defer self.gpa.free(attestation);
                var registration = try webauthn.verifyRegistration(
                    self.gpa,
                    attestation,
                    client_data,
                    &self.challenge,
                    origin,
                    "localhost",
                    payload.value.prfOutput,
                );
                errdefer registration.deinit(self.gpa);
                if (!std.mem.eql(u8, expected_credential_id, registration.credential_id)) return error.InvalidRequest;
                return .{ .enroll = registration };
            },
            .unlock => {
                const credential_id_b64 = payload.value.credentialId orelse return error.InvalidRequest;
                const credential = self.findCredential(credential_id_b64) orelse return error.InvalidRequest;
                const credential_id = try decodeB64Alloc(self.gpa, credential_id_b64);
                defer self.gpa.free(credential_id);
                const auth_data = try decodeB64Alloc(self.gpa, payload.value.authenticatorData orelse return error.InvalidRequest);
                defer self.gpa.free(auth_data);
                const signature = try decodeB64Alloc(self.gpa, payload.value.signature orelse return error.InvalidRequest);
                defer self.gpa.free(signature);
                const public_key = try decodeB64Alloc(self.gpa, credential.public_key_b64);
                defer self.gpa.free(public_key);
                return .{ .unlock = try webauthn.verifyAssertion(
                    self.gpa,
                    credential_id,
                    auth_data,
                    client_data,
                    signature,
                    &self.challenge,
                    origin,
                    "localhost",
                    credential.cose_alg,
                    public_key,
                    credential.sign_count,
                    payload.value.prfOutput,
                ) };
            },
        }
    }

    fn findCredential(self: *const Server, credential_id_b64: []const u8) ?Credential {
        for (self.config.credentials) |credential| {
            if (std.mem.eql(u8, credential.credential_id_b64, credential_id_b64)) return credential;
        }
        return null;
    }
};

const SecurityStatus = enum {
    ok,
    forbidden,
    unauthorized,
    bad_request,
};

fn sendSecurityFailure(io: Io, stream: std.Io.net.Stream, deadline_ms: i64, status: SecurityStatus) !void {
    switch (status) {
        .ok => unreachable,
        .forbidden => try sendJson(io, stream, deadline_ms, 403, "Forbidden", "{\"ok\":false}"),
        .unauthorized => try sendJson(io, stream, deadline_ms, 401, "Unauthorized", "{\"ok\":false}"),
        .bad_request => try sendJson(io, stream, deadline_ms, 400, "Bad Request", "{\"ok\":false}"),
    }
}

const Request = struct {
    storage: []u8,
    header_end: usize,
    body_start: usize,

    fn deinit(self: *Request, gpa: Allocator) void {
        gpa.free(self.storage);
        self.* = undefined;
    }

    fn requestLine(self: *const Request) []const u8 {
        const end = std.mem.indexOf(u8, self.storage[0..self.header_end], "\r\n") orelse return &.{};
        return self.storage[0..end];
    }

    fn is(self: *const Request, method: []const u8, path: []const u8) bool {
        const line = self.requestLine();
        var parts = std.mem.splitScalar(u8, line, ' ');
        const actual_method = parts.next() orelse return false;
        const actual_path = parts.next() orelse return false;
        const version = parts.next() orelse return false;
        if (parts.next() != null) return false;
        return std.mem.eql(u8, actual_method, method) and
            std.mem.eql(u8, actual_path, path) and
            (std.mem.eql(u8, version, "HTTP/1.1") or std.mem.eql(u8, version, "HTTP/1.0"));
    }

    fn uniqueHeader(self: *const Request, name: []const u8) ?[]const u8 {
        const first_line_end = std.mem.indexOf(u8, self.storage[0..self.header_end], "\r\n") orelse return null;
        var lines = std.mem.splitSequence(u8, self.storage[first_line_end + 2 .. self.header_end], "\r\n");
        var found: ?[]const u8 = null;
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
            const header_name = std.mem.trim(u8, line[0..colon], " \t");
            if (!std.ascii.eqlIgnoreCase(header_name, name)) continue;
            if (found != null) return null;
            found = std.mem.trim(u8, line[colon + 1 ..], " \t");
        }
        return found;
    }

    fn body(self: *const Request) []const u8 {
        return self.storage[self.body_start..];
    }
};

fn readRequest(gpa: Allocator, io: Io, stream: std.Io.net.Stream, deadline_ms: i64) !Request {
    var storage: std.ArrayList(u8) = .empty;
    errdefer storage.deinit(gpa);
    var read_buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);

    var header_end: ?usize = null;
    while (header_end == null) {
        if (storage.items.len >= max_header_bytes) return error.RequestTooLarge;
        const b = try readByteWithDeadline(io, &reader.interface, stream.socket.handle, deadline_ms);
        try storage.append(gpa, b);
        if (storage.items.len >= 4 and std.mem.endsWith(u8, storage.items, "\r\n\r\n")) {
            header_end = storage.items.len - 2;
        }
    }

    const body_start = storage.items.len;
    var partial = Request{
        .storage = storage.items,
        .header_end = header_end.?,
        .body_start = body_start,
    };
    const content_length_value = partial.uniqueHeader("Content-Length");
    const content_length = if (content_length_value) |value|
        std.fmt.parseInt(usize, value, 10) catch return error.InvalidRequest
    else
        0;
    if (content_length > max_body_bytes) return error.RequestTooLarge;
    try storage.ensureUnusedCapacity(gpa, content_length);
    for (0..content_length) |_| {
        const b = try readByteWithDeadline(io, &reader.interface, stream.socket.handle, deadline_ms);
        storage.appendAssumeCapacity(b);
    }

    const owned = try storage.toOwnedSlice(gpa);
    return .{ .storage = owned, .header_end = header_end.?, .body_start = body_start };
}

fn readByteWithDeadline(io: Io, reader: *Io.Reader, fd: std.posix.fd_t, deadline_ms: i64) !u8 {
    if (reader.seek == reader.end) try waitForFd(io, fd, std.posix.POLL.IN, deadline_ms);
    return reader.takeByte() catch return error.InvalidRequest;
}

fn validHost(request: *const Request, port: u16) bool {
    const host = request.uniqueHeader("Host") orelse return false;
    var expected_buffer: [64]u8 = undefined;
    const expected = std.fmt.bufPrint(&expected_buffer, "localhost:{d}", .{port}) catch return false;
    return std.ascii.eqlIgnoreCase(host, expected);
}

fn decodeB64Alloc(gpa: Allocator, encoded: []const u8) ![]u8 {
    const len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded) catch return error.InvalidRequest;
    const result = try gpa.alloc(u8, len);
    errdefer gpa.free(result);
    std.base64.url_safe_no_pad.Decoder.decode(result, encoded) catch return error.InvalidRequest;
    return result;
}

fn nowMs(io: Io) i64 {
    return std.Io.Clock.awake.now(io).toMilliseconds();
}

fn waitForFd(io: Io, fd: std.posix.fd_t, events: @FieldType(std.posix.pollfd, "events"), deadline_ms: i64) !void {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return error.UnsupportedPlatform;
    const remaining = deadline_ms - nowMs(io);
    if (remaining <= 0) return error.Timeout;
    var fds = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = events,
        .revents = 0,
    }};
    const ready = std.posix.poll(&fds, @intCast(@min(remaining, std.math.maxInt(i32)))) catch return error.NetworkFailure;
    if (ready == 0) return error.Timeout;
    if ((fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL)) != 0 and
        (fds[0].revents & events) == 0)
    {
        return error.NetworkFailure;
    }
}

fn sendJson(io: Io, stream: std.Io.net.Stream, deadline_ms: i64, status: u16, reason: []const u8, body: []const u8) !void {
    try waitForFd(io, stream.socket.handle, std.posix.POLL.OUT, deadline_ms);
    var buffer: [2048]u8 = undefined;
    var writer = stream.writer(io, &buffer);
    writer.interface.print(
        "HTTP/1.1 {d} {s}\r\n" ++
            "Content-Type: application/json\r\n" ++
            "Cache-Control: no-store\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n\r\n{s}",
        .{ status, reason, body.len, body },
    ) catch return error.NetworkFailure;
    writer.interface.flush() catch return error.NetworkFailure;
}

fn sendHtml(io: Io, stream: std.Io.net.Stream, deadline_ms: i64, body: []const u8) !void {
    try waitForFd(io, stream.socket.handle, std.posix.POLL.OUT, deadline_ms);
    var buffer: [4096]u8 = undefined;
    var writer = stream.writer(io, &buffer);
    writer.interface.print(
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/html; charset=utf-8\r\n" ++
            "Cache-Control: no-store\r\n" ++
            "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'\r\n" ++
            "X-Frame-Options: DENY\r\n" ++
            "Referrer-Policy: no-referrer\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n\r\n{s}",
        .{ body.len, body },
    ) catch return error.NetworkFailure;
    writer.interface.flush() catch return error.NetworkFailure;
}

const ceremony_html =
    \\<!doctype html>
    \\<html><head><meta charset="utf-8"><title>Keyring security key approval</title>
    \\<style>body{font:16px system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem}pre{white-space:pre-wrap;color:#900}</style></head>
    \\<body><h1>Keyring security key approval</h1><p id="status">Preparing WebAuthn…</p><pre id="error"></pre>
    \\<script>
    \\const statusNode=document.getElementById('status'),errorNode=document.getElementById('error');
    \\const b64uToBytes=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0))};
    \\const bytesToB64u=b=>{let s='';for(const x of new Uint8Array(b))s+=String.fromCharCode(x);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
    \\async function post(path,token,body){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-Keyring-Token':token},body:JSON.stringify(body),cache:'no-store'});if(!r.ok)throw new Error(`${path} failed (${r.status})`);return r.json()}
    \\async function run(){
    \\  const token=new URLSearchParams(location.hash.slice(1)).get('token');history.replaceState(null,'','/');
    \\  if(!token)throw new Error('Missing one-time session token. Open the URL printed by keyring.');
    \\  if(!window.PublicKeyCredential||!navigator.credentials)throw new Error('This browser does not support WebAuthn.');
    \\  const o=await post('/api/options',token,{});
    \\  let credential;
    \\  if(o.mode==='enroll'){
    \\    credential=await navigator.credentials.create({publicKey:{challenge:b64uToBytes(o.challenge),rp:{id:o.rpId,name:'Keyring'},user:{id:b64uToBytes(o.userId),name:`keyring-${o.storeId}`,displayName:'Keyring security key'},pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-8}],authenticatorSelection:{residentKey:'discouraged',userVerification:'preferred'},timeout:120000,attestation:'none',extensions:{prf:{eval:{first:b64uToBytes(o.prfSalt)}}}}});
    \\  }else{
    \\    const allow=o.credentials.map(c=>({type:'public-key',id:b64uToBytes(c.credentialId)}));
    \\    const evalByCredential={};for(const c of o.credentials)evalByCredential[c.credentialId]={first:b64uToBytes(c.prfSalt)};
    \\    credential=await navigator.credentials.get({publicKey:{challenge:b64uToBytes(o.challenge),rpId:o.rpId,allowCredentials:allow,userVerification:'preferred',timeout:120000,extensions:{prf:{evalByCredential}}}});
    \\  }
    \\  const ext=credential.getClientExtensionResults(),first=ext&&ext.prf&&ext.prf.results&&ext.prf.results.first;
    \\  if(!first||new Uint8Array(first).byteLength!==32)throw new Error('This browser or security key did not return the required WebAuthn PRF output.');
    \\  const payload={credentialId:bytesToB64u(credential.rawId),clientDataJSON:bytesToB64u(credential.response.clientDataJSON),prfOutput:bytesToB64u(first)};
    \\  if(o.mode==='enroll')payload.attestationObject=bytesToB64u(credential.response.attestationObject);
    \\  else{payload.authenticatorData=bytesToB64u(credential.response.authenticatorData);payload.signature=bytesToB64u(credential.response.signature)}
    \\  await post('/api/complete',token,payload);statusNode.textContent='Security key verified. You may close this tab.';
    \\}
    \\run().catch(e=>{statusNode.textContent='Approval failed.';errorNode.textContent=e.message});
    \\</script></body></html>
;

fn parseRequestForTest(gpa: Allocator, raw: []const u8) !Request {
    const separator = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.InvalidRequest;
    return .{
        .storage = try gpa.dupe(u8, raw),
        .header_end = separator + 2,
        .body_start = separator + 4,
    };
}

fn b64Alloc(gpa: Allocator, bytes: []const u8) ![]u8 {
    const result = try gpa.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(bytes.len));
    _ = std.base64.url_safe_no_pad.Encoder.encode(result, bytes);
    return result;
}

fn testAuthData(gpa: Allocator, rp_id: []const u8, flags: u8, count: u32, credential_id: ?[]const u8, cose: ?[]const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var rp_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(rp_id, &rp_hash, .{});
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

fn cborHead(out: *std.ArrayList(u8), gpa: Allocator, major: u3, value: usize) !void {
    const prefix: u8 = @as(u8, major) << 5;
    if (value < 24) {
        try out.append(gpa, prefix | @as(u8, @intCast(value)));
    } else {
        try out.appendSlice(gpa, &.{ prefix | 24, @intCast(value) });
    }
}

fn cborInt(out: *std.ArrayList(u8), gpa: Allocator, value: i64) !void {
    try cborHead(out, gpa, if (value < 0) 1 else 0, @intCast(if (value < 0) -1 - value else value));
}

fn cborBytes(out: *std.ArrayList(u8), gpa: Allocator, bytes: []const u8) !void {
    try cborHead(out, gpa, 2, bytes.len);
    try out.appendSlice(gpa, bytes);
}

fn testEdCose(gpa: Allocator, public_key: [32]u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try cborHead(&out, gpa, 5, 4);
    try cborInt(&out, gpa, 1);
    try cborInt(&out, gpa, 1);
    try cborInt(&out, gpa, 3);
    try cborInt(&out, gpa, -8);
    try cborInt(&out, gpa, -1);
    try cborInt(&out, gpa, 6);
    try cborInt(&out, gpa, -2);
    try cborBytes(&out, gpa, &public_key);
    return out.toOwnedSlice(gpa);
}

fn sendTestRequest(gpa: Allocator, io: Io, port: u16, request: []const u8) ![]u8 {
    var address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(port) };
    var stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream });
    defer stream.socket.close(io);
    var write_buffer: [4096]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    try writer.interface.writeAll(request);
    try writer.interface.flush();
    var read_buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var response: std.ArrayList(u8) = .empty;
    errdefer response.deinit(gpa);
    var chunk: [1024]u8 = undefined;
    while (true) {
        const n = reader.interface.readSliceShort(&chunk) catch |err| return err;
        if (n == 0) break;
        try response.appendSlice(gpa, chunk[0..n]);
    }
    return response.toOwnedSlice(gpa);
}

fn apiRequest(gpa: Allocator, port: u16, path: []const u8, token: []const u8, body: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "POST {s} HTTP/1.1\r\nHost: localhost:{d}\r\nOrigin: http://localhost:{d}\r\nX-Keyring-Token: {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ path, port, port, token, body.len, body },
    );
}

const TestThreadContext = struct {
    server: *Server,
    result: ?Result = null,
    err: ?anyerror = null,

    fn run(self: *TestThreadContext) void {
        self.result = self.server.run() catch |err| {
            self.err = err;
            return;
        };
    }
};

test "Host Origin token and content type checks" {
    const gpa = std.testing.allocator;
    var request = try parseRequestForTest(gpa, "POST /api/options HTTP/1.1\r\nHost: LOCALHOST:1234\r\nOrigin: http://localhost:1234\r\nX-Keyring-Token: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 2\r\n\r\n{}");
    defer request.deinit(gpa);
    try std.testing.expect(validHost(&request, 1234));
    try std.testing.expect(!validHost(&request, 1235));

    var server: Server = undefined;
    server.bound_port = 1234;
    server.session_token = @splat('A');
    try std.testing.expectEqual(SecurityStatus.ok, server.apiSecurityStatus(&request));

    var bad_origin = try parseRequestForTest(gpa, "POST /api/options HTTP/1.1\r\nHost: localhost:1234\r\nOrigin: http://evil.test\r\nX-Keyring-Token: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}");
    defer bad_origin.deinit(gpa);
    try std.testing.expectEqual(SecurityStatus.forbidden, server.apiSecurityStatus(&bad_origin));

    var bad_token = try parseRequestForTest(gpa, "POST /api/options HTTP/1.1\r\nHost: localhost:1234\r\nOrigin: http://localhost:1234\r\nX-Keyring-Token: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}");
    defer bad_token.deinit(gpa);
    try std.testing.expectEqual(SecurityStatus.unauthorized, server.apiSecurityStatus(&bad_token));
}

test "single-use challenge consumption rejects replay" {
    var server: Server = undefined;
    server.options_issued = true;
    server.challenge_consumed = false;
    try server.consumeChallenge();
    try std.testing.expect(server.challenge_consumed);
    try std.testing.expectError(error.ChallengeConsumed, server.consumeChallenge());
}

test "full simulated enroll and unlock HTTP ceremonies" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Ed25519 = std.crypto.sign.Ed25519;
    const key_pair = try Ed25519.KeyPair.generateDeterministic(@splat(0x31));
    const public_key = key_pair.public_key.toBytes();
    const credential_id = "loopback-ed25519-id";
    const credential_id_b64 = try b64Alloc(gpa, credential_id);
    defer gpa.free(credential_id_b64);
    const public_key_b64 = try b64Alloc(gpa, &public_key);
    defer gpa.free(public_key_b64);
    const prf_bytes: [32]u8 = @splat(0x5a);
    const prf_b64 = try b64Alloc(gpa, &prf_bytes);
    defer gpa.free(prf_b64);
    const salt_bytes: [32]u8 = @splat(0x6b);
    const salt_b64 = try b64Alloc(gpa, &salt_bytes);
    defer gpa.free(salt_b64);
    const store_id_bytes: [16]u8 = @splat(0x7c);
    const store_id_b64 = try b64Alloc(gpa, &store_id_bytes);
    defer gpa.free(store_id_b64);

    const cose = try testEdCose(gpa, public_key);
    defer gpa.free(cose);
    const registration_auth = try testAuthData(gpa, "localhost", 0x41, 1, credential_id, cose);
    defer gpa.free(registration_auth);
    const registration_b64 = try b64Alloc(gpa, registration_auth);
    defer gpa.free(registration_b64);

    var enroll_server = try Server.init(gpa, io, .{
        .mode = .enroll,
        .timeout_ms = 5_000,
        .store_id_b64 = store_id_b64,
        .enrollment_prf_salt_b64 = salt_b64,
    });
    defer enroll_server.deinit();
    var enroll_context = TestThreadContext{ .server = &enroll_server };
    const enroll_thread = try std.Thread.spawn(.{}, TestThreadContext.run, .{&enroll_context});

    const options_request = try apiRequest(gpa, enroll_server.bound_port, "/api/options", &enroll_server.session_token, "{}");
    defer gpa.free(options_request);
    const options_response = try sendTestRequest(gpa, io, enroll_server.bound_port, options_request);
    defer gpa.free(options_response);
    try std.testing.expect(std.mem.indexOf(u8, options_response, "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, options_response, &enroll_server.challenge) != null);

    const enroll_origin = try enroll_server.originAlloc(gpa);
    defer gpa.free(enroll_origin);
    const create_json = try std.fmt.allocPrint(
        gpa,
        "{{\"type\":\"webauthn.create\",\"challenge\":\"{s}\",\"origin\":\"{s}\"}}",
        .{ enroll_server.challenge, enroll_origin },
    );
    defer gpa.free(create_json);
    const create_json_b64 = try b64Alloc(gpa, create_json);
    defer gpa.free(create_json_b64);
    const complete_body = try std.fmt.allocPrint(
        gpa,
        "{{\"credentialId\":\"{s}\",\"clientDataJSON\":\"{s}\",\"attestationObject\":\"{s}\",\"prfOutput\":\"{s}\"}}",
        .{ credential_id_b64, create_json_b64, registration_b64, prf_b64 },
    );
    defer gpa.free(complete_body);
    const complete_request = try apiRequest(gpa, enroll_server.bound_port, "/api/complete", &enroll_server.session_token, complete_body);
    defer gpa.free(complete_request);
    const complete_response = try sendTestRequest(gpa, io, enroll_server.bound_port, complete_request);
    defer gpa.free(complete_response);
    enroll_thread.join();
    try std.testing.expect(enroll_context.err == null);
    try std.testing.expect(std.mem.indexOf(u8, complete_response, "200 OK") != null);
    var enroll_result = enroll_context.result.?;
    defer enroll_result.deinit(gpa);
    try std.testing.expectEqualSlices(u8, credential_id, enroll_result.enroll.credential_id);

    const credentials = [_]Credential{.{
        .credential_id_b64 = credential_id_b64,
        .cose_alg = -8,
        .public_key_b64 = public_key_b64,
        .sign_count = 1,
        .prf_salt_b64 = salt_b64,
    }};
    var unlock_server = try Server.init(gpa, io, .{
        .mode = .unlock,
        .timeout_ms = 5_000,
        .store_id_b64 = store_id_b64,
        .credentials = &credentials,
    });
    defer unlock_server.deinit();
    var unlock_context = TestThreadContext{ .server = &unlock_server };
    const unlock_thread = try std.Thread.spawn(.{}, TestThreadContext.run, .{&unlock_context});

    const unlock_options_request = try apiRequest(gpa, unlock_server.bound_port, "/api/options", &unlock_server.session_token, "{}");
    defer gpa.free(unlock_options_request);
    const unlock_options_response = try sendTestRequest(gpa, io, unlock_server.bound_port, unlock_options_request);
    defer gpa.free(unlock_options_response);
    try std.testing.expect(std.mem.indexOf(u8, unlock_options_response, "200 OK") != null);

    const unlock_origin = try unlock_server.originAlloc(gpa);
    defer gpa.free(unlock_origin);
    const get_json = try std.fmt.allocPrint(
        gpa,
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{s}\",\"origin\":\"{s}\"}}",
        .{ unlock_server.challenge, unlock_origin },
    );
    defer gpa.free(get_json);
    const assertion_auth = try testAuthData(gpa, "localhost", 0x01, 2, null, null);
    defer gpa.free(assertion_auth);
    var client_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(get_json, &client_hash, .{});
    const signed = try std.mem.concat(gpa, u8, &.{ assertion_auth, &client_hash });
    defer gpa.free(signed);
    const signature = try key_pair.sign(signed, null);
    const signature_bytes = signature.toBytes();
    const get_json_b64 = try b64Alloc(gpa, get_json);
    defer gpa.free(get_json_b64);
    const assertion_auth_b64 = try b64Alloc(gpa, assertion_auth);
    defer gpa.free(assertion_auth_b64);
    const signature_b64 = try b64Alloc(gpa, &signature_bytes);
    defer gpa.free(signature_b64);
    const unlock_body = try std.fmt.allocPrint(
        gpa,
        "{{\"credentialId\":\"{s}\",\"clientDataJSON\":\"{s}\",\"authenticatorData\":\"{s}\",\"signature\":\"{s}\",\"prfOutput\":\"{s}\"}}",
        .{ credential_id_b64, get_json_b64, assertion_auth_b64, signature_b64, prf_b64 },
    );
    defer gpa.free(unlock_body);
    const unlock_request = try apiRequest(gpa, unlock_server.bound_port, "/api/complete", &unlock_server.session_token, unlock_body);
    defer gpa.free(unlock_request);
    const unlock_response = try sendTestRequest(gpa, io, unlock_server.bound_port, unlock_request);
    defer gpa.free(unlock_response);
    unlock_thread.join();
    try std.testing.expect(unlock_context.err == null);
    try std.testing.expect(std.mem.indexOf(u8, unlock_response, "200 OK") != null);
    var unlock_result = unlock_context.result.?;
    defer unlock_result.deinit(gpa);
    try std.testing.expectEqual(@as(u32, 2), unlock_result.unlock.new_sign_count);
}

test "server timeout closes the listener" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const salt: [32]u8 = @splat(1);
    const salt_b64 = try b64Alloc(gpa, &salt);
    defer gpa.free(salt_b64);
    var server = try Server.init(gpa, threaded.io(), .{
        .mode = .enroll,
        .timeout_ms = 20,
        .store_id_b64 = "store",
        .enrollment_prf_salt_b64 = salt_b64,
    });
    defer server.deinit();
    try std.testing.expectError(error.Timeout, server.run());
    try std.testing.expect(!server.listener_open);
}
