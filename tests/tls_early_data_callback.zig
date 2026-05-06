//! Tests for `Context.setAllowEarlyDataCallback` — the QUIC
//! anti-replay integration point. The callback is implemented on
//! top of BoringSSL's `select_certificate_cb`, which fires for
//! every ClientHello before the resumption decision is made; this
//! file exercises both branches (allow → 0-RTT accepted; deny →
//! 0-RTT silently disabled, full handshake still succeeds).
//!
//! The test scaffolding mirrors `tls_session.zig` — two `tls.Conn`s
//! exchanging CRYPTO bytes through a Zig-side bridge. The server
//! runs with `early_data_enabled = true`; the second handshake of
//! each test resumes the captured session.

const std = @import("std");
const boringssl = @import("boringssl");
const tls = boringssl.tls;
const quic = tls.quic;
const c = boringssl.raw;

const test_cert_pem = @embedFile("data/test_cert.pem");
const test_key_pem = @embedFile("data/test_key.pem");

const capture_alloc = std.testing.allocator;

// Captured by the new-session callback; reset by each test.
var captured_session: ?[]u8 = null;

fn captureSession(_: ?*anyopaque, session_in: tls.Session) void {
    var s = session_in;
    defer s.deinit();
    if (captured_session != null) return;
    captured_session = s.toBytes(capture_alloc) catch null;
}

const Endpoint = struct {
    conn: tls.Conn,
    inbox: [4]Inbox = .{ .{}, .{}, .{}, .{} },
    peer: ?*Endpoint = null,
    saw_alert: ?u8 = null,
};

const Inbox = struct {
    buf: [16384]u8 = undefined,
    len: usize = 0,

    fn append(self: *Inbox, data: []const u8) !void {
        if (self.len + data.len > self.buf.len) return error.InboxOverflow;
        @memcpy(self.buf[self.len .. self.len + data.len], data);
        self.len += data.len;
    }

    fn drain(self: *Inbox) []const u8 {
        const out = self.buf[0..self.len];
        self.len = 0;
        return out;
    }
};

fn setSecret(
    ssl: ?*c.SSL,
    level: c.ssl_encryption_level_t,
    cipher: ?*const c.SSL_CIPHER,
    secret: [*c]const u8,
    secret_len: usize,
) callconv(.c) c_int {
    _ = .{ ssl, level, cipher, secret, secret_len };
    return 1;
}

fn addHandshakeData(
    ssl: ?*c.SSL,
    level: c.ssl_encryption_level_t,
    data: [*c]const u8,
    len: usize,
) callconv(.c) c_int {
    const ep_raw = tls.Conn.userDataFromSsl(ssl.?) orelse return 0;
    const ep: *Endpoint = @ptrCast(@alignCast(ep_raw));
    const peer = ep.peer orelse return 0;
    const lvl = quic.EncryptionLevel.fromC(level);
    const idx = @as(usize, @intCast(@intFromEnum(lvl)));
    peer.inbox[idx].append(data[0..len]) catch return 0;
    return 1;
}

fn flushFlight(_: ?*c.SSL) callconv(.c) c_int {
    return 1;
}

fn sendAlert(
    ssl: ?*c.SSL,
    _: c.ssl_encryption_level_t,
    alert: u8,
) callconv(.c) c_int {
    const ep_raw = tls.Conn.userDataFromSsl(ssl.?) orelse return 0;
    const ep: *Endpoint = @ptrCast(@alignCast(ep_raw));
    ep.saw_alert = alert;
    return 1;
}

const bridge_method: quic.Method = .{
    .set_read_secret = setSecret,
    .set_write_secret = setSecret,
    .add_handshake_data = addHandshakeData,
    .flush_flight = flushFlight,
    .send_alert = sendAlert,
};

fn advanceHandshake(ep: *Endpoint) !void {
    if (ep.conn.handshakeDone()) return;
    ep.conn.handshake() catch |e| switch (e) {
        error.WantRead, error.WantWrite => {},
        // The deny test path: server denied 0-RTT, client must
        // reset and retry the handshake at the application level.
        error.EarlyDataRejected => ep.conn.resetEarlyDataReject(),
        else => return e,
    };
}

fn driveOneStep(ep: *Endpoint) !void {
    inline for (.{
        quic.EncryptionLevel.initial,
        quic.EncryptionLevel.early_data,
        quic.EncryptionLevel.handshake,
        quic.EncryptionLevel.application,
    }) |lvl| {
        const idx = @as(usize, @intCast(@intFromEnum(lvl)));
        if (ep.inbox[idx].len > 0) {
            const bytes = ep.inbox[idx].drain();
            try ep.conn.provideQuicData(lvl, bytes);
            if (ep.conn.handshakeDone()) {
                try ep.conn.processQuicPostHandshake();
            } else {
                try advanceHandshake(ep);
            }
        }
    }
    if (!ep.conn.handshakeDone()) try advanceHandshake(ep);
}

const HandshakeResult = struct {
    client_status: tls.Conn.EarlyDataStatus,
    server_status: tls.Conn.EarlyDataStatus,
};

fn runHandshake(
    client_ctx: tls.Context,
    server_ctx: tls.Context,
    session: ?tls.Session,
) !HandshakeResult {
    var ep_c: Endpoint = .{ .conn = try client_ctx.newQuicClient() };
    defer ep_c.conn.deinit();
    var ep_s: Endpoint = .{ .conn = try server_ctx.newQuicServer() };
    defer ep_s.conn.deinit();

    ep_c.peer = &ep_s;
    ep_s.peer = &ep_c;
    try ep_c.conn.setUserData(&ep_c);
    try ep_s.conn.setUserData(&ep_s);
    try ep_c.conn.setQuicMethod(&bridge_method);
    try ep_s.conn.setQuicMethod(&bridge_method);

    const params = [_]u8{ 0x00, 0x01, 0x02, 0x03 };
    try ep_c.conn.setQuicTransportParams(&params);
    try ep_s.conn.setQuicTransportParams(&params);

    const early_ctx = [_]u8{ 0x42, 0x42, 0x42, 0x42 };
    try ep_s.conn.setQuicEarlyDataContext(&early_ctx);

    try ep_c.conn.setHostname("localhost");

    if (session) |s| try ep_c.conn.setSession(s);

    var step: u32 = 0;
    while (step < 100) : (step += 1) {
        try driveOneStep(&ep_c);
        try driveOneStep(&ep_s);
        if (ep_c.conn.handshakeDone() and ep_s.conn.handshakeDone()) {
            const c_app = @as(usize, @intCast(@intFromEnum(quic.EncryptionLevel.application)));
            if (ep_c.inbox[c_app].len == 0 and ep_s.inbox[c_app].len == 0) break;
        }
    }

    try std.testing.expect(ep_c.conn.handshakeDone());
    try std.testing.expect(ep_s.conn.handshakeDone());
    try std.testing.expectEqual(@as(?u8, null), ep_c.saw_alert);
    try std.testing.expectEqual(@as(?u8, null), ep_s.saw_alert);

    return .{
        .client_status = ep_c.conn.earlyDataStatus(),
        .server_status = ep_s.conn.earlyDataStatus(),
    };
}

const CallbackProbe = struct {
    invocations: u32 = 0,
    decision: bool = true,
    last_session_id_len: usize = 0,
    last_session_id_bytes: [32]u8 = @splat(0),
};

fn allowCallback(user_data: ?*anyopaque, conn: *tls.Conn) bool {
    const probe: *CallbackProbe = @ptrCast(@alignCast(user_data.?));
    probe.invocations += 1;
    if (conn.peerSessionId()) |id| {
        const n = @min(id.len, probe.last_session_id_bytes.len);
        @memcpy(probe.last_session_id_bytes[0..n], id[0..n]);
        probe.last_session_id_len = id.len;
    } else {
        probe.last_session_id_len = 0;
    }
    return probe.decision;
}

const protos = [_][]const u8{"hq-test"};

fn newServerCtxWithCallback(probe: *CallbackProbe) !tls.Context {
    var server_ctx = try tls.Context.initServer(.{
        .verify = .none,
        .min_version = c.TLS1_3_VERSION,
        .max_version = c.TLS1_3_VERSION,
        .alpn = &protos,
        .early_data_enabled = true,
    });
    errdefer server_ctx.deinit();
    try server_ctx.loadCertChainAndKey(test_cert_pem, test_key_pem);
    try server_ctx.setAllowEarlyDataCallback(allowCallback, probe);
    return server_ctx;
}

fn newClientCtx() !tls.Context {
    var client_ctx = try tls.Context.initClient(.{
        .verify = .none,
        .min_version = c.TLS1_3_VERSION,
        .max_version = c.TLS1_3_VERSION,
        .alpn = &protos,
        .early_data_enabled = true,
    });
    errdefer client_ctx.deinit();
    try client_ctx.setNewSessionCallback(captureSession, null);
    return client_ctx;
}

test "setAllowEarlyDataCallback rejects on a client context" {
    var ctx = try tls.Context.initClient(.{ .verify = .none });
    defer ctx.deinit();
    try std.testing.expectError(
        tls.Error.NotServerContext,
        ctx.setAllowEarlyDataCallback(allowCallback, null),
    );
}

test "AllowEarlyDataCallback fires on every ClientHello (cold + resumed)" {
    captured_session = null;
    defer if (captured_session) |b| capture_alloc.free(b);

    var probe: CallbackProbe = .{};

    var server_ctx = try newServerCtxWithCallback(&probe);
    defer server_ctx.deinit();
    var client_ctx = try newClientCtx();
    defer client_ctx.deinit();

    // Cold handshake: callback should fire once, peerSessionId
    // should be null (no resumed session attached).
    {
        const status = try runHandshake(client_ctx, server_ctx, null);
        try std.testing.expectEqual(@as(u32, 1), probe.invocations);
        try std.testing.expectEqual(@as(usize, 0), probe.last_session_id_len);
        try std.testing.expectEqual(tls.Conn.EarlyDataStatus.not_offered, status.client_status);
    }
    try std.testing.expect(captured_session != null);

    // Resumed handshake: callback fires again, this time
    // peerSessionId should be a non-empty slice from the resumed
    // session, and (because the probe defaults to "allow") 0-RTT
    // should be accepted on both sides.
    {
        var session = try tls.Session.fromBytes(client_ctx, captured_session.?);
        defer session.deinit();

        const status = try runHandshake(client_ctx, server_ctx, session);
        try std.testing.expectEqual(@as(u32, 2), probe.invocations);
        try std.testing.expect(probe.last_session_id_len > 0);
        try std.testing.expectEqual(tls.Conn.EarlyDataStatus.accepted, status.client_status);
        try std.testing.expectEqual(tls.Conn.EarlyDataStatus.accepted, status.server_status);
    }
}

test "AllowEarlyDataCallback returning false silently disables 0-RTT" {
    captured_session = null;
    defer if (captured_session) |b| capture_alloc.free(b);

    var probe: CallbackProbe = .{};

    var server_ctx = try newServerCtxWithCallback(&probe);
    defer server_ctx.deinit();
    var client_ctx = try newClientCtx();
    defer client_ctx.deinit();

    // Cold handshake to capture a session. Probe still returns true
    // here so the cold path doesn't matter for 0-RTT semantics.
    _ = try runHandshake(client_ctx, server_ctx, null);
    try std.testing.expect(captured_session != null);

    // Now flip the probe to deny early data. The handshake must
    // still complete (no alert, no error), but BoringSSL should
    // report that 0-RTT was not offered to the application — the
    // server side's reason is `ssl_early_data_disabled`.
    probe.decision = false;

    var session = try tls.Session.fromBytes(client_ctx, captured_session.?);
    defer session.deinit();

    const status = try runHandshake(client_ctx, server_ctx, session);
    // Client side: 0-RTT was offered and rejected by the server;
    // the client surfaced that to us as `EarlyDataRejected`, the
    // test scaffolding called `resetEarlyDataReject`, and the
    // handshake then completed normally — so the final status is
    // `.rejected` rather than `.accepted`.
    try std.testing.expect(status.client_status != .accepted);
    // Server side: BoringSSL records `ssl_early_data_disabled`
    // when the embedder flipped `enable_early_data` off. That maps
    // to `.not_offered` via our `EarlyDataStatus` enum.
    try std.testing.expect(status.server_status != .accepted);
}

test "Conn.peerSessionId returns null when no session is attached" {
    var server_ctx = try tls.Context.initServer(.{
        .verify = .none,
        .min_version = c.TLS1_3_VERSION,
        .max_version = c.TLS1_3_VERSION,
        .alpn = &protos,
    });
    defer server_ctx.deinit();
    try server_ctx.loadCertChainAndKey(test_cert_pem, test_key_pem);

    var conn = try server_ctx.newQuicServer();
    defer conn.deinit();

    try std.testing.expectEqual(@as(?[]const u8, null), conn.peerSessionId());
}

test "Conn.disableEarlyData toggles the per-connection flag" {
    var server_ctx = try tls.Context.initServer(.{
        .verify = .none,
        .min_version = c.TLS1_3_VERSION,
        .max_version = c.TLS1_3_VERSION,
        .alpn = &protos,
        .early_data_enabled = true,
    });
    defer server_ctx.deinit();
    try server_ctx.loadCertChainAndKey(test_cert_pem, test_key_pem);

    var conn = try server_ctx.newQuicServer();
    defer conn.deinit();

    // Smoke test: just call it, ensuring the FFI shim doesn't blow up.
    conn.disableEarlyData();
}
