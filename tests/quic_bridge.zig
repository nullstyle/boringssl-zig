//! End-to-end QUIC TLS handshake driven entirely through
//! `tls.quic.Method` callbacks — no UDP, no QUIC packet protection,
//! just two `tls.Conn`s exchanging CRYPTO bytes via Zig functions.
//!
//! This is the v0.4.0 acceptance test for the QUIC bridge: if it
//! passes, the SSL_QUIC_METHOD ABI shim is wired correctly and a
//! downstream QUIC stack (e.g. quic_zig) can drive a real handshake.

const std = @import("std");
const boringssl = @import("boringssl");
const tls = boringssl.tls;
const quic = tls.quic;
const c = boringssl.raw;

const test_cert_pem = @embedFile("data/test_cert.pem");
const test_key_pem = @embedFile("data/test_key.pem");

const Endpoint = struct {
    conn: tls.Conn,
    /// One pending-bytes slot per encryption level, queued by the
    /// peer's `add_handshake_data` callback for us to feed back
    /// through `provideQuicData`.
    inbox: [4]Inbox = .{ .{}, .{}, .{}, .{} },
    /// Mirror of which encryption levels we've installed
    /// read/write secrets for. Useful for asserting both sides
    /// reach `application` after handshake.
    have_read_secret: [4]bool = .{ false, false, false, false },
    have_write_secret: [4]bool = .{ false, false, false, false },
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
    _ = .{ cipher, secret, secret_len };
    const ep_raw = tls.Conn.userDataFromSsl(ssl.?) orelse return 0;
    const ep: *Endpoint = @ptrCast(@alignCast(ep_raw));
    const lvl = quic.EncryptionLevel.fromC(level);
    // We use the same callback for both read and write secrets here.
    // The test asserts on a "we got *some* secret for level X"
    // basis, which is enough to validate the bridge is wired.
    const idx = @as(usize, @intCast(@intFromEnum(lvl)));
    ep.have_read_secret[idx] = true;
    ep.have_write_secret[idx] = true;
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

fn flushFlight(ssl: ?*c.SSL) callconv(.c) c_int {
    _ = ssl;
    return 1;
}

fn sendAlert(
    ssl: ?*c.SSL,
    level: c.ssl_encryption_level_t,
    alert: u8,
) callconv(.c) c_int {
    _ = level;
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

test "QUIC TLS handshake completes through the Method bridge" {
    // Both sides need TLS 1.3 only and an ALPN list with overlap.
    const protos = [_][]const u8{"hq-test"};

    var server_ctx = try tls.Context.initServer(.{
        .verify = .none,
        .min_version = c.TLS1_3_VERSION,
        .max_version = c.TLS1_3_VERSION,
        .alpn = &protos,
    });
    defer server_ctx.deinit();
    try server_ctx.loadCertChainAndKey(test_cert_pem, test_key_pem);

    var client_ctx = try tls.Context.initClient(.{
        .verify = .none,
        .min_version = c.TLS1_3_VERSION,
        .max_version = c.TLS1_3_VERSION,
        .alpn = &protos,
    });
    defer client_ctx.deinit();

    var client_ep: Endpoint = .{ .conn = try client_ctx.newQuicClient() };
    defer client_ep.conn.deinit();

    var server_ep: Endpoint = .{ .conn = try server_ctx.newQuicServer() };
    defer server_ep.conn.deinit();

    client_ep.peer = &server_ep;
    server_ep.peer = &client_ep;

    // Pin the user-data pointer so callbacks can recover *Endpoint
    // from the *SSL handed to them.
    try client_ep.conn.setUserData(&client_ep);
    try server_ep.conn.setUserData(&server_ep);

    try client_ep.conn.setQuicMethod(&bridge_method);
    try server_ep.conn.setQuicMethod(&bridge_method);

    // Both sides need transport_parameters set before the handshake.
    // The actual bytes are opaque to the bridge — quic_zig encodes
    // RFC 9000 §18 form; here we just send a non-empty placeholder.
    const placeholder = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    try client_ep.conn.setQuicTransportParams(&placeholder);
    try server_ep.conn.setQuicTransportParams(&placeholder);

    try client_ep.conn.setHostname("localhost");

    // Confirm both SSLs are in QUIC mode.
    try std.testing.expect(client_ep.conn.isQuic());
    try std.testing.expect(server_ep.conn.isQuic());

    // Drive the handshake. The QUIC TLS state machine progresses
    // through encryption levels (initial → handshake → application);
    // we must provide bytes one level at a time and call
    // SSL_do_handshake between, since the keys for level N+1 are
    // derived during processing of level N.
    var step: u32 = 0;
    while (step < 50) : (step += 1) {
        if (client_ep.conn.handshakeDone() and server_ep.conn.handshakeDone()) break;

        try driveOneStep(&client_ep);
        try driveOneStep(&server_ep);
    }

    try std.testing.expect(client_ep.conn.handshakeDone());
    try std.testing.expect(server_ep.conn.handshakeDone());
    try std.testing.expectEqual(@as(?u8, null), client_ep.saw_alert);
    try std.testing.expectEqual(@as(?u8, null), server_ep.saw_alert);

    // After handshake, both sides should be at the application
    // encryption level for both reads and writes.
    try std.testing.expect(client_ep.have_read_secret[@intFromEnum(quic.EncryptionLevel.application)]);
    try std.testing.expect(client_ep.have_write_secret[@intFromEnum(quic.EncryptionLevel.application)]);
    try std.testing.expect(server_ep.have_read_secret[@intFromEnum(quic.EncryptionLevel.application)]);
    try std.testing.expect(server_ep.have_write_secret[@intFromEnum(quic.EncryptionLevel.application)]);

    // ALPN selection should match.
    const c_alpn = client_ep.conn.alpnSelected() orelse return error.NoAlpnSelected;
    const s_alpn = server_ep.conn.alpnSelected() orelse return error.NoAlpnSelected;
    try std.testing.expectEqualSlices(u8, "hq-test", c_alpn);
    try std.testing.expectEqualSlices(u8, "hq-test", s_alpn);

    // Each side sees the peer's transport_parameters bytes.
    const peer_params_at_client = client_ep.conn.peerQuicTransportParams() orelse
        return error.NoPeerTransportParams;
    const peer_params_at_server = server_ep.conn.peerQuicTransportParams() orelse
        return error.NoPeerTransportParams;
    try std.testing.expectEqualSlices(u8, &placeholder, peer_params_at_client);
    try std.testing.expectEqualSlices(u8, &placeholder, peer_params_at_server);
}

fn driveOneStep(ep: *Endpoint) !void {
    // For each encryption level (low to high), drain any queued
    // bytes from the peer, feed them in, and advance the handshake.
    // Then make a final handshake call in case there was nothing
    // queued but we still need to produce data.
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
            try advanceHandshake(ep);
        }
    }
    try advanceHandshake(ep);
}

fn advanceHandshake(ep: *Endpoint) !void {
    if (ep.conn.handshakeDone()) return;
    ep.conn.handshake() catch |e| switch (e) {
        error.WantRead, error.WantWrite => {},
        else => {
            var ebuf: [256]u8 = undefined;
            const err_code = c.zbssl_ERR_peek_last_error();
            _ = c.zbssl_ERR_error_string_n(err_code, &ebuf, ebuf.len);
            std.debug.print("handshake error: {} :: {s} (alert={?})\n", .{ e, std.mem.sliceTo(&ebuf, 0), ep.saw_alert });
            return e;
        },
    };
}
