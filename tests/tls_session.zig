//! Session resumption + 0-RTT round-trip through the QUIC bridge.
//!
//! This is the v0.4.0 acceptance test:
//!   1. First handshake completes; the client captures the
//!      NewSessionTicket via `setNewSessionCallback` and serializes
//!      the session via `Session.toBytes`.
//!   2. A second handshake on a fresh `Conn` calls `setSession`
//!      with the saved bytes and `setEarlyDataEnabled(true)`.
//!   3. Both sides report `earlyDataStatus() == .accepted`.

const std = @import("std");
const boringssl = @import("boringssl");
const tls = boringssl.tls;
const quic = tls.quic;
const c = boringssl.raw;

const test_cert_pem = @embedFile("data/test_cert.pem");
const test_key_pem = @embedFile("data/test_key.pem");

// Captured by the new-session callback. Reset at the start of each
// test so multi-test runs don't see stale state.
var captured: ?[]u8 = null;
const capture_alloc = std.testing.allocator;

fn captureSession(_: ?*anyopaque, session_in: tls.Session) void {
    var s = session_in;
    defer s.deinit();
    if (captured != null) return; // already have one; ignore extras
    captured = s.toBytes(capture_alloc) catch null;
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
                // Post-handshake bytes (e.g. NewSessionTicket).
                try ep.conn.processQuicPostHandshake();
            } else {
                try advanceHandshake(ep);
            }
        }
    }
    if (!ep.conn.handshakeDone()) try advanceHandshake(ep);
}

const Phase = enum { fresh, resumed };

fn runHandshake(
    client_ctx: tls.Context,
    server_ctx: tls.Context,
    session: ?tls.Session,
) !struct {
    client_status: tls.Conn.EarlyDataStatus,
    server_status: tls.Conn.EarlyDataStatus,
} {
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

    // Server-side 0-RTT replay context. Required for the server to
    // accept early data.
    const early_ctx = [_]u8{ 0x42, 0x42, 0x42, 0x42 };
    try ep_s.conn.setQuicEarlyDataContext(&early_ctx);

    try ep_c.conn.setHostname("localhost");

    if (session) |s| try ep_c.conn.setSession(s);

    var step: u32 = 0;
    while (step < 100) : (step += 1) {
        try driveOneStep(&ep_c);
        try driveOneStep(&ep_s);
        // Stop when both handshakes are done AND no more pending
        // post-handshake bytes are queued (the NST flight from the
        // server can take an extra step to drain).
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

test "Session.toBytes / fromBytes round-trip preserves session contents" {
    captured = null;
    defer if (captured) |b| capture_alloc.free(b);

    const protos = [_][]const u8{"hq-test"};

    var server_ctx = try tls.Context.initServer(.{
        .verify = .none,
        .min_version = c.TLS1_3_VERSION,
        .max_version = c.TLS1_3_VERSION,
        .alpn = &protos,
        .early_data_enabled = true,
    });
    defer server_ctx.deinit();
    try server_ctx.loadCertChainAndKey(test_cert_pem, test_key_pem);

    var client_ctx = try tls.Context.initClient(.{
        .verify = .none,
        .min_version = c.TLS1_3_VERSION,
        .max_version = c.TLS1_3_VERSION,
        .alpn = &protos,
        .early_data_enabled = true,
    });
    defer client_ctx.deinit();
    try client_ctx.setNewSessionCallback(captureSession, null);

    _ = try runHandshake(client_ctx, server_ctx, null);

    try std.testing.expect(captured != null);

    // Round-trip: fromBytes the bytes, then toBytes again, compare.
    var s1 = try tls.Session.fromBytes(client_ctx, captured.?);
    defer s1.deinit();
    const round_trip_bytes = try s1.toBytes(capture_alloc);
    defer capture_alloc.free(round_trip_bytes);
    try std.testing.expectEqualSlices(u8, captured.?, round_trip_bytes);
}

test "QUIC 0-RTT round-trip via Session resumption" {
    captured = null;
    defer if (captured) |b| capture_alloc.free(b);

    const protos = [_][]const u8{"hq-test"};

    var server_ctx = try tls.Context.initServer(.{
        .verify = .none,
        .min_version = c.TLS1_3_VERSION,
        .max_version = c.TLS1_3_VERSION,
        .alpn = &protos,
        .early_data_enabled = true,
    });
    defer server_ctx.deinit();
    try server_ctx.loadCertChainAndKey(test_cert_pem, test_key_pem);

    var client_ctx = try tls.Context.initClient(.{
        .verify = .none,
        .min_version = c.TLS1_3_VERSION,
        .max_version = c.TLS1_3_VERSION,
        .alpn = &protos,
        .early_data_enabled = true,
    });
    defer client_ctx.deinit();
    try client_ctx.setNewSessionCallback(captureSession, null);

    // Phase 1: cold handshake; capture the session.
    {
        const status = try runHandshake(client_ctx, server_ctx, null);
        // Cold handshake — nothing was offered.
        try std.testing.expectEqual(tls.Conn.EarlyDataStatus.not_offered, status.client_status);
    }
    try std.testing.expect(captured != null);

    // Phase 2: resume with the captured session and assert 0-RTT
    // accepted on both sides.
    {
        var session = try tls.Session.fromBytes(client_ctx, captured.?);
        defer session.deinit();

        const status = try runHandshake(client_ctx, server_ctx, session);
        try std.testing.expectEqual(tls.Conn.EarlyDataStatus.accepted, status.client_status);
        try std.testing.expectEqual(tls.Conn.EarlyDataStatus.accepted, status.server_status);
    }
}
