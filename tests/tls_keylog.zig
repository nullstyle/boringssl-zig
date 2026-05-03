//! Smoke test for `Context.setKeylogCallback` (SSLKEYLOGFILE-style
//! debug output). Drive a real handshake with a callback installed
//! and verify it fires at least once with non-empty lines.

const std = @import("std");
const boringssl = @import("boringssl");
const tls = boringssl.tls;

const test_cert_pem = @embedFile("data/test_cert.pem");
const test_key_pem = @embedFile("data/test_key.pem");

var keylog_lines_seen: usize = 0;
var keylog_first_line_buf: [256]u8 = @splat(0);
var keylog_first_line_len: usize = 0;

fn onKeylog(line: []const u8) void {
    keylog_lines_seen += 1;
    if (keylog_first_line_len == 0 and line.len > 0 and line.len <= keylog_first_line_buf.len) {
        @memcpy(keylog_first_line_buf[0..line.len], line);
        keylog_first_line_len = line.len;
    }
}

test "keylog callback fires during a TLS 1.3 handshake" {
    keylog_lines_seen = 0;
    keylog_first_line_len = 0;

    const sp = try makeSocketpair();
    defer _ = closeFd(sp[0]);
    defer _ = closeFd(sp[1]);
    try setNonblock(sp[0]);
    try setNonblock(sp[1]);

    var server_ctx = try tls.Context.initServer(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
    });
    defer server_ctx.deinit();
    try server_ctx.loadCertChainAndKey(test_cert_pem, test_key_pem);
    try server_ctx.setKeylogCallback(onKeylog);

    var client_ctx = try tls.Context.initClient(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
    });
    defer client_ctx.deinit();
    try client_ctx.setKeylogCallback(onKeylog);

    var server_conn = try server_ctx.newServer(.{ .fd = sp[0] });
    defer server_conn.deinit();
    var client_conn = try client_ctx.newClient(.{ .hostname = "localhost", .fd = sp[1] });
    defer client_conn.deinit();

    var step: u32 = 0;
    while (step < 200) : (step += 1) {
        const c_done = client_conn.handshakeDone();
        const s_done = server_conn.handshakeDone();
        if (c_done and s_done) break;
        if (!c_done) {
            client_conn.handshake() catch |e| switch (e) {
                error.WantRead, error.WantWrite => {},
                else => return e,
            };
        }
        if (!s_done) {
            server_conn.handshake() catch |e| switch (e) {
                error.WantRead, error.WantWrite => {},
                else => return e,
            };
        }
    }

    try std.testing.expect(client_conn.handshakeDone());
    try std.testing.expect(server_conn.handshakeDone());

    // Each side fires the callback for each derived secret. TLS 1.3
    // exposes at least CLIENT_HANDSHAKE_TRAFFIC_SECRET,
    // SERVER_HANDSHAKE_TRAFFIC_SECRET, CLIENT_TRAFFIC_SECRET_0,
    // SERVER_TRAFFIC_SECRET_0, EXPORTER_SECRET (5 each side, ish).
    try std.testing.expect(keylog_lines_seen > 0);

    // Lines should look like Wireshark expects: an SSLKEYLOGFILE
    // entry begins with a known label like "CLIENT_HANDSHAKE_..."
    // or "CLIENT_TRAFFIC_SECRET_..." or "SERVER_..." or "EXPORTER_...".
    const first = keylog_first_line_buf[0..keylog_first_line_len];
    const has_known_prefix =
        std.mem.startsWith(u8, first, "CLIENT_") or
        std.mem.startsWith(u8, first, "SERVER_") or
        std.mem.startsWith(u8, first, "EXPORTER_") or
        std.mem.startsWith(u8, first, "EARLY_");
    try std.testing.expect(has_known_prefix);
}

extern "c" fn socketpair(domain: c_int, sock_type: c_int, protocol: c_int, fds: *[2]c_int) c_int;
extern "c" fn fcntl(fd: c_int, cmd: c_int, ...) c_int;
extern "c" fn close(fd: c_int) c_int;

const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const O_NONBLOCK: c_int = if (@import("builtin").os.tag == .macos) 0o4 else 0o4000;

fn makeSocketpair() ![2]c_int {
    var fds: [2]c_int = undefined;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) != 0) return error.SocketpairFailed;
    return fds;
}

fn closeFd(fd: c_int) c_int {
    return close(fd);
}

fn setNonblock(fd: c_int) !void {
    const flags = fcntl(fd, F_GETFL);
    if (flags < 0) return error.FcntlFailed;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return error.FcntlFailed;
}
