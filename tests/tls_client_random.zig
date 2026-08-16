//! SSL_get_client_random binding: after a minimal in-process
//! handshake, both endpoints must report the same 32-byte RFC 8446
//! client_random (the client generated it into its ClientHello; the
//! server parsed it back out of the same flight).

const std = @import("std");
const boringssl = @import("boringssl");
const tls = boringssl.tls;

const test_cert_pem = @embedFile("data/test_cert.pem");
const test_key_pem = @embedFile("data/test_key.pem");

test "getClientRandom: client and server agree on the 32-byte ClientHello random" {
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
    var server_conn = try server_ctx.newServer(.{ .fd = sp[0] });
    defer server_conn.deinit();

    var client_ctx = try tls.Context.initClient(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
    });
    defer client_ctx.deinit();
    var client_conn = try client_ctx.newClient(.{
        .hostname = "localhost",
        .fd = sp[1],
    });
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

    const client_random = try client_conn.getClientRandom();
    const server_random = try server_conn.getClientRandom();
    try std.testing.expectEqualSlices(u8, &client_random, &server_random);

    // The value must be freshly generated, not the zero-initialized
    // placeholder BoringSSL keeps before a ClientHello exists — an
    // all-zero "random" would make the whole TLS 1.3 transcript
    // forgeable, and this binding's whole point is the real bytes.
    var any_nonzero = false;
    for (client_random) |b| {
        if (b != 0) any_nonzero = true;
    }
    try std.testing.expect(any_nonzero);
}

// libc bindings: Zig 0.16's std.posix has been trimmed to a minimal
// surface, and these test helpers are simpler with direct extern decls.
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
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) != 0) {
        return error.SocketpairFailed;
    }
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
