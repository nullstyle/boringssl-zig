//! Server-side TLS tests: cert/key loading, in-process handshake
//! over a socket pair, ALPN negotiation.

const std = @import("std");
const boringssl = @import("boringssl");
const tls = boringssl.tls;

const test_cert_pem = @embedFile("data/test_cert.pem");
const test_key_pem = @embedFile("data/test_key.pem");

test "server context loads PEM cert + key" {
    var ctx = try tls.Context.initServer(.{ .verify = .none });
    defer ctx.deinit();
    try ctx.loadCertChainAndKey(test_cert_pem, test_key_pem);
}

test "TLS 1.3 handshake over socketpair with ALPN selection" {
    const sp = try makeSocketpair();
    defer _ = closeFd(sp[0]);
    defer _ = closeFd(sp[1]);

    try setNonblock(sp[0]);
    try setNonblock(sp[1]);

    const server_protos = [_][]const u8{"h3"};
    var server_ctx = try tls.Context.initServer(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &server_protos,
    });
    defer server_ctx.deinit();
    try server_ctx.loadCertChainAndKey(test_cert_pem, test_key_pem);
    var server_conn = try server_ctx.newServer(.{ .fd = sp[0] });
    defer server_conn.deinit();

    const client_protos = [_][]const u8{ "h3", "h2" };
    var client_ctx = try tls.Context.initClient(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &client_protos,
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

    const client_alpn = client_conn.alpnSelected() orelse
        return error.NoAlpnNegotiated;
    const server_alpn = server_conn.alpnSelected() orelse
        return error.NoAlpnNegotiated;
    try std.testing.expectEqualSlices(u8, "h3", client_alpn);
    try std.testing.expectEqualSlices(u8, "h3", server_alpn);

    try std.testing.expectEqualStrings("TLSv1.3", client_conn.protocolVersion());
    try std.testing.expectEqualStrings("TLSv1.3", server_conn.protocolVersion());
}

test "TLS handshake fails when ALPN doesn't overlap" {
    const sp = try makeSocketpair();
    defer _ = closeFd(sp[0]);
    defer _ = closeFd(sp[1]);
    try setNonblock(sp[0]);
    try setNonblock(sp[1]);

    const server_protos = [_][]const u8{"h3"};
    var server_ctx = try tls.Context.initServer(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &server_protos,
    });
    defer server_ctx.deinit();
    try server_ctx.loadCertChainAndKey(test_cert_pem, test_key_pem);
    var server_conn = try server_ctx.newServer(.{ .fd = sp[0] });
    defer server_conn.deinit();

    // Client only offers a protocol the server doesn't list.
    const client_protos = [_][]const u8{"http/1.1"};
    var client_ctx = try tls.Context.initClient(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &client_protos,
    });
    defer client_ctx.deinit();
    var client_conn = try client_ctx.newClient(.{
        .hostname = "localhost",
        .fd = sp[1],
    });
    defer client_conn.deinit();

    var step: u32 = 0;
    var saw_handshake_failure = false;
    while (step < 200) : (step += 1) {
        const c_done = client_conn.handshakeDone();
        const s_done = server_conn.handshakeDone();
        if (c_done and s_done) break;

        if (!c_done) {
            client_conn.handshake() catch |e| switch (e) {
                error.WantRead, error.WantWrite => {},
                error.HandshakeFailed, error.SyscallError => {
                    saw_handshake_failure = true;
                    break;
                },
                else => return e,
            };
        }
        if (!s_done) {
            server_conn.handshake() catch |e| switch (e) {
                error.WantRead, error.WantWrite => {},
                error.HandshakeFailed, error.SyscallError => {
                    saw_handshake_failure = true;
                    break;
                },
                else => return e,
            };
        }
    }

    try std.testing.expect(saw_handshake_failure);
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
