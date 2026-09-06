//! Peer-identity accessors: `Conn.peerCertSpkiDigest` and the
//! `setSni` / `setHostname` identity-check split.
//!
//! The SPKI digest is pinned against a known-answer constant computed
//! OUTSIDE BoringSSL (`openssl x509 -pubkey | openssl pkey -pubin
//! -outform DER | openssl dgst -sha256` on the fixture) so a digest
//! preimage drift — the classic silent identity-break — fails here
//! instead of propagating into every embedder's peer-id database.

const std = @import("std");
const boringssl = @import("boringssl");
const tls = boringssl.tls;
const raw = boringssl.raw;

const test_cert_pem = @embedFile("data/test_cert.pem");
const test_key_pem = @embedFile("data/test_key.pem");

/// SHA-256 over the DER-encoded SubjectPublicKeyInfo of
/// tests/data/test_cert.pem, computed with the openssl CLI pipeline
/// documented in the module docstring.
const test_cert_spki_sha256 = [32]u8{
    0x5c, 0x8c, 0x38, 0xed, 0xce, 0xf0, 0x7e, 0xb8,
    0x0e, 0xb5, 0x28, 0x43, 0xfb, 0xf1, 0xa3, 0xf5,
    0xde, 0xb8, 0x98, 0x0b, 0x1b, 0xf7, 0x4f, 0x08,
    0x0b, 0x16, 0x81, 0xa1, 0x6e, 0x8c, 0x0d, 0xa9,
};

/// Drive a socketpair handshake until both sides report
/// `handshakeDone` (mirrors the pump loop in tls_server.zig). Returns
/// false if the step budget runs out; a handshake error is returned
/// via `saw_error` so rejection tests can share the helper.
fn pumpHandshake(
    client: *tls.Conn,
    server: *tls.Conn,
    saw_error: *bool,
) !bool {
    var step: u32 = 0;
    while (step < 200) : (step += 1) {
        const c_done = client.handshakeDone();
        const s_done = server.handshakeDone();
        if (c_done and s_done) return true;

        if (!c_done) {
            client.handshake() catch |e| switch (e) {
                error.WantRead, error.WantWrite => {},
                else => {
                    saw_error.* = true;
                    return false;
                },
            };
        }
        if (!s_done) {
            server.handshake() catch |e| switch (e) {
                error.WantRead, error.WantWrite => {},
                else => {
                    saw_error.* = true;
                    return false;
                },
            };
        }
    }
    return false;
}

test "peerCertSpkiDigest: KAT digest client-side, null server-side and pre-handshake" {
    const sp = try makeSocketpair();
    defer _ = closeFd(sp[0]);
    defer _ = closeFd(sp[1]);
    try setNonblock(sp[0]);
    try setNonblock(sp[1]);

    var server_ctx = try tls.Context.initServer(.{
        .verify = .none,
        .min_version = raw.TLS1_3_VERSION,
    });
    defer server_ctx.deinit();
    try server_ctx.loadCertChainAndKey(test_cert_pem, test_key_pem);
    var server_conn = try server_ctx.newServer(.{ .fd = sp[0] });
    defer server_conn.deinit();

    var client_ctx = try tls.Context.initClient(.{
        .verify = .none,
        .min_version = raw.TLS1_3_VERSION,
    });
    defer client_ctx.deinit();
    var client_conn = try client_ctx.newClient(.{
        .hostname = "localhost",
        .fd = sp[1],
    });
    defer client_conn.deinit();

    // Pre-handshake: no peer certificate exists on either side.
    try std.testing.expect(client_conn.peerCertSpkiDigest() == null);
    try std.testing.expect(server_conn.peerCertSpkiDigest() == null);

    var saw_error = false;
    try std.testing.expect(try pumpHandshake(&client_conn, &server_conn, &saw_error));

    // Client saw the server's certificate: digest must equal the
    // independently-computed SPKI SHA-256 of the fixture.
    const client_digest = client_conn.peerCertSpkiDigest() orelse
        return error.NoServerCertDigest;
    try std.testing.expectEqualSlices(u8, &test_cert_spki_sha256, &client_digest);

    // The client presented no certificate (verify = .none context,
    // no client identity installed), so the server side stays null.
    try std.testing.expect(server_conn.peerCertSpkiDigest() == null);
}

test "setSni skips the name check while chain verification stays mandatory" {
    // A name that is NOT in the fixture's SAN (localhost/127.0.0.1):
    // with setHostname the pinned-anchor handshake must fail on the
    // identity check; with setSni it must complete on chain trust.
    const mismatched = "not-the-san.example";

    // -- control: setHostname (SNI + identity binding) rejects ----
    {
        const sp = try makeSocketpair();
        defer _ = closeFd(sp[0]);
        defer _ = closeFd(sp[1]);
        try setNonblock(sp[0]);
        try setNonblock(sp[1]);

        var server_ctx = try tls.Context.initServer(.{
            .verify = .none,
            .min_version = raw.TLS1_3_VERSION,
        });
        defer server_ctx.deinit();
        try server_ctx.loadCertChainAndKey(test_cert_pem, test_key_pem);
        var server_conn = try server_ctx.newServer(.{ .fd = sp[0] });
        defer server_conn.deinit();

        var client_ctx = try tls.Context.initClient(.{
            .verify = .none,
            .min_version = raw.TLS1_3_VERSION,
        });
        defer client_ctx.deinit();
        try pinRootCa(client_ctx, test_cert_pem);
        var client_conn = try clientConnOnFd(client_ctx, sp[1]);
        defer client_conn.deinit();
        try client_conn.setHostname(mismatched);

        var saw_error = false;
        _ = try pumpHandshake(&client_conn, &server_conn, &saw_error);
        try std.testing.expect(saw_error);
    }

    // -- setSni: same pinned anchor, same mismatched name, completes
    {
        const sp = try makeSocketpair();
        defer _ = closeFd(sp[0]);
        defer _ = closeFd(sp[1]);
        try setNonblock(sp[0]);
        try setNonblock(sp[1]);

        var server_ctx = try tls.Context.initServer(.{
            .verify = .none,
            .min_version = raw.TLS1_3_VERSION,
        });
        defer server_ctx.deinit();
        try server_ctx.loadCertChainAndKey(test_cert_pem, test_key_pem);
        var server_conn = try server_ctx.newServer(.{ .fd = sp[0] });
        defer server_conn.deinit();

        var client_ctx = try tls.Context.initClient(.{
            .verify = .none,
            .min_version = raw.TLS1_3_VERSION,
        });
        defer client_ctx.deinit();
        try pinRootCa(client_ctx, test_cert_pem);
        var client_conn = try clientConnOnFd(client_ctx, sp[1]);
        defer client_conn.deinit();
        try client_conn.setSni(mismatched);

        var saw_error = false;
        try std.testing.expect(try pumpHandshake(&client_conn, &server_conn, &saw_error));
        try std.testing.expect(!saw_error);

        // Chain still validated against the pinned anchor, and the
        // digest accessor agrees with the KAT on this posture too.
        const digest = client_conn.peerCertSpkiDigest() orelse
            return error.NoServerCertDigest;
        try std.testing.expectEqualSlices(u8, &test_cert_spki_sha256, &digest);
    }
}

test "setSni posture still rejects a chain that misses the pinned anchor" {
    // Proves setSni decouples ONLY the name check: swap the server's
    // key (same profile, different key) and the pinned-anchor client
    // must refuse even with the name check off.
    const untrusted_cert_pem = @embedFile("data/test_untrusted_cert.pem");
    const untrusted_key_pem = @embedFile("data/test_untrusted_key.pem");

    const sp = try makeSocketpair();
    defer _ = closeFd(sp[0]);
    defer _ = closeFd(sp[1]);
    try setNonblock(sp[0]);
    try setNonblock(sp[1]);

    var server_ctx = try tls.Context.initServer(.{
        .verify = .none,
        .min_version = raw.TLS1_3_VERSION,
    });
    defer server_ctx.deinit();
    try server_ctx.loadCertChainAndKey(untrusted_cert_pem, untrusted_key_pem);
    var server_conn = try server_ctx.newServer(.{ .fd = sp[0] });
    defer server_conn.deinit();

    var client_ctx = try tls.Context.initClient(.{
        .verify = .none,
        .min_version = raw.TLS1_3_VERSION,
    });
    defer client_ctx.deinit();
    try pinRootCa(client_ctx, test_cert_pem);
    var client_conn = try clientConnOnFd(client_ctx, sp[1]);
    defer client_conn.deinit();
    try client_conn.setSni("localhost");

    var saw_error = false;
    _ = try pumpHandshake(&client_conn, &server_conn, &saw_error);
    try std.testing.expect(saw_error);
}

/// Build a client `tls.Conn` on a raw fd with NO hostname installed —
/// neither SNI nor the identity binding. `Context.newClient` always
/// applies both via setHostname; these tests need to choose the
/// posture themselves (setHostname vs setSni) after construction, so
/// they replicate the SSL_new / connect-state / set_fd sequence the
/// wrapper's own `newClient` performs, minus the hostname steps.
fn clientConnOnFd(ctx: tls.Context, fd: c_int) !tls.Conn {
    const ssl = raw.zbssl_SSL_new(ctx.inner) orelse return error.SslAllocFailed;
    errdefer raw.zbssl_SSL_free(ssl);
    raw.zbssl_SSL_set_connect_state(ssl);
    if (raw.zbssl_SSL_set_fd(ssl, fd) != 1) return error.SslSetFdFailed;
    return .{ .inner = ssl };
}

/// Parse one PEM certificate from memory and pin it as the ONLY trust
/// anchor of `ctx`, flipping the context to SSL_VERIFY_PEER. Mirrors
/// quic-zig's tls.pem.installTrustAnchors for the two-posture tests.
fn pinRootCa(ctx: tls.Context, ca_pem: []const u8) !void {
    const store = raw.zbssl_SSL_CTX_get_cert_store(ctx.inner) orelse
        return error.StoreUnavailable;
    const bio = raw.zbssl_BIO_new_mem_buf(ca_pem.ptr, @intCast(ca_pem.len)) orelse
        return error.Oom;
    defer _ = raw.zbssl_BIO_free(bio);
    const cert = raw.zbssl_PEM_read_bio_X509(bio, null, null, null) orelse
        return error.InvalidPem;
    defer raw.zbssl_X509_free(cert);
    if (raw.zbssl_X509_STORE_add_cert(store, cert) != 1) return error.AddFailed;
    raw.zbssl_SSL_CTX_set_verify(ctx.inner, raw.SSL_VERIFY_PEER, null);
}

// libc bindings: direct extern decls keep the helpers free of
// std.posix surface churn (house style from tls_server.zig).
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
