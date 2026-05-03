//! QUIC TLS bridge — types and helpers that consumers of
//! `boringssl.tls` use when running BoringSSL's TLS 1.3 stack as a
//! handshake driver for QUIC (RFC 9001).
//!
//! The actual installation of a `Method` and the `provideQuicData` /
//! `processQuicPostHandshake` calls live as methods on `tls.Conn`;
//! this module just exposes the types that those methods take.

const std = @import("std");
const c = @import("c");

/// QUIC encryption levels. Mirrors BoringSSL's `ssl_encryption_level_t`
/// (RFC 9001 §5).
pub const EncryptionLevel = enum(c_int) {
    initial = 0,
    early_data = 1,
    handshake = 2,
    application = 3,

    pub fn fromC(level: c.ssl_encryption_level_t) EncryptionLevel {
        return @enumFromInt(@as(c_int, @intCast(level)));
    }

    pub fn toC(self: EncryptionLevel) c.ssl_encryption_level_t {
        return @intCast(@intFromEnum(self));
    }
};

/// QUIC TLS callback table — ABI-compatible with BoringSSL's
/// `SSL_QUIC_METHOD` struct. Consumers fill this in with C-callable
/// Zig functions and pass it to `Conn.setQuicMethod`. All five
/// fields must be non-null.
///
/// Each callback returns 1 on success and 0 on failure. When a
/// callback returns 0, BoringSSL aborts the handshake; the QUIC
/// implementation should also tear down the connection.
///
/// Use `tls.Conn.userDataFromSsl(ssl)` from inside a callback to
/// retrieve the `*Connection` (or whatever opaque pointer the
/// consumer has stashed) belonging to this SSL.
pub const Method = extern struct {
    /// Install a read-side traffic secret for `level`.
    set_read_secret: ?*const fn (
        ssl: ?*c.SSL,
        level: c.ssl_encryption_level_t,
        cipher: ?*const c.SSL_CIPHER,
        secret: [*c]const u8,
        secret_len: usize,
    ) callconv(.c) c_int,

    /// Install a write-side traffic secret for `level`.
    set_write_secret: ?*const fn (
        ssl: ?*c.SSL,
        level: c.ssl_encryption_level_t,
        cipher: ?*const c.SSL_CIPHER,
        secret: [*c]const u8,
        secret_len: usize,
    ) callconv(.c) c_int,

    /// BoringSSL has produced outgoing handshake bytes at `level`
    /// (CRYPTO frame payload). The QUIC stack should buffer them
    /// for transmission; subsequent calls may extend the same
    /// flight at the same level.
    add_handshake_data: ?*const fn (
        ssl: ?*c.SSL,
        level: c.ssl_encryption_level_t,
        data: [*c]const u8,
        len: usize,
    ) callconv(.c) c_int,

    /// Marks the end of the current handshake flight: the QUIC
    /// stack may now coalesce buffered data into packets and send.
    flush_flight: ?*const fn (ssl: ?*c.SSL) callconv(.c) c_int,

    /// BoringSSL wants to send a TLS alert at `level`. The QUIC
    /// stack should close the connection with the appropriate
    /// CONNECTION_CLOSE error (RFC 9001 §4.8: error code = 0x100 +
    /// alert).
    send_alert: ?*const fn (
        ssl: ?*c.SSL,
        level: c.ssl_encryption_level_t,
        alert: u8,
    ) callconv(.c) c_int,
};

comptime {
    // Sanity-check that our extern struct matches BoringSSL's at
    // compile time. If translate-c output for SSL_QUIC_METHOD ever
    // shifts (e.g. fields reordered, a new field added), this will
    // catch it.
    if (@sizeOf(Method) != @sizeOf(c.SSL_QUIC_METHOD)) {
        @compileError("Method size != SSL_QUIC_METHOD size; ABI mismatch");
    }
}

test "EncryptionLevel maps to / from C round-trip" {
    const std_t = std.testing;
    inline for (.{ EncryptionLevel.initial, .early_data, .handshake, .application }) |lvl| {
        try std_t.expectEqual(lvl, EncryptionLevel.fromC(lvl.toC()));
    }
}

test "Method has the same size as SSL_QUIC_METHOD" {
    try std.testing.expectEqual(@sizeOf(c.SSL_QUIC_METHOD), @sizeOf(Method));
}
