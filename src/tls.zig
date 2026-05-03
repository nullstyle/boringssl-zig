//! Minimal TLS client wrapper. Decouples from socket I/O — pass a raw fd.
//!
//! This is Phase 1 surface: enough to do an HTTPS GET against a real host
//! with hostname verification and a CA bundle. Server mode and async
//! integrations land later.

const std = @import("std");
const c = @import("c");

pub const Error = error{
    OutOfMemory,
    SslCtxAllocFailed,
    SslAllocFailed,
    SslSetFdFailed,
    SslSetHostnameFailed,
    DefaultVerifyPathsFailed,
    LoadCAFileFailed,
    LoadCADirFailed,
    HostnameTooLong,
    HandshakeFailed,
    ReadFailed,
    WriteFailed,
    WantRead,
    WantWrite,
    ConnectionClosed,
    SyscallError,
};

pub const VerifyMode = union(enum) {
    /// Disable certificate verification. Insecure; for tests only.
    none,
    /// Use BoringSSL's compiled-in default CA bundle path
    /// (typically `$SSL_CERT_FILE` if set, otherwise the build-time default).
    system,
    /// Load a single PEM file containing trusted root certificates.
    ca_file: [:0]const u8,
    /// Load a directory of hashed CA certificates.
    ca_dir: [:0]const u8,
};

pub const ContextOptions = struct {
    verify: VerifyMode = .system,
    /// TLS minimum version. Defaults to TLS 1.2.
    min_version: u16 = c.TLS1_2_VERSION,
    /// TLS maximum version. 0 means library default (TLS 1.3).
    max_version: u16 = 0,
};

pub const Context = struct {
    inner: *c.SSL_CTX,

    pub fn initClient(options: ContextOptions) Error!Context {
        const method = c.zbssl_TLS_client_method();
        const ctx = c.zbssl_SSL_CTX_new(method) orelse return Error.SslCtxAllocFailed;
        errdefer c.zbssl_SSL_CTX_free(ctx);

        if (c.zbssl_SSL_CTX_set_min_proto_version(ctx, options.min_version) != 1) {
            return Error.SslCtxAllocFailed;
        }
        if (options.max_version != 0) {
            _ = c.zbssl_SSL_CTX_set_max_proto_version(ctx, options.max_version);
        }

        switch (options.verify) {
            .none => {
                c.zbssl_SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);
            },
            .system => {
                c.zbssl_SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
                if (c.zbssl_SSL_CTX_set_default_verify_paths(ctx) != 1) {
                    return Error.DefaultVerifyPathsFailed;
                }
            },
            .ca_file => |path| {
                c.zbssl_SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
                if (c.zbssl_SSL_CTX_load_verify_locations(ctx, path.ptr, null) != 1) {
                    return Error.LoadCAFileFailed;
                }
            },
            .ca_dir => |path| {
                c.zbssl_SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
                if (c.zbssl_SSL_CTX_load_verify_locations(ctx, null, path.ptr) != 1) {
                    return Error.LoadCADirFailed;
                }
            },
        }

        return .{ .inner = ctx };
    }

    pub fn deinit(self: *Context) void {
        c.zbssl_SSL_CTX_free(self.inner);
        self.inner = undefined;
    }

    pub const ConnOptions = struct {
        /// Hostname for SNI and certificate verification. Must be NUL-terminated.
        hostname: [:0]const u8,
        /// Connected socket file descriptor. The Conn does not take ownership
        /// of the fd; the caller closes it after Conn.deinit().
        fd: c_int,
    };

    pub fn newClient(self: Context, options: ConnOptions) Error!Conn {
        const ssl = c.zbssl_SSL_new(self.inner) orelse return Error.SslAllocFailed;
        errdefer c.zbssl_SSL_free(ssl);

        // SNI: server name in ClientHello.
        if (c.zbssl_SSL_set_tlsext_host_name(ssl, options.hostname.ptr) != 1) {
            return Error.SslSetHostnameFailed;
        }

        // Hostname pinning: verify the cert's SAN matches.
        const param = c.zbssl_SSL_get0_param(ssl);
        _ = c.zbssl_X509_VERIFY_PARAM_set1_host(param, options.hostname.ptr, options.hostname.len);

        if (c.zbssl_SSL_set_fd(ssl, options.fd) != 1) {
            return Error.SslSetFdFailed;
        }

        return .{ .inner = ssl };
    }
};

pub const Conn = struct {
    inner: *c.SSL,

    pub fn deinit(self: *Conn) void {
        c.zbssl_SSL_free(self.inner);
        self.inner = undefined;
    }

    pub fn handshake(self: *Conn) Error!void {
        const ret = c.zbssl_SSL_connect(self.inner);
        if (ret != 1) return mapSslError(self.inner, ret, Error.HandshakeFailed);
    }

    pub fn read(self: *Conn, buffer: []u8) Error!usize {
        if (buffer.len == 0) return 0;
        const ret = c.zbssl_SSL_read(self.inner, buffer.ptr, @intCast(buffer.len));
        if (ret <= 0) return mapSslError(self.inner, ret, Error.ReadFailed);
        return @intCast(ret);
    }

    pub fn write(self: *Conn, data: []const u8) Error!usize {
        if (data.len == 0) return 0;
        const ret = c.zbssl_SSL_write(self.inner, data.ptr, @intCast(data.len));
        if (ret <= 0) return mapSslError(self.inner, ret, Error.WriteFailed);
        return @intCast(ret);
    }

    /// Repeated SSL_write until all data is sent. Returns on first error.
    pub fn writeAll(self: *Conn, data: []const u8) Error!void {
        var rest: []const u8 = data;
        while (rest.len > 0) {
            const n = try self.write(rest);
            rest = rest[n..];
        }
    }

    /// Initiate a clean shutdown. May need to be called twice for a full
    /// bidirectional close; the first call sends close_notify, the second
    /// waits for the peer's. Returns 0 on first phase, 1 on full close.
    pub fn shutdown(self: *Conn) Error!u8 {
        const ret = c.zbssl_SSL_shutdown(self.inner);
        if (ret < 0) return mapSslError(self.inner, ret, Error.WriteFailed);
        return @intCast(ret);
    }

    pub fn cipherName(self: *Conn) []const u8 {
        const cipher = c.zbssl_SSL_get_current_cipher(self.inner) orelse return "(none)";
        const name = c.zbssl_SSL_CIPHER_get_name(cipher) orelse return "(unknown)";
        return std.mem.sliceTo(name, 0);
    }

    pub fn protocolVersion(self: *Conn) []const u8 {
        const version = c.zbssl_SSL_get_version(self.inner) orelse return "(unknown)";
        return std.mem.sliceTo(version, 0);
    }
};

fn mapSslError(ssl: *c.SSL, ret: c_int, default: Error) Error {
    const err_code = c.zbssl_SSL_get_error(ssl, ret);
    return switch (err_code) {
        c.SSL_ERROR_WANT_READ => Error.WantRead,
        c.SSL_ERROR_WANT_WRITE => Error.WantWrite,
        c.SSL_ERROR_ZERO_RETURN => Error.ConnectionClosed,
        c.SSL_ERROR_SYSCALL => Error.SyscallError,
        else => default,
    };
}
