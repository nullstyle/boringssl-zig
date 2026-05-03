//! TLS 1.3 wrapper around BoringSSL — client + server, with ALPN
//! negotiation, certificate/key loading, and the QUIC TLS bridge
//! (see the `quic` sub-module).
//!
//! The `Conn` type is fd-based for plain TLS use and fd-less for
//! QUIC use. In QUIC mode the caller drives the handshake by calling
//! `provideQuicData` with bytes from CRYPTO frames and reading
//! out-going handshake bytes via the `Method` callbacks installed
//! through `setQuicMethod`.

const std = @import("std");
const c = @import("c");

pub const quic = @import("tls_quic.zig");

const c_alloc = std.heap.c_allocator;

pub const Error = error{
    OutOfMemory,
    SslCtxAllocFailed,
    SslAllocFailed,
    SslSetFdFailed,
    SslSetHostnameFailed,
    DefaultVerifyPathsFailed,
    LoadCAFileFailed,
    LoadCADirFailed,
    HandshakeFailed,
    ReadFailed,
    WriteFailed,
    WantRead,
    WantWrite,
    ConnectionClosed,
    SyscallError,
    AlpnTooLong,
    AlpnInvalid,
    AlpnSetFailed,
    InvalidPem,
    KeyMismatch,
    UseCertFailed,
    UsePrivateKeyFailed,
    QuicSetupFailed,
    QuicProvideDataFailed,
    QuicTransportParamsFailed,
    QuicEarlyDataContextFailed,
    NotServerContext,
    NotClientContext,
    SessionSerializeFailed,
    SessionParseFailed,
    SetSessionFailed,
    KeylogSetupFailed,
};

pub const Mode = enum { client, server };

pub const VerifyMode = union(enum) {
    /// Disable certificate verification. Insecure; for tests only.
    none,
    /// Use BoringSSL's compiled-in default CA bundle path.
    system,
    /// Load a single PEM file containing trusted root certificates.
    ca_file: [:0]const u8,
    /// Load a directory of hashed CA certificates.
    ca_dir: [:0]const u8,
};

pub const ContextOptions = struct {
    verify: VerifyMode = .system,
    /// Minimum TLS version. Defaults to TLS 1.2.
    min_version: u16 = c.TLS1_2_VERSION,
    /// Maximum TLS version. 0 = library default (TLS 1.3).
    max_version: u16 = 0,
    /// ALPN protocol list, ordered by preference. Each entry is the
    /// wire identifier (no length prefix), e.g. "h3" or "hq-interop".
    /// Empty disables ALPN. Each protocol must be 1..255 bytes.
    ///
    /// On the client, this list is sent in ClientHello. On the
    /// server, the first server-listed protocol that the client
    /// also offers is selected; if there's no overlap, the
    /// handshake fails with no_application_protocol.
    alpn: []const []const u8 = &.{},

    /// Enable 0-RTT (early data) support on this context. On a
    /// client, allows resumed connections to send early data; on a
    /// server, allows accepting early data from clients that bring
    /// a valid session ticket. Default false because 0-RTT has
    /// replay-safety implications the application must opt into.
    ///
    /// Servers using QUIC must additionally call
    /// `Conn.setQuicEarlyDataContext` before the handshake — it's
    /// the QUIC-specific replay-safety binding.
    early_data_enabled: bool = false,
};

pub const Context = struct {
    inner: *c.SSL_CTX,
    mode: Mode,

    pub fn initClient(options: ContextOptions) Error!Context {
        return init(.client, options);
    }

    pub fn initServer(options: ContextOptions) Error!Context {
        return init(.server, options);
    }

    fn init(mode: Mode, options: ContextOptions) Error!Context {
        const method = switch (mode) {
            .client => c.zbssl_TLS_client_method(),
            .server => c.zbssl_TLS_server_method(),
        };
        const ctx = c.zbssl_SSL_CTX_new(method) orelse return Error.SslCtxAllocFailed;
        errdefer c.zbssl_SSL_CTX_free(ctx);

        if (c.zbssl_SSL_CTX_set_min_proto_version(ctx, options.min_version) != 1) {
            return Error.SslCtxAllocFailed;
        }
        if (options.max_version != 0) {
            if (c.zbssl_SSL_CTX_set_max_proto_version(ctx, options.max_version) != 1) {
                return Error.SslCtxAllocFailed;
            }
        }

        switch (options.verify) {
            .none => {
                c.zbssl_SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);
            },
            .system => {
                if (mode == .client) {
                    c.zbssl_SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
                    if (c.zbssl_SSL_CTX_set_default_verify_paths(ctx) != 1) {
                        return Error.DefaultVerifyPathsFailed;
                    }
                } else {
                    // Servers don't verify clients by default — that's mTLS,
                    // which we don't configure here. `system` on a server is
                    // equivalent to `none`.
                    c.zbssl_SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);
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

        if (options.alpn.len > 0) {
            try installAlpn(ctx, mode, options.alpn);
        }

        if (options.early_data_enabled) {
            c.zbssl_SSL_CTX_set_early_data_enabled(ctx, 1);
        }

        return .{ .inner = ctx, .mode = mode };
    }

    /// Register a callback invoked when BoringSSL receives a
    /// NewSessionTicket on this client `Context`. The callback is
    /// passed ownership of the `Session` — it must call `deinit()`
    /// when done (or hand ownership somewhere else).
    ///
    /// Calling more than once replaces the previous callback.
    pub fn setNewSessionCallback(
        self: Context,
        cb: NewSessionCallback,
        user_data: ?*anyopaque,
    ) Error!void {
        if (self.mode != .client) return Error.NotClientContext;

        const idx = newSessionExIndex();
        const holder = c_alloc.create(NewSessionHolder) catch return Error.OutOfMemory;
        holder.* = .{ .cb = cb, .user_data = user_data };
        if (c.zbssl_SSL_CTX_set_ex_data(self.inner, idx, holder) != 1) {
            c_alloc.destroy(holder);
            return Error.QuicSetupFailed;
        }
        c.zbssl_SSL_CTX_sess_set_new_cb(self.inner, newSessionTrampoline);
        // For new_cb to fire, client cache mode must be enabled.
        _ = c.zbssl_SSL_CTX_set_session_cache_mode(self.inner, c.SSL_SESS_CACHE_CLIENT |
            c.SSL_SESS_CACHE_NO_INTERNAL_STORE);
    }

    /// Register a TLS keylog callback (SSLKEYLOGFILE-style debug
    /// output). The callback receives one log line per secret in
    /// the format Wireshark expects. Calling more than once
    /// replaces the previous callback.
    pub fn setKeylogCallback(
        self: Context,
        cb: KeylogCallback,
    ) Error!void {
        const idx = keylogExIndex();
        const holder = c_alloc.create(KeylogHolder) catch return Error.OutOfMemory;
        holder.* = .{ .cb = cb };
        if (c.zbssl_SSL_CTX_set_ex_data(self.inner, idx, holder) != 1) {
            c_alloc.destroy(holder);
            return Error.KeylogSetupFailed;
        }
        c.zbssl_SSL_CTX_set_keylog_callback(self.inner, keylogTrampoline);
    }

    pub fn deinit(self: *Context) void {
        c.zbssl_SSL_CTX_free(self.inner);
        self.inner = undefined;
    }

    /// Load a PEM-encoded certificate chain plus a PEM-encoded
    /// private key. The first certificate in `chain_pem` is the
    /// end-entity (leaf); any subsequent PEM certs are added as
    /// intermediates. The private key is validated against the leaf.
    ///
    /// Server-only API: callers must use a `Context` created with
    /// `initServer`.
    pub fn loadCertChainAndKey(
        self: Context,
        chain_pem: []const u8,
        key_pem: []const u8,
    ) Error!void {
        if (self.mode != .server) return Error.NotServerContext;

        const cert_bio = c.zbssl_BIO_new_mem_buf(chain_pem.ptr, @intCast(chain_pem.len)) orelse
            return Error.OutOfMemory;
        defer _ = c.zbssl_BIO_free(cert_bio);

        var idx: usize = 0;
        while (true) {
            const cert = c.zbssl_PEM_read_bio_X509(cert_bio, null, null, null);
            if (cert == null) {
                if (idx == 0) return Error.InvalidPem;
                // Reaching end-of-input is normal; clear the residual error.
                c.zbssl_ERR_clear_error();
                break;
            }
            if (idx == 0) {
                if (c.zbssl_SSL_CTX_use_certificate(self.inner, cert) != 1) {
                    c.zbssl_X509_free(cert);
                    return Error.UseCertFailed;
                }
                // SSL_CTX_use_certificate up-refs internally; release ours.
                c.zbssl_X509_free(cert);
            } else {
                if (c.zbssl_SSL_CTX_add0_chain_cert(self.inner, cert) != 1) {
                    c.zbssl_X509_free(cert);
                    return Error.UseCertFailed;
                }
                // add0 takes ownership; do not free.
            }
            idx += 1;
        }

        const key_bio = c.zbssl_BIO_new_mem_buf(key_pem.ptr, @intCast(key_pem.len)) orelse
            return Error.OutOfMemory;
        defer _ = c.zbssl_BIO_free(key_bio);

        const pkey = c.zbssl_PEM_read_bio_PrivateKey(key_bio, null, null, null) orelse
            return Error.InvalidPem;
        defer c.zbssl_EVP_PKEY_free(pkey);

        if (c.zbssl_SSL_CTX_use_PrivateKey(self.inner, pkey) != 1) {
            return Error.UsePrivateKeyFailed;
        }
        if (c.zbssl_SSL_CTX_check_private_key(self.inner) != 1) {
            return Error.KeyMismatch;
        }
    }

    pub const ConnOptions = struct {
        /// Hostname for SNI and certificate verification.
        hostname: [:0]const u8,
        /// Connected socket fd. Conn does not own the fd.
        fd: c_int,
    };

    pub fn newClient(self: Context, options: ConnOptions) Error!Conn {
        const ssl = c.zbssl_SSL_new(self.inner) orelse return Error.SslAllocFailed;
        errdefer c.zbssl_SSL_free(ssl);

        c.zbssl_SSL_set_connect_state(ssl);

        if (c.zbssl_SSL_set_tlsext_host_name(ssl, options.hostname.ptr) != 1) {
            return Error.SslSetHostnameFailed;
        }

        const param = c.zbssl_SSL_get0_param(ssl);
        _ = c.zbssl_X509_VERIFY_PARAM_set1_host(param, options.hostname.ptr, options.hostname.len);

        if (c.zbssl_SSL_set_fd(ssl, options.fd) != 1) {
            return Error.SslSetFdFailed;
        }

        return .{ .inner = ssl };
    }

    pub const ServerConnOptions = struct {
        /// Connected socket fd. Conn does not own the fd.
        fd: c_int,
    };

    pub fn newServer(self: Context, options: ServerConnOptions) Error!Conn {
        if (self.mode != .server) return Error.NotServerContext;
        const ssl = c.zbssl_SSL_new(self.inner) orelse return Error.SslAllocFailed;
        errdefer c.zbssl_SSL_free(ssl);

        c.zbssl_SSL_set_accept_state(ssl);

        if (c.zbssl_SSL_set_fd(ssl, options.fd) != 1) {
            return Error.SslSetFdFailed;
        }

        return .{ .inner = ssl };
    }

    /// Create a fd-less SSL for use as a QUIC client. The caller
    /// drives the handshake via the `quic.Method` bridge installed
    /// with `Conn.setQuicMethod`.
    pub fn newQuicClient(self: Context) Error!Conn {
        const ssl = c.zbssl_SSL_new(self.inner) orelse return Error.SslAllocFailed;
        errdefer c.zbssl_SSL_free(ssl);
        c.zbssl_SSL_set_connect_state(ssl);
        return .{ .inner = ssl };
    }

    /// Create a fd-less SSL for use as a QUIC server.
    pub fn newQuicServer(self: Context) Error!Conn {
        if (self.mode != .server) return Error.NotServerContext;
        const ssl = c.zbssl_SSL_new(self.inner) orelse return Error.SslAllocFailed;
        errdefer c.zbssl_SSL_free(ssl);
        c.zbssl_SSL_set_accept_state(ssl);
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
        const ret = c.zbssl_SSL_do_handshake(self.inner);
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

    pub fn writeAll(self: *Conn, data: []const u8) Error!void {
        var rest: []const u8 = data;
        while (rest.len > 0) {
            const n = try self.write(rest);
            rest = rest[n..];
        }
    }

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

    /// The ALPN protocol selected by the negotiation, or null if
    /// none was selected (peer didn't advertise, no overlap, or no
    /// ALPN configured on either side).
    pub fn alpnSelected(self: *Conn) ?[]const u8 {
        var ptr: [*c]const u8 = null;
        var len: c_uint = 0;
        c.zbssl_SSL_get0_alpn_selected(self.inner, &ptr, &len);
        if (len == 0 or ptr == null) return null;
        return ptr[0..@intCast(len)];
    }

    /// Set Server Name Indication (SNI) for the upcoming handshake.
    /// Useful for QUIC clients that don't go through `newClient`.
    pub fn setHostname(self: *Conn, hostname: [:0]const u8) Error!void {
        if (c.zbssl_SSL_set_tlsext_host_name(self.inner, hostname.ptr) != 1) {
            return Error.SslSetHostnameFailed;
        }
        const param = c.zbssl_SSL_get0_param(self.inner);
        _ = c.zbssl_X509_VERIFY_PARAM_set1_host(param, hostname.ptr, hostname.len);
    }

    // -- QUIC bridge -----------------------------------------------------

    /// Install the QUIC method callback table. The pointer must
    /// outlive the Conn (typically a `static const` value or a
    /// caller-owned long-lived value).
    pub fn setQuicMethod(self: *Conn, method: *const quic.Method) Error!void {
        const c_method: [*c]const c.SSL_QUIC_METHOD = @ptrCast(@alignCast(method));
        if (c.zbssl_SSL_set_quic_method(self.inner, c_method) != 1) {
            return Error.QuicSetupFailed;
        }
    }

    /// Stash an opaque user-data pointer on this `Conn`. Useful for
    /// QUIC implementations that need to recover a `*Connection`
    /// from inside a `quic.Method` callback (which only gets `*SSL`).
    /// Retrieve with `userData()`.
    pub fn setUserData(self: *Conn, ptr: ?*anyopaque) Error!void {
        const idx = sslUserExIndex();
        if (c.zbssl_SSL_set_ex_data(self.inner, idx, ptr) != 1) {
            return Error.QuicSetupFailed;
        }
    }

    pub fn userData(self: *Conn) ?*anyopaque {
        return c.zbssl_SSL_get_ex_data(self.inner, sslUserExIndex());
    }

    /// Retrieve the user data stashed on a raw `SSL *` pointer.
    /// Equivalent to `Conn.userData()` but useful inside a callback
    /// that only has the C handle.
    pub fn userDataFromSsl(ssl: *c.SSL) ?*anyopaque {
        return c.zbssl_SSL_get_ex_data(ssl, sslUserExIndex());
    }

    /// Configure the local QUIC transport_parameters to send in the
    /// handshake (RFC 9000 §18). The bytes are caller-encoded; this
    /// wrapper just shuttles the opaque blob through.
    pub fn setQuicTransportParams(self: *Conn, params: []const u8) Error!void {
        if (c.zbssl_SSL_set_quic_transport_params(self.inner, params.ptr, params.len) != 1) {
            return Error.QuicTransportParamsFailed;
        }
    }

    /// Returns the peer's QUIC transport_parameters bytes after the
    /// handshake makes them available, or null if not yet received.
    /// Lifetime: valid until the SSL is freed.
    pub fn peerQuicTransportParams(self: *Conn) ?[]const u8 {
        var ptr: [*c]const u8 = null;
        var len: usize = 0;
        c.zbssl_SSL_get_peer_quic_transport_params(self.inner, &ptr, &len);
        if (len == 0 or ptr == null) return null;
        return ptr[0..len];
    }

    /// Server-side: configure a context blob covering every transport
    /// or application setting that affects 0-RTT semantics
    /// (RFC 9001 §4.6.1). Must be set on the server before the
    /// handshake or 0-RTT will be refused.
    pub fn setQuicEarlyDataContext(self: *Conn, context: []const u8) Error!void {
        if (c.zbssl_SSL_set_quic_early_data_context(self.inner, context.ptr, context.len) != 1) {
            return Error.QuicEarlyDataContextFailed;
        }
    }

    /// Hand BoringSSL handshake bytes received from the peer at a
    /// given encryption level.
    pub fn provideQuicData(
        self: *Conn,
        level: quic.EncryptionLevel,
        data: []const u8,
    ) Error!void {
        if (c.zbssl_SSL_provide_quic_data(self.inner, level.toC(), data.ptr, data.len) != 1) {
            return Error.QuicProvideDataFailed;
        }
    }

    /// After the handshake completes, process any post-handshake
    /// data (e.g. NewSessionTicket). Returns 1 on success, 0 on
    /// failure.
    pub fn processQuicPostHandshake(self: *Conn) Error!void {
        if (c.zbssl_SSL_process_quic_post_handshake(self.inner) != 1) {
            return Error.HandshakeFailed;
        }
    }

    pub fn quicReadLevel(self: *Conn) quic.EncryptionLevel {
        return quic.EncryptionLevel.fromC(c.zbssl_SSL_quic_read_level(self.inner));
    }

    pub fn quicWriteLevel(self: *Conn) quic.EncryptionLevel {
        return quic.EncryptionLevel.fromC(c.zbssl_SSL_quic_write_level(self.inner));
    }

    pub fn isQuic(self: *Conn) bool {
        return c.zbssl_SSL_is_quic(self.inner) == 1;
    }

    /// True when the TLS 1.3 handshake has completed.
    pub fn handshakeDone(self: *Conn) bool {
        return c.zbssl_SSL_in_init(self.inner) == 0;
    }

    // -- session resumption / 0-RTT ---------------------------------------

    /// Apply a previously-saved `Session` to this client connection
    /// so the upcoming handshake attempts resumption. Must be set
    /// before `handshake()`. The session is up-ref'd internally;
    /// the caller retains ownership and may call `deinit` on the
    /// passed-in `Session` at any time.
    pub fn setSession(self: *Conn, session: Session) Error!void {
        if (c.zbssl_SSL_set_session(self.inner, session.inner) != 1) {
            return Error.SetSessionFailed;
        }
    }

    /// Enable or disable 0-RTT for this specific connection. Per-Conn
    /// override of the Context-level setting.
    pub fn setEarlyDataEnabled(self: *Conn, enabled: bool) void {
        c.zbssl_SSL_set_early_data_enabled(self.inner, if (enabled) 1 else 0);
    }

    pub const EarlyDataStatus = enum {
        /// Handshake hasn't progressed enough yet, or 0-RTT was not
        /// attempted (no session cached, server didn't advertise).
        not_offered,
        /// Server accepted 0-RTT — early data was delivered safely.
        accepted,
        /// Server rejected 0-RTT — caller should re-send any early
        /// data at the application encryption level.
        rejected,
    };

    /// Coarse "did 0-RTT succeed?" status.
    pub fn earlyDataStatus(self: *Conn) EarlyDataStatus {
        const reason = c.zbssl_SSL_get_early_data_reason(self.inner);
        return switch (reason) {
            c.ssl_early_data_unknown,
            c.ssl_early_data_disabled,
            c.ssl_early_data_no_session_offered,
            => .not_offered,
            c.ssl_early_data_accepted => .accepted,
            else => .rejected,
        };
    }

    /// Human-readable explanation of the early-data outcome (see
    /// `enum ssl_early_data_reason_t` for the full list). Returns a
    /// borrowed string with static lifetime.
    pub fn earlyDataReason(self: *Conn) []const u8 {
        const reason = c.zbssl_SSL_get_early_data_reason(self.inner);
        const s = c.zbssl_SSL_early_data_reason_string(reason) orelse return "(unknown)";
        return std.mem.sliceTo(s, 0);
    }
};

/// Owned wrapper around BoringSSL's `SSL_SESSION`. Sessions are
/// reference-counted; `deinit` releases one reference.
pub const Session = struct {
    inner: *c.SSL_SESSION,

    pub fn deinit(self: *Session) void {
        c.zbssl_SSL_SESSION_free(self.inner);
        self.inner = undefined;
    }

    /// Bump the refcount and return a second handle. Both must be
    /// `deinit`'d.
    pub fn upRef(self: Session) Session {
        _ = c.zbssl_SSL_SESSION_up_ref(self.inner);
        return .{ .inner = self.inner };
    }

    /// Serialize the session for storage. Returns a heap-allocated
    /// buffer owned by `allocator`. Caller frees with
    /// `allocator.free(...)`.
    pub fn toBytes(self: Session, allocator: std.mem.Allocator) Error![]u8 {
        var buf: [*c]u8 = null;
        var len: usize = 0;
        if (c.zbssl_SSL_SESSION_to_bytes(self.inner, &buf, &len) != 1) {
            return Error.SessionSerializeFailed;
        }
        defer c.zbssl_OPENSSL_free(buf);
        const out = allocator.alloc(u8, len) catch return Error.OutOfMemory;
        @memcpy(out, buf[0..len]);
        return out;
    }

    /// Parse bytes produced by `toBytes` (or compatible). The
    /// returned `Session` owns one reference; call `deinit` when
    /// done.
    ///
    /// Requires an `SSL_CTX` for resolving the session's certificate
    /// pool — pass the client `Context` you intend to apply this
    /// session to via `Conn.setSession`.
    pub fn fromBytes(ctx: Context, bytes: []const u8) Error!Session {
        const inner = c.zbssl_SSL_SESSION_from_bytes(bytes.ptr, bytes.len, ctx.inner) orelse
            return Error.SessionParseFailed;
        return .{ .inner = inner };
    }
};

/// Callback invoked when a NewSessionTicket arrives on a client
/// `Context` configured via `setNewSessionCallback`. The callback
/// receives ownership of the `Session` — call `deinit` (or hand
/// ownership somewhere else) when done. Typical use: serialize via
/// `Session.toBytes` and stash for resumption.
pub const NewSessionCallback = *const fn (
    user_data: ?*anyopaque,
    session: Session,
) void;

/// Callback invoked once per TLS secret derivation when a Context
/// is configured via `setKeylogCallback`. The line is a single
/// SSLKEYLOGFILE entry; concatenate with `\n` to write a Wireshark-
/// compatible file.
pub const KeylogCallback = *const fn (line: []const u8) void;

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

// -- ALPN internals ------------------------------------------------------

const AlpnHolder = struct {
    wire: []u8,
};

/// Lazily-allocated `SSL_CTX` ex-data slot for the AlpnHolder. Uses
/// atomic CAS rather than a mutex so we don't depend on a particular
/// stdlib path for synchronization primitives. A benign race could
/// call `SSL_CTX_get_ex_new_index` twice and "leak" an unused index
/// integer; we take the loser's index in that case.
var alpn_ex_index_atomic: std.atomic.Value(c_int) =
    std.atomic.Value(c_int).init(-1);

fn alpnExIndex() c_int {
    const idx = alpn_ex_index_atomic.load(.acquire);
    if (idx != -1) return idx;
    const new_idx = c.zbssl_SSL_CTX_get_ex_new_index(0, null, null, null, alpnFreeCallback);
    if (alpn_ex_index_atomic.cmpxchgStrong(-1, new_idx, .acq_rel, .acquire)) |observed| {
        return observed;
    }
    return new_idx;
}

fn alpnFreeCallback(
    parent: ?*anyopaque,
    ptr: ?*anyopaque,
    ad: ?*c.CRYPTO_EX_DATA,
    idx: c_int,
    argl: c_long,
    argp: ?*anyopaque,
) callconv(.c) void {
    _ = .{ parent, ad, idx, argl, argp };
    if (ptr) |p| {
        const h: *AlpnHolder = @ptrCast(@alignCast(p));
        if (h.wire.len > 0) c_alloc.free(h.wire);
        c_alloc.destroy(h);
    }
}

fn alpnSelectCallback(
    ssl: ?*c.SSL,
    out: [*c][*c]const u8,
    out_len: [*c]u8,
    in: [*c]const u8,
    inlen: c_uint,
    arg: ?*anyopaque,
) callconv(.c) c_int {
    _ = arg;
    // If we got here, the user installed an ALPN list, so a mismatch
    // is fatal: send the no_application_protocol alert. (Required by
    // RFC 9001 §8.1 for QUIC; sensible for general TLS servers too.)
    const ctx = c.zbssl_SSL_get_SSL_CTX(ssl) orelse return c.SSL_TLSEXT_ERR_ALERT_FATAL;
    const ex_idx = alpnExIndex();
    const holder_raw = c.zbssl_SSL_CTX_get_ex_data(ctx, ex_idx) orelse
        return c.SSL_TLSEXT_ERR_ALERT_FATAL;
    const holder: *const AlpnHolder = @ptrCast(@alignCast(holder_raw));

    const server = holder.wire;
    const client = in[0..inlen];

    var sp: usize = 0;
    while (sp < server.len) {
        const sl: usize = server[sp];
        if (sp + 1 + sl > server.len) break;
        const sproto = server[sp + 1 .. sp + 1 + sl];
        var cp: usize = 0;
        while (cp < client.len) {
            const cl: usize = client[cp];
            if (cp + 1 + cl > client.len) break;
            if (cl == sl and std.mem.eql(u8, sproto, client[cp + 1 .. cp + 1 + cl])) {
                out.* = sproto.ptr;
                out_len.* = @intCast(sl);
                return c.SSL_TLSEXT_ERR_OK;
            }
            cp += 1 + cl;
        }
        sp += 1 + sl;
    }
    return c.SSL_TLSEXT_ERR_ALERT_FATAL;
}

fn buildAlpnWire(protocols: []const []const u8) Error![]u8 {
    var total: usize = 0;
    for (protocols) |p| {
        if (p.len == 0 or p.len > 255) return Error.AlpnInvalid;
        total += 1 + p.len;
    }
    if (total == 0 or total > 65535) return Error.AlpnTooLong;

    const buf = c_alloc.alloc(u8, total) catch return Error.OutOfMemory;
    var pos: usize = 0;
    for (protocols) |p| {
        buf[pos] = @intCast(p.len);
        @memcpy(buf[pos + 1 .. pos + 1 + p.len], p);
        pos += 1 + p.len;
    }
    return buf;
}

fn installAlpn(ctx: *c.SSL_CTX, mode: Mode, protocols: []const []const u8) Error!void {
    const wire = try buildAlpnWire(protocols);

    if (mode == .client) {
        // SSL_CTX_set_alpn_protos: returns 0 on success, 1 on failure.
        const rc = c.zbssl_SSL_CTX_set_alpn_protos(ctx, wire.ptr, @intCast(wire.len));
        c_alloc.free(wire); // BoringSSL copied the bytes; we can release.
        if (rc != 0) return Error.AlpnSetFailed;
    } else {
        const idx = alpnExIndex();
        const holder = c_alloc.create(AlpnHolder) catch {
            c_alloc.free(wire);
            return Error.OutOfMemory;
        };
        holder.wire = wire;
        if (c.zbssl_SSL_CTX_set_ex_data(ctx, idx, holder) != 1) {
            c_alloc.free(wire);
            c_alloc.destroy(holder);
            return Error.AlpnSetFailed;
        }
        c.zbssl_SSL_CTX_set_alpn_select_cb(ctx, alpnSelectCallback, null);
    }
}

// -- new-session callback ex-data ----------------------------------------

const NewSessionHolder = struct {
    cb: NewSessionCallback,
    user_data: ?*anyopaque,
};

var new_session_ex_index_atomic: std.atomic.Value(c_int) =
    std.atomic.Value(c_int).init(-1);

fn newSessionExIndex() c_int {
    const idx = new_session_ex_index_atomic.load(.acquire);
    if (idx != -1) return idx;
    const new_idx = c.zbssl_SSL_CTX_get_ex_new_index(0, null, null, null, newSessionFreeCallback);
    if (new_session_ex_index_atomic.cmpxchgStrong(-1, new_idx, .acq_rel, .acquire)) |observed| {
        return observed;
    }
    return new_idx;
}

fn newSessionFreeCallback(
    parent: ?*anyopaque,
    ptr: ?*anyopaque,
    ad: ?*c.CRYPTO_EX_DATA,
    idx: c_int,
    argl: c_long,
    argp: ?*anyopaque,
) callconv(.c) void {
    _ = .{ parent, ad, idx, argl, argp };
    if (ptr) |p| {
        const h: *NewSessionHolder = @ptrCast(@alignCast(p));
        c_alloc.destroy(h);
    }
}

fn newSessionTrampoline(
    ssl: ?*c.SSL,
    session: ?*c.SSL_SESSION,
) callconv(.c) c_int {
    const ctx = c.zbssl_SSL_get_SSL_CTX(ssl) orelse return 0;
    const idx = newSessionExIndex();
    const holder_raw = c.zbssl_SSL_CTX_get_ex_data(ctx, idx) orelse return 0;
    const holder: *const NewSessionHolder = @ptrCast(@alignCast(holder_raw));
    const sess = session orelse return 0;
    holder.cb(holder.user_data, .{ .inner = sess });
    // Return 1 to signal we took ownership; BoringSSL won't free.
    return 1;
}

// -- keylog callback ex-data ---------------------------------------------

const KeylogHolder = struct {
    cb: KeylogCallback,
};

var keylog_ex_index_atomic: std.atomic.Value(c_int) =
    std.atomic.Value(c_int).init(-1);

fn keylogExIndex() c_int {
    const idx = keylog_ex_index_atomic.load(.acquire);
    if (idx != -1) return idx;
    const new_idx = c.zbssl_SSL_CTX_get_ex_new_index(0, null, null, null, keylogFreeCallback);
    if (keylog_ex_index_atomic.cmpxchgStrong(-1, new_idx, .acq_rel, .acquire)) |observed| {
        return observed;
    }
    return new_idx;
}

fn keylogFreeCallback(
    parent: ?*anyopaque,
    ptr: ?*anyopaque,
    ad: ?*c.CRYPTO_EX_DATA,
    idx: c_int,
    argl: c_long,
    argp: ?*anyopaque,
) callconv(.c) void {
    _ = .{ parent, ad, idx, argl, argp };
    if (ptr) |p| {
        const h: *KeylogHolder = @ptrCast(@alignCast(p));
        c_alloc.destroy(h);
    }
}

fn keylogTrampoline(
    ssl: ?*const c.SSL,
    line: [*c]const u8,
) callconv(.c) void {
    const ctx = c.zbssl_SSL_get_SSL_CTX(@constCast(ssl)) orelse return;
    const idx = keylogExIndex();
    const holder_raw = c.zbssl_SSL_CTX_get_ex_data(ctx, idx) orelse return;
    const holder: *const KeylogHolder = @ptrCast(@alignCast(holder_raw));
    const line_slice = std.mem.sliceTo(line, 0);
    holder.cb(line_slice);
}

// -- SSL ex-data for opaque user pointer ---------------------------------

var ssl_user_ex_index_atomic: std.atomic.Value(c_int) =
    std.atomic.Value(c_int).init(-1);

fn sslUserExIndex() c_int {
    const idx = ssl_user_ex_index_atomic.load(.acquire);
    if (idx != -1) return idx;
    const new_idx = c.zbssl_SSL_get_ex_new_index(0, null, null, null, null);
    if (ssl_user_ex_index_atomic.cmpxchgStrong(-1, new_idx, .acq_rel, .acquire)) |observed| {
        return observed;
    }
    return new_idx;
}

// -- tests ---------------------------------------------------------------

test "client context still inits with default options" {
    var ctx = try Context.initClient(.{ .verify = .none });
    defer ctx.deinit();
}

test "server context refuses loadCertChainAndKey when not server" {
    var ctx = try Context.initClient(.{ .verify = .none });
    defer ctx.deinit();
    try std.testing.expectError(
        Error.NotServerContext,
        ctx.loadCertChainAndKey("", ""),
    );
}

// (The "loads embedded test cert + key" test lives in
// tests/tls_server.zig — it needs @embedFile from outside src/, which
// Zig 0.16 forbids from a module's own source files.)

test "loadCertChainAndKey rejects malformed PEM" {
    var ctx = try Context.initServer(.{ .verify = .none });
    defer ctx.deinit();
    try std.testing.expectError(Error.InvalidPem, ctx.loadCertChainAndKey("garbage", "garbage"));
}

test "ALPN client config sets without error" {
    const protos = [_][]const u8{ "h3", "hq-interop" };
    var ctx = try Context.initClient(.{ .verify = .none, .alpn = &protos });
    defer ctx.deinit();
}

test "ALPN server config sets without error" {
    const protos = [_][]const u8{ "h3", "hq-interop" };
    var ctx = try Context.initServer(.{ .verify = .none, .alpn = &protos });
    defer ctx.deinit();
}

test "ALPN rejects oversized protocol entries" {
    var huge: [256]u8 = @splat(0x41);
    const protos = [_][]const u8{&huge};
    try std.testing.expectError(
        Error.AlpnInvalid,
        Context.initClient(.{ .verify = .none, .alpn = &protos }),
    );
}

test "ALPN rejects empty protocol entries" {
    const protos = [_][]const u8{""};
    try std.testing.expectError(
        Error.AlpnInvalid,
        Context.initClient(.{ .verify = .none, .alpn = &protos }),
    );
}
