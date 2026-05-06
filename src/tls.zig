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
    AllowEarlyDataCallbackInstallFailed,
    EarlyDataRejected,
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

    /// Testing-only override for whether BoringSSL behaves as if AES
    /// hardware is available. Passing `false` makes TLS 1.3 clients prefer
    /// ChaCha20-Poly1305 over AES-GCM, which is useful for interop suites that
    /// need deterministic ChaCha ClientHellos on AES-capable hosts.
    aes_hw_override_for_testing: ?bool = null,
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
        if (options.aes_hw_override_for_testing) |has_aes_hw| {
            c.boringssl_zig_SSL_CTX_set_aes_hw_override_for_testing(
                ctx,
                if (has_aes_hw) 1 else 0,
            );
        }

        return .{ .inner = ctx, .mode = mode };
    }

    /// Testing-only override for whether BoringSSL behaves as if AES hardware
    /// is available. Use `false` to prefer ChaCha20-Poly1305 in TLS 1.3.
    pub fn setAesHardwareOverrideForTesting(self: Context, has_aes_hw: bool) void {
        c.boringssl_zig_SSL_CTX_set_aes_hw_override_for_testing(
            self.inner,
            if (has_aes_hw) 1 else 0,
        );
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

    /// Register a server-side hook that decides, per incoming
    /// ClientHello, whether 0-RTT (early data) is allowed for that
    /// specific handshake attempt. Returning `false` disables early
    /// data for that connection without aborting the handshake —
    /// a normal 1-RTT handshake proceeds and BoringSSL reports
    /// `ssl_early_data_disabled` via `Conn.earlyDataReason()`.
    ///
    /// This is the QUIC anti-replay integration point (RFC 9001
    /// §9.2): the embedder runs its anti-replay tracker against the
    /// resumed session identity (see `Conn.peerSessionId`) and
    /// returns `false` if the offer would be a replay.
    ///
    /// The callback fires for every ClientHello on this server
    /// `Context`. For non-resumed handshakes the ClientHello will
    /// not carry a pre_shared_key extension and `Conn.peerSessionId`
    /// will return null — embedders may use that as a fast "no
    /// replay check needed" signal. BoringSSL also rejects 0-RTT
    /// for those handshakes regardless of the callback's return.
    ///
    /// Implemented on top of BoringSSL's
    /// `SSL_CTX_set_select_certificate_cb`. That hook fires before
    /// the resumption decision is taken, so calling
    /// `SSL_set_early_data_enabled(ssl, 0)` on a `false` return
    /// reliably suppresses 0-RTT acceptance. Returns
    /// `Error.AllowEarlyDataCallbackInstallFailed` if the ex-data
    /// slot used to stash the holder cannot be installed.
    pub fn setAllowEarlyDataCallback(
        self: *Context,
        cb: AllowEarlyDataCallback,
        user_data: ?*anyopaque,
    ) Error!void {
        if (self.mode != .server) return Error.NotServerContext;

        const idx = allowEarlyDataExIndex();
        const holder = c_alloc.create(AllowEarlyDataHolder) catch return Error.OutOfMemory;
        holder.* = .{ .cb = cb, .user_data = user_data };
        if (c.zbssl_SSL_CTX_set_ex_data(self.inner, idx, holder) != 1) {
            c_alloc.destroy(holder);
            return Error.AllowEarlyDataCallbackInstallFailed;
        }
        c.zbssl_SSL_CTX_set_select_certificate_cb(self.inner, allowEarlyDataTrampoline);
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

    /// Disable early data on this specific connection. Useful from
    /// inside a callback that has decided the offer is a replay or
    /// otherwise unsafe to honor. Equivalent to
    /// `SSL_set_early_data_enabled(ssl, 0)` and matches the inverse
    /// of `setEarlyDataEnabled(true)`.
    pub fn disableEarlyData(self: *Conn) void {
        c.zbssl_SSL_set_early_data_enabled(self.inner, 0);
    }

    /// Reset a client connection that hit
    /// `Error.EarlyDataRejected`. After this returns the SSL is
    /// logically a fresh connection on which `handshake()` may be
    /// called again to complete the full 1-RTT handshake. Calling
    /// this on a connection that did NOT hit early-data rejection
    /// is undefined behavior in BoringSSL.
    pub fn resetEarlyDataReject(self: *Conn) void {
        c.zbssl_SSL_reset_early_data_reject(self.inner);
    }

    /// Returns a stable identity for the resumption attempt being
    /// processed, or null if no session is being resumed. Used by
    /// embedders inside an `AllowEarlyDataCallback` to feed their
    /// 0-RTT replay tracker.
    ///
    /// During an `AllowEarlyDataCallback` invocation: returns the
    /// PSK identity (TLS 1.3 session ticket bytes) from the
    /// ClientHello's `pre_shared_key` extension. The bytes point
    /// into the ClientHello buffer and are only valid for the
    /// duration of the callback — copy if you need to retain them.
    /// Returns null when the ClientHello does not offer a
    /// pre_shared_key (a non-resumed handshake).
    ///
    /// Outside the callback: returns BoringSSL's
    /// `SSL_SESSION_get_id` bytes for whatever session is currently
    /// bound to the connection. May be null if no session is
    /// attached yet.
    pub fn peerSessionId(self: *Conn) ?[]const u8 {
        if (current_client_hello) |hello| {
            if (hello.*.ssl == self.inner) {
                return extractPskIdentity(hello);
            }
        }
        const session = c.zbssl_SSL_get_session(self.inner) orelse return null;
        var len: c_uint = 0;
        const ptr = c.zbssl_SSL_SESSION_get_id(session, &len);
        if (len == 0 or ptr == null) return null;
        return ptr[0..@intCast(len)];
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

/// Server-side hook installed via `Context.setAllowEarlyDataCallback`.
/// Invoked from the BoringSSL early callback for every ClientHello,
/// before the resumption decision is made. Return `true` to allow
/// 0-RTT for this connection, `false` to disable it (the handshake
/// continues as a normal 1-RTT handshake).
///
/// `ssl` is a transient `*Conn` view valid only for the duration of
/// the callback. Use `Conn.peerSessionId()` from inside the callback
/// to obtain a stable identity for the resumption attempt; that
/// returns null when no resumed session is attached, in which case
/// the return value is moot — BoringSSL won't accept 0-RTT anyway.
///
/// The callback must be infallible from BoringSSL's perspective; if
/// the embedder needs to abort the handshake outright on a
/// catastrophic anti-replay error, it should set up that behavior
/// out-of-band and return `false` here so 0-RTT is at least denied.
pub const AllowEarlyDataCallback = *const fn (
    user_data: ?*anyopaque,
    ssl: *Conn,
) bool;

fn mapSslError(ssl: *c.SSL, ret: c_int, default: Error) Error {
    const err_code = c.zbssl_SSL_get_error(ssl, ret);
    return switch (err_code) {
        c.SSL_ERROR_WANT_READ => Error.WantRead,
        c.SSL_ERROR_WANT_WRITE => Error.WantWrite,
        c.SSL_ERROR_ZERO_RETURN => Error.ConnectionClosed,
        c.SSL_ERROR_SYSCALL => Error.SyscallError,
        c.SSL_ERROR_EARLY_DATA_REJECTED => Error.EarlyDataRejected,
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
        // Checked end-of-entry math: every step against peer-controlled
        // bytes must fail closed, never wrap.
        const s_end = std.math.add(usize, sp, 1) catch break;
        const s_proto_end = std.math.add(usize, s_end, sl) catch break;
        if (s_proto_end > server.len) break;
        const sproto = server[s_end..s_proto_end];
        var cp: usize = 0;
        while (cp < client.len) {
            const cl: usize = client[cp];
            const c_end = std.math.add(usize, cp, 1) catch break;
            const c_proto_end = std.math.add(usize, c_end, cl) catch break;
            if (c_proto_end > client.len) break;
            if (cl == sl and std.mem.eql(u8, sproto, client[c_end..c_proto_end])) {
                out.* = sproto.ptr;
                out_len.* = @intCast(sl);
                return c.SSL_TLSEXT_ERR_OK;
            }
            cp = c_proto_end;
        }
        sp = s_proto_end;
    }
    return c.SSL_TLSEXT_ERR_ALERT_FATAL;
}

fn buildAlpnWire(protocols: []const []const u8) Error![]u8 {
    var total: usize = 0;
    for (protocols) |p| {
        if (p.len == 0 or p.len > 255) return Error.AlpnInvalid;
        // Checked accumulator: sum could overflow with adversarial
        // caller input (huge protocol list pointers/lengths).
        const step = std.math.add(usize, 1, p.len) catch return Error.AlpnTooLong;
        total = std.math.add(usize, total, step) catch return Error.AlpnTooLong;
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

// -- allow-early-data callback ex-data -----------------------------------

const AllowEarlyDataHolder = struct {
    cb: AllowEarlyDataCallback,
    user_data: ?*anyopaque,
};

/// Threadlocal pointer stashed by the trampoline so that
/// `Conn.peerSessionId()` can reach the in-flight ClientHello when
/// invoked from inside an `AllowEarlyDataCallback`. Cleared back to
/// null on trampoline exit. The pointer is owned by BoringSSL and
/// only valid for the duration of the callback.
threadlocal var current_client_hello: ?*const c.SSL_CLIENT_HELLO = null;

/// Extract the first `PskIdentity` (a TLS 1.3 session ticket) from
/// the ClientHello's `pre_shared_key` extension, if present. Returns
/// null when the extension is missing or malformed — both indicate
/// a non-resumption handshake from the embedder's perspective.
///
/// Wire format (RFC 8446 §4.2.11):
///   OfferedPsks {
///     PskIdentity identities<7..2^16-1>;  // 2-byte length prefix, then entries
///     PskBinderEntry binders<33..2^16-1>;
///   }
///   PskIdentity {
///     opaque identity<1..2^16-1>;         // 2-byte length, then bytes
///     uint32 obfuscated_ticket_age;
///   }
/// The minimum for a valid first entry is therefore 2+1+4=7 bytes
/// inside the identities list, plus the 2-byte list-length prefix.
fn extractPskIdentity(hello: *const c.SSL_CLIENT_HELLO) ?[]const u8 {
    var ext_data: [*c]const u8 = null;
    var ext_len: usize = 0;
    if (c.zbssl_SSL_early_callback_ctx_extension_get(
        hello,
        c.TLSEXT_TYPE_pre_shared_key,
        &ext_data,
        &ext_len,
    ) != 1) return null;
    if (ext_data == null or ext_len < 4) return null;

    const ext = ext_data[0..ext_len];
    const list_len = @as(usize, ext[0]) << 8 | @as(usize, ext[1]);
    // The list must hold at least one full PskIdentity (>=7 bytes)
    // and fit inside the extension body.
    if (list_len < 7) return null;
    const list_end = std.math.add(usize, 2, list_len) catch return null;
    if (list_end > ext.len) return null;

    const id_len = @as(usize, ext[2]) << 8 | @as(usize, ext[3]);
    if (id_len == 0) return null;
    const id_start: usize = 4;
    const id_end = std.math.add(usize, id_start, id_len) catch return null;
    if (id_end > list_end) return null;
    return ext[id_start..id_end];
}

var allow_early_data_ex_index_atomic: std.atomic.Value(c_int) =
    std.atomic.Value(c_int).init(-1);

fn allowEarlyDataExIndex() c_int {
    const idx = allow_early_data_ex_index_atomic.load(.acquire);
    if (idx != -1) return idx;
    const new_idx = c.zbssl_SSL_CTX_get_ex_new_index(0, null, null, null, allowEarlyDataFreeCallback);
    if (allow_early_data_ex_index_atomic.cmpxchgStrong(-1, new_idx, .acq_rel, .acquire)) |observed| {
        return observed;
    }
    return new_idx;
}

fn allowEarlyDataFreeCallback(
    parent: ?*anyopaque,
    ptr: ?*anyopaque,
    ad: ?*c.CRYPTO_EX_DATA,
    idx: c_int,
    argl: c_long,
    argp: ?*anyopaque,
) callconv(.c) void {
    _ = .{ parent, ad, idx, argl, argp };
    if (ptr) |p| {
        const h: *AllowEarlyDataHolder = @ptrCast(@alignCast(p));
        c_alloc.destroy(h);
    }
}

fn allowEarlyDataTrampoline(
    client_hello: [*c]const c.SSL_CLIENT_HELLO,
) callconv(.c) c.ssl_select_cert_result_t {
    // Pull the SSL out of the early-callback context, then walk to
    // the SSL_CTX where the holder lives.
    const hello = client_hello orelse return c.ssl_select_cert_success;
    const ssl = hello.*.ssl orelse return c.ssl_select_cert_success;
    const ctx = c.zbssl_SSL_get_SSL_CTX(ssl) orelse return c.ssl_select_cert_success;
    const idx = allowEarlyDataExIndex();
    const holder_raw = c.zbssl_SSL_CTX_get_ex_data(ctx, idx) orelse
        return c.ssl_select_cert_success;
    const holder: *const AllowEarlyDataHolder = @ptrCast(@alignCast(holder_raw));

    // Stash the ClientHello pointer so `Conn.peerSessionId()` can
    // reach the pre_shared_key extension during the callback. The
    // BoringSSL hook is synchronous, so a threadlocal is enough;
    // restore the previous value (typically null) on exit so
    // nested or re-entrant calls compose cleanly.
    const prev = current_client_hello;
    current_client_hello = @ptrCast(hello);
    defer current_client_hello = prev;

    var conn: Conn = .{ .inner = ssl };
    const allow = holder.cb(holder.user_data, &conn);
    if (!allow) {
        // Disable 0-RTT for this connection. BoringSSL will fall
        // back to a normal 1-RTT handshake; downstream code can read
        // `Conn.earlyDataReason()` to confirm
        // `ssl_early_data_disabled` was the cause.
        c.zbssl_SSL_set_early_data_enabled(ssl, 0);
    }
    // Always return success from the early callback — returning
    // `ssl_select_cert_error` would abort the handshake, but the
    // anti-replay use case only requires denying 0-RTT, not killing
    // the connection. Aborts belong to a separate hook the embedder
    // owns.
    return c.ssl_select_cert_success;
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

test "client context accepts AES hardware override testing knob" {
    var ctx = try Context.initClient(.{
        .verify = .none,
        .aes_hw_override_for_testing = false,
    });
    defer ctx.deinit();

    ctx.setAesHardwareOverrideForTesting(false);
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
