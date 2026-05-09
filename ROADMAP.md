# boringssl-zig roadmap

This document captures planned releases driven primarily by
[`quic-zig`](../quic-zig)'s production-grade requirements, with one eye on
keeping the wrapper generally useful for non-QUIC consumers.

## Released

- **v0.1.0** (2026-05-03) — Zig wrapper, native build.zig, BoringSSL
  via `zig fetch`, symbol-prefixed (`BORINGSSL_PREFIX=zbssl`),
  cross-compiles to aarch64/x86_64 × {macos, linux-musl}. Public
  surface: `crypto.{hash, hmac, rand}`, `tls.{Context, Conn}`
  (client only), `errors`, `raw.zbssl_*`.
- **v0.2.0** (2026-05-03) — QUIC-ready crypto primitives:
  `crypto.aead.{AesGcm128, AesGcm256, ChaCha20Poly1305}`,
  `crypto.kdf.HkdfSha{256,384,512}`,
  `crypto.aes.{Aes128, Aes256}` single-block. Cross-cutting RFC 9001
  §A.1 initial-secret KAT lives upstream.
- **v0.3.0** (2026-05-03) — TLS 1.3 server + ALPN + QUIC TLS bridge.
  Combined what was originally planned as v0.3.0 (server) + v0.4.0
  (QUIC) since they're tightly coupled. Adds:
  - `tls.Context.initServer` + `loadCertChainAndKey` (PEM in
    memory; chain + key validated against each other).
  - ALPN via `ContextOptions.alpn` for both client
    (`SSL_CTX_set_alpn_protos`) and server
    (`SSL_CTX_set_alpn_select_cb` with first-server-preference;
    mismatch → `no_application_protocol` fatal alert).
  - `Conn.alpnSelected()`, `Conn.setHostname()`, `Conn.handshakeDone()`.
  - `Conn.newQuicClient` / `newQuicServer` for fd-less SSL objects.
  - `tls.quic.Method` (ABI-compatible with `SSL_QUIC_METHOD`),
    `tls.quic.EncryptionLevel`, plus `Conn` methods:
    `setQuicMethod`, `setQuicTransportParams`,
    `peerQuicTransportParams`, `setQuicEarlyDataContext`,
    `provideQuicData`, `processQuicPostHandshake`,
    `quicReadLevel` / `quicWriteLevel`, `isQuic`,
    `setUserData` / `userData` / `userDataFromSsl`.
  - In-process socketpair TLS 1.3 handshake KAT with ALPN.
  - In-process end-to-end QUIC TLS handshake KAT through the
    bridge — no UDP, no QUIC packet protection, just two
    `tls.Conn`s exchanging CRYPTO bytes through Zig callbacks.

  45/45 tests green.

- **v0.4.0** (2026-05-03) — TLS 1.3 session resumption + QUIC 0-RTT.
  Adds:
  - `tls.Session` (owned `SSL_SESSION` wrapper) with
    `toBytes`/`fromBytes`/`upRef`/`deinit`.
  - `Conn.setSession(session)` for client-side resumption.
  - `Context.setNewSessionCallback(cb, user_data)` over
    `SSL_CTX_sess_set_new_cb`; ownership of the captured
    `Session` transfers to the callback.
  - `Conn.setEarlyDataEnabled(bool)` and a Context-level option
    of the same name.
  - `Conn.earlyDataStatus() EarlyDataStatus`
    (`not_offered / accepted / rejected`) and
    `earlyDataReason() []const u8` for the textual reason from
    `SSL_get_early_data_reason`.
  - End-to-end QUIC 0-RTT acceptance test through the bridge:
    capture session via callback → `Session.fromBytes` →
    `setSession` → second handshake → both sides
    `earlyDataStatus() == .accepted`.
- **v0.5.0** (2026-05-03) — ChaCha20 + production polish.
  Adds:
  - `crypto.chacha20.{xor, quicHpMask}` over `CRYPTO_chacha_20`.
    `xor` for general stream-cipher use; `quicHpMask` for QUIC
    header protection per RFC 9001 §5.4.4. RFC 8439 §2.4.2 KAT.
  - `errors.popErrorString(allocator)` and `popErrorStringInto`
    for diagnostic logging from BoringSSL's per-thread error
    queue.
  - `Context.setKeylogCallback(cb)` over
    `SSL_CTX_set_keylog_callback`. Test asserts the callback
    fires with valid SSLKEYLOGFILE-prefixed lines during a real
    handshake.

  Shipped together with v0.4.0 in a single bump to 0.5.0, since
  both are quic-zig-driven and tightly related to the production-grade
  surface. 53/53 tests green.
- **v0.6.0** (2026-05-08) — AES-128/256-ECB single-block decrypt.
  Adds:
  - `crypto.aes.Block(bits).initDecrypt(key)` over
    `AES_set_decrypt_key`, returning a `Block` whose embedded
    `AES_KEY` carries the inverse-direction round-key schedule.
  - `crypto.aes.Block(bits).decryptBlock(in, out)` over
    `AES_decrypt`. Matched-pair contract documented: pair `init` +
    `encryptBlock` or `initDecrypt` + `decryptBlock`; mismatching
    them produces undefined output (different schedules).
  - FIPS 197 Appendix C.1 / C.3 KATs for AES-128 and AES-256
    decrypt, plus an encrypt/decrypt round-trip property test under
    a random key.

  Driven by quic-zig's QUIC-LB
  ([draft-ietf-quic-load-balancers-21][quic-lb]) §5.5.1 single-pass
  decode helper: the LB-side decoder needs the inverse of the §5.4.1
  AES-128-ECB encrypt the server uses to mint connection IDs.
  65/65 tests green (37 wrapper + 28 KAT).

  [quic-lb]: https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/

## Planned

### Beyond v0.5.0 (unscheduled)

Things we'd take a PR for but don't drive:
- Windows support.
- FIPS mode.
- Custom certificate verification callbacks (`SSL_CTX_set_verify`
  with a Zig callback).
- BoringSSL's Hybrid Public Key Encryption (HPKE) wrappers.
- AES-GCM-SIV / Poly1305 standalone primitives.

## Release process

1. Land changes on `main` with full test suite green.
2. Bump `version` in `build.zig.zon` and tag the commit annotated
   with the release notes (mirroring the style of v0.2.0).
3. Push tag to the GitHub origin
   (`git@github.com:nullstyle/boringssl-zig.git`).
4. Update `quic-zig`'s `build.zig.zon` to point at the new tarball URL
   when the bump is intentional. (During development of quic-zig we
   continue using a path dep.)

## Compatibility

- **Zig:** floor pinned to 0.16.0; no plans to support 0.15 or earlier.
- **BoringSSL:** pinned by SHA via `zig fetch`. Bumps come with a
  manual review of the upstream changelog.
- **API:** v0.x.0 releases may make small ergonomic breaks. v1.0.0
  freezes the high-level `crypto.*` and `tls.*` surfaces; `raw.*`
  is unstable forever (it's translate-c output).
