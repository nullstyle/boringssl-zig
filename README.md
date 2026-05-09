# boringssl-zig

A Zig wrapper around BoringSSL, intended for publication as a Zig package.
Builds BoringSSL natively from `build.zig` — consumers need only Zig
0.16.0; CMake is optional and only used as a verification path.

**Status: 0.6.0 — AES-128/256-ECB single-block decrypt
(`Aes128.initDecrypt` / `decryptBlock`) on top of 0.5.0. Drives
QUIC-LB draft-21 §5.5.1 single-pass decode in quic-zig.**

| Phase | What | Status |
| --- | --- | --- |
| 0 | CMake-built prebuilt + KATs | ✅ |
| 1 | Cross-compile macOS + linux-musl, TLS client wrapper | ✅ |
| 2 | Drop CMake — native `build.zig` is the default | ✅ |
| 3 | Consumable as `build.zig.zon` dependency, BoringSSL via `zig fetch` | ✅ |
| 0.2 | AEAD (GCM, ChaCha20-Poly1305) + HKDF + AES-Block | ✅ |
| 0.3 | TLS server + cert/key loading + ALPN + QUIC `SSL_QUIC_METHOD` bridge | ✅ |
| 0.4 | TLS 1.3 session resumption + QUIC 0-RTT (`tls.Session`, new-session callback, early-data status) | ✅ |
| 0.5 | ChaCha20 stream cipher, `errors.popErrorString`, `Context.setKeylogCallback` | ✅ |
| 0.6 | AES-128/256-ECB single-block decrypt for QUIC-LB §5.5.1 | ✅ |

Verified targets: `aarch64-macos`, `x86_64-macos`, `aarch64-linux-musl`,
`x86_64-linux-musl`. KAT tests run natively on macOS targets and on x86_64
via Rosetta. Linux cross builds link cleanly (qemu not used).

## Quick start

```sh
mise install            # zig 0.16.0 (and go for the optional cmake path)
just deps               # init the BoringSSL submodule
just test               # 22 tests: SHA-2 KATs, HMAC RFC 4231, RAND, errors, etc.
just smoke              # SHA-256 + 16 random bytes
just tls-smoke          # HTTPS round-trip to example.com:443 (TLS 1.3, cert verify)
```

`just test` does the full BoringSSL native build (libcrypto.a + libssl.a)
on first run; subsequent invocations hit the Zig cache.

## How the build works

`build.zig` reads `deps/boringssl/gen/sources.json` — BoringSSL's
build-system-agnostic source manifest — and feeds the C++ and `.S` files
straight into `b.addLibrary(.static)` steps. No CMake, no Ninja, no
external compiler driver.

```
deps/boringssl/gen/sources.json
            ↓
    build_boringssl.zig
            ↓
    libcrypto static lib   (244 .cc + 24 .S + bcm.cc + 99 .S)
    libssl    static lib   (38 .cc, links libcrypto)
            ↓
    boringssl_mod.linkLibrary(...)
```

All assembly files are gated by `#if defined(OPENSSL_X86_64) && defined(__APPLE__)`
and similar — so we include them all and let the preprocessor select per
target. Windows-only NASM (`*.asm`) is intentionally skipped.

The `BORINGSSL_PREFIX=zbssl` define is applied so every exported symbol
is renamed (verified: `nm libcrypto.a | grep 'T _zbssl_'`). This means
the library can safely link beside system OpenSSL or another BoringSSL
copy without ODR collisions.

## Choosing a build path

```sh
zig build test                                 # native (default)
zig build test -Dboringssl-source=zig          # explicit native
zig build test -Dboringssl-source=cmake        # use vendor/ prebuilt
just verify-paths                              # both paths must pass KATs
```

The CMake path remains for cross-checking the native build:
`scripts/build-boringssl.sh <target>` produces a vendored
`libcrypto.a`/`libssl.a` reproducible by SHA-256, recorded in
`manifest.json`. If the native build ever diverges from upstream, the
KATs against the CMake build are the comparison oracle.

## Wrapper API

```zig
const boringssl = @import("boringssl");

// Hashes
const digest = boringssl.crypto.hash.Sha256.hash("hello");
var hash_ctx = boringssl.crypto.hash.Sha512.init();
hash_ctx.update("...");
const tag = hash_ctx.finalDigest();

// HMAC
const mac = boringssl.crypto.hmac.HmacSha256.auth(key, msg);

// AEAD (TLS 1.3 / RFC 9001 packet protection)
var aead = try boringssl.crypto.aead.AesGcm128.init(&aead_key);
defer aead.deinit();
const ct_len = try aead.seal(&ct_buf, &nonce, ad, plaintext);
const pt_len = try aead.open(&pt_buf, &nonce, ad, ct_buf[0..ct_len]);

// HKDF (RFC 5869; QUIC initial-secret derivation)
const prk = boringssl.crypto.kdf.HkdfSha256.extract(salt, ikm);
boringssl.crypto.kdf.HkdfSha256.expand(&prk, info, &okm);

// AES single-block (header protection — AES suite)
const aes = boringssl.crypto.aes.Aes128.init(&hp_key);
var mask: [16]u8 = undefined;
aes.encryptBlock(&sample, &mask);

// ChaCha20 (stream cipher + QUIC HP mask for ChaCha suite)
boringssl.crypto.chacha20.xor(&out_buf, &in_buf, &cc_key, &cc_nonce, 0);
const cc_mask = boringssl.crypto.chacha20.quicHpMask(&cc_hp_key, &sample);

// Random
var rand_buf: [32]u8 = undefined;
try boringssl.crypto.rand.fillBytes(&rand_buf);

// TLS client
var tls_ctx = try boringssl.tls.Context.initClient(.{ .verify = .system });
defer tls_ctx.deinit();
var conn = try tls_ctx.newClient(.{ .hostname = "example.com", .fd = sock });
defer conn.deinit();
try conn.handshake();
try conn.writeAll("GET / HTTP/1.1\r\n...\r\n\r\n");

// TLS server (with cert + key + ALPN)
const protos = [_][]const u8{ "h2", "http/1.1" };
var srv_ctx = try boringssl.tls.Context.initServer(.{
    .verify = .none,
    .min_version = boringssl.raw.TLS1_3_VERSION,
    .alpn = &protos,
});
defer srv_ctx.deinit();
try srv_ctx.loadCertChainAndKey(cert_pem_bytes, key_pem_bytes);
var srv_conn = try srv_ctx.newServer(.{ .fd = accept_fd });
defer srv_conn.deinit();
try srv_conn.handshake();
const negotiated = srv_conn.alpnSelected(); // ?[]const u8

// QUIC TLS bridge — drive TLS 1.3 over BoringSSL's SSL_QUIC_METHOD.
var quic_conn = try srv_ctx.newQuicServer();
defer quic_conn.deinit();
try quic_conn.setUserData(my_state_ptr);
try quic_conn.setQuicMethod(&my_method); // boringssl.tls.quic.Method
try quic_conn.setQuicTransportParams(rfc9000_section_18_bytes);
try quic_conn.setQuicEarlyDataContext(replay_context_bytes); // server-side 0-RTT
try quic_conn.handshake(); // returns WantRead until peer bytes arrive
try quic_conn.provideQuicData(.initial, peer_crypto_bytes);

// Session resumption + 0-RTT (client side)
try client_ctx.setNewSessionCallback(captureSession, null);
// ... after handshake, captured session has been serialized to bytes ...
var session = try boringssl.tls.Session.fromBytes(client_ctx, saved_session_bytes);
defer session.deinit();
var resumed = try client_ctx.newQuicClient();
defer resumed.deinit();
try resumed.setSession(session);
resumed.setEarlyDataEnabled(true);
// ... drive handshake; then check ...
const status = resumed.earlyDataStatus(); // .accepted / .rejected / .not_offered

// SSLKEYLOGFILE-style debugging
try client_ctx.setKeylogCallback(struct {
    fn line(s: []const u8) void { std.debug.print("{s}\n", .{s}); }
}.line);

// Drain BoringSSL's per-thread error queue
if (try boringssl.errors.popErrorString(allocator)) |msg| {
    defer allocator.free(msg);
    std.debug.print("bssl: {s}\n", .{msg});
}

// Raw access (unstable; symbols carry the `zbssl_` prefix):
boringssl.raw.zbssl_SHA256_Init(&raw_ctx);
```

### The `raw` namespace

`boringssl.raw` is the translate-c output of [`src/c_imports.h`](src/c_imports.h),
which pulls in `<openssl/{base,crypto,err,evp,sha,hmac,rand,ssl,x509,x509v3,bio,aead,hkdf,aes,chacha,pem}.h>`.
The supported way to call BoringSSL functions is the wrapper API
(`boringssl.crypto.*`, `boringssl.tls.*`); reach into `raw.*` only when
you need a primitive the wrapper hasn't yet exposed.

A few rules for `raw.*`:

- Function symbols carry the `zbssl_` prefix: `raw.zbssl_SHA256_Init`,
  `raw.zbssl_HMAC_Update`, `raw.zbssl_SSL_CTX_new`. Type names are
  unprefixed (`raw.SHA256_CTX`, `raw.SSL`).
- Numeric/macro constants pass through unchanged: `raw.SSL_VERIFY_PEER`,
  `raw.TLS1_2_VERSION`, `raw.SSL_ERROR_WANT_READ`.
- Translate-c skips function-like macros that use token pasting (e.g.
  pieces of BoringSSL's hostname-verification macros). The wrapper
  layer handles these — if you find a missing helper you wanted to call
  directly, that's the signal to add it to the wrapper.
- BoringSSL's API stability promise applies (it's "live at head"): a
  BoringSSL repin can rename or remove `raw.*` names without warning.
  The wrapper API is what shields you from this churn.

## Cross-compiling

```sh
zig build test  -Dtarget=aarch64-macos          # native arm64 mac
zig build test  -Dtarget=x86_64-macos           # via Rosetta
zig build       -Dtarget=aarch64-linux-musl     # link only (no qemu)
zig build       -Dtarget=x86_64-linux-musl
```

The Linux cross builds produce statically-linked ELF binaries; running
them from macOS needs `qemu-aarch64` / `qemu-x86_64` (or use `-fqemu`).

## Layout

```
src/                    library code only (shipped to consumers)
  c_imports.h
  root.zig              public API: crypto.{hash,hmac,rand,aead,kdf,aes,chacha20}, tls, errors, raw
  crypto/{hash,hmac,rand,aead,kdf,aes,chacha20}.zig
  tls.zig               TLS 1.3 client + server (fd-based + fd-less for QUIC), Session, callbacks
  tls_quic.zig          QUIC-specific types (EncryptionLevel, Method)
  internal/errors.zig   error-queue helpers (popErrorString, etc.)
cli/                    development binaries (NOT shipped)
  smoke.zig             SHA-256 + RAND demo
  tls_smoke.zig         HTTPS round-trip
tests/                  KATs and in-process integration tests
  data/                 self-signed P-256 test cert + key
  kat_*.zig             SHA-2, HMAC-SHA-2 (RFC 4231), RAND
  tls_server.zig        cert loading + socketpair handshake + ALPN
  quic_bridge.zig       end-to-end QUIC TLS handshake via Method callbacks
  tls_session.zig       session resumption + QUIC 0-RTT round-trip
  tls_keylog.zig        keylog callback fires with SSLKEYLOGFILE-format lines
examples/consumer/      standalone Zig package importing boringssl-zig
                        via build.zig.zon — `just test-consumer` exercises it
build.zig               main build script, dispatches on -Dboringssl-source
build_boringssl.zig     reads gen/sources.json, emits libcrypto/libssl
scripts/
  build-boringssl.sh    CMake driver (verification-only path)
  verify-prebuilt.sh    sha256 verification of CMake artifacts
deps/boringssl/         pinned submodule (CMake verification path only)
vendor/boringssl-prebuilt/<target>/
                        CMake outputs (only populated by `just boringssl-cmake`)
zig-pkg/                local Zig package cache (gitignored)
```

The `build.zig.zon` `.paths` whitelist deliberately omits `cli/`,
`examples/`, `tests/`, `deps/`, `vendor/`, and `scripts/` — so when a
downstream consumer fetches this package, they only get the library
sources plus the build scripts they need to compile BoringSSL.

## Tooling

`mise.toml` is the source of truth.

| Tool  | Pin     | Required for |
| ----- | ------- | --- |
| zig   | 0.16.0  | always |
| just  | 1.49.0  | always (workflow) |
| go    | 1.23.4  | only when running CMake path with `BORINGSSL_PREFIX` |
| cmake | 4.3.2   | only for the CMake verification path |
| ninja | 1.13.2  | only for the CMake verification path |

Plain consumers using `build.zig.zon` will only need zig itself.

## Symbol prefixing

`BORINGSSL_PREFIX=zbssl` is applied via the headers BoringSSL ships in
`include/openssl/prefix_symbols.h` and `include/openssl/asm_base.h`. No
generation step is required at build time — the prefix headers are
checked in upstream, and our build only needs to define the macro.

The wrapper API hides the prefix; only the `boringssl.raw` namespace
exposes prefixed names directly.

## Reproducibility

The CMake path stamps `SOURCE_DATE_EPOCH` from the BoringSSL commit
timestamp; two clean builds produce byte-identical archives whose
sha256s are recorded in `manifest.json` and verified by
`scripts/verify-prebuilt.sh`.

The native zig path is content-hash-cached by Zig itself.

## Consuming as a dependency

A working example lives at [examples/consumer/](examples/consumer/). Its
`build.zig.zon` declares a path dependency on this package:

```zig
.dependencies = .{
    .boringssl_zig = .{ .path = "../.." },
},
```

Its `build.zig` pulls the module:

```zig
const boringssl_dep = b.dependency("boringssl_zig", .{
    .target = target,
    .optimize = optimize,
});
exe_mod.addImport("boringssl", boringssl_dep.module("boringssl"));
```

Run `just test-consumer` to build it from a clean cache; it compiles
BoringSSL fresh (one-time ~8s on Apple Silicon) and runs three KATs to
prove the imported API works.

URL-based dependencies also work — BoringSSL itself is fetched as a
Zig package dependency:

```toml
# build.zig.zon (this repo)
.dependencies = .{
    .boringssl_src = .{
        .url = "https://boringssl.googlesource.com/boringssl/+archive/<commit>.tar.gz",
        .hash = "N-V-__8AAIz-yA1qPu2wxEtNpv8DTC2EpGepIdO2F1uU5M9k",
    },
},
```

`build_boringssl.zig` resolves source paths through the dependency
(`boringssl_src.path("crypto/aes/aes.cc")` etc.). `git submodule update`
is only required for the CMake verification path; consumers using the
native zig path don't need it.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs:

- **native test** on `ubuntu-latest`: `zig build test`, `zig build run-smoke`,
  and the consumer integration test.
- **cross**: matrix over `aarch64-macos`, `x86_64-macos`, `aarch64-linux-musl`,
  `x86_64-linux-musl` — link-only check via `zig build -Dtarget=...`.

The workflow is validated locally with [act](https://github.com/nektos/act):

```sh
just act-ci             # native job
just act-ci cross       # cross matrix
```

On Apple Silicon, `act` uses the arm64 variant of `catthehacker/ubuntu:act-latest`
(forcing `linux/amd64` triggers a Rosetta `bss_size overflow` during `zig translate-c`).

## What's next

- **Tag 0.1.0** in git and push (we have a local `v0.1.0` tag waiting on a
  remote).
- **CMake parity in CI**: today only the native zig path runs in CI. Adding
  the CMake comparison would catch upstream BoringSSL changes that break
  the verification path; cost is ~3 min extra build time and Go/CMake
  setup. Worth doing, not load-bearing.

Out of scope deliberately: Windows, FIPS mode, BoringSSL's full upstream
test suite. Open an issue if you need any of these.
