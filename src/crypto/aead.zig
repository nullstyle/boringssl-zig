//! Authenticated encryption with associated data (AEAD).
//!
//! Wraps BoringSSL's `EVP_AEAD_CTX` for AES-GCM and ChaCha20-Poly1305 — the
//! three AEADs required by TLS 1.3 / RFC 9001 packet protection. All three
//! use a 12-byte nonce and a 16-byte authentication tag.

const std = @import("std");
const c = @import("c");

pub const Algorithm = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,

    pub fn keyLen(alg: Algorithm) usize {
        return switch (alg) {
            .aes_128_gcm => 16,
            .aes_256_gcm => 32,
            .chacha20_poly1305 => 32,
        };
    }

    pub fn nonceLen(alg: Algorithm) usize {
        _ = alg;
        return 12;
    }

    pub fn tagLen(alg: Algorithm) usize {
        _ = alg;
        return 16;
    }
};

pub const Error = error{
    InitFailed,
    SealFailed,
    /// Authentication failed. Either the ciphertext was modified, the AD
    /// doesn't match, or the wrong key/nonce was used. Treat as untrusted.
    Auth,
    OutputTooSmall,
};

pub const AesGcm128 = Aead(.aes_128_gcm);
pub const AesGcm256 = Aead(.aes_256_gcm);
pub const ChaCha20Poly1305 = Aead(.chacha20_poly1305);

pub fn Aead(comptime alg: Algorithm) type {
    return struct {
        const Self = @This();
        pub const algorithm = alg;
        pub const key_len = Algorithm.keyLen(alg);
        pub const nonce_len = Algorithm.nonceLen(alg);
        pub const tag_len = Algorithm.tagLen(alg);
        pub const Key = [key_len]u8;
        pub const Nonce = [nonce_len]u8;

        ctx: *c.EVP_AEAD_CTX,

        fn aeadFn() ?*const c.EVP_AEAD {
            return switch (alg) {
                .aes_128_gcm => c.zbssl_EVP_aead_aes_128_gcm(),
                .aes_256_gcm => c.zbssl_EVP_aead_aes_256_gcm(),
                .chacha20_poly1305 => c.zbssl_EVP_aead_chacha20_poly1305(),
            };
        }

        pub fn init(key: *const Key) Error!Self {
            const ctx = c.zbssl_EVP_AEAD_CTX_new(aeadFn(), key, key_len, 0) orelse
                return Error.InitFailed;
            return .{ .ctx = ctx };
        }

        pub fn deinit(self: *Self) void {
            c.zbssl_EVP_AEAD_CTX_free(self.ctx);
            self.ctx = undefined;
        }

        /// Encrypt `plaintext` with associated data `ad` under `nonce`.
        /// Writes ciphertext + 16-byte tag into `dst`; returns bytes written
        /// (always plaintext.len + tag_len).
        ///
        /// `dst.len` must be at least `plaintext.len + tag_len`.
        /// `nonce` must be unique per call under this key. Reuse breaks
        /// confidentiality and integrity.
        pub fn seal(
            self: *const Self,
            dst: []u8,
            nonce: *const Nonce,
            ad: []const u8,
            plaintext: []const u8,
        ) Error!usize {
            if (dst.len < plaintext.len + tag_len) return Error.OutputTooSmall;
            var out_len: usize = 0;
            const ok = c.zbssl_EVP_AEAD_CTX_seal(
                self.ctx,
                dst.ptr,
                &out_len,
                dst.len,
                nonce,
                nonce_len,
                plaintext.ptr,
                plaintext.len,
                ad.ptr,
                ad.len,
            );
            if (ok != 1) return Error.SealFailed;
            return out_len;
        }

        /// Decrypt and verify `ciphertext` (ciphertext || tag) with `ad` and `nonce`.
        /// Writes plaintext into `dst`; returns plaintext length on success.
        ///
        /// `dst.len` must be at least `ciphertext.len - tag_len`. On
        /// `error.Auth`, `dst` contents are unspecified — do NOT use them.
        pub fn open(
            self: *const Self,
            dst: []u8,
            nonce: *const Nonce,
            ad: []const u8,
            ciphertext: []const u8,
        ) Error!usize {
            if (ciphertext.len < tag_len) return Error.Auth;
            if (dst.len < ciphertext.len - tag_len) return Error.OutputTooSmall;
            var out_len: usize = 0;
            const ok = c.zbssl_EVP_AEAD_CTX_open(
                self.ctx,
                dst.ptr,
                &out_len,
                dst.len,
                nonce,
                nonce_len,
                ciphertext.ptr,
                ciphertext.len,
                ad.ptr,
                ad.len,
            );
            if (ok != 1) return Error.Auth;
            return out_len;
        }
    };
}

test "AesGcm128 round-trip" {
    const key: AesGcm128.Key = @splat(0x42);
    const nonce: AesGcm128.Nonce = @splat(0x01);
    const ad = "associated";
    const pt = "the quick brown fox";

    var aead = try AesGcm128.init(&key);
    defer aead.deinit();

    var ct: [pt.len + AesGcm128.tag_len]u8 = undefined;
    const ct_len = try aead.seal(&ct, &nonce, ad, pt);
    try std.testing.expectEqual(@as(usize, pt.len + AesGcm128.tag_len), ct_len);

    var pt_out: [pt.len]u8 = undefined;
    const pt_len = try aead.open(&pt_out, &nonce, ad, ct[0..ct_len]);
    try std.testing.expectEqualSlices(u8, pt, pt_out[0..pt_len]);
}

test "AesGcm256 round-trip" {
    const key: AesGcm256.Key = @splat(0xab);
    const nonce: AesGcm256.Nonce = @splat(0xcd);
    var aead = try AesGcm256.init(&key);
    defer aead.deinit();
    var buf: [64]u8 = undefined;
    const ct_len = try aead.seal(&buf, &nonce, "", "hello");
    var out: [5]u8 = undefined;
    const pt_len = try aead.open(&out, &nonce, "", buf[0..ct_len]);
    try std.testing.expectEqualSlices(u8, "hello", out[0..pt_len]);
}

test "ChaCha20Poly1305 round-trip" {
    const key: ChaCha20Poly1305.Key = @splat(0x55);
    const nonce: ChaCha20Poly1305.Nonce = @splat(0x07);
    var aead = try ChaCha20Poly1305.init(&key);
    defer aead.deinit();
    var buf: [64]u8 = undefined;
    const ct_len = try aead.seal(&buf, &nonce, "ad", "msg");
    var out: [3]u8 = undefined;
    const pt_len = try aead.open(&out, &nonce, "ad", buf[0..ct_len]);
    try std.testing.expectEqualSlices(u8, "msg", out[0..pt_len]);
}

test "open rejects modified ciphertext" {
    const key: AesGcm128.Key = @splat(0x11);
    const nonce: AesGcm128.Nonce = @splat(0x22);
    var aead = try AesGcm128.init(&key);
    defer aead.deinit();
    var buf: [32]u8 = undefined;
    const ct_len = try aead.seal(&buf, &nonce, "", "secret");
    buf[0] ^= 1;
    var out: [16]u8 = undefined;
    try std.testing.expectError(Error.Auth, aead.open(&out, &nonce, "", buf[0..ct_len]));
}

test "open rejects wrong AD" {
    const key: AesGcm128.Key = @splat(0x33);
    const nonce: AesGcm128.Nonce = @splat(0x44);
    var aead = try AesGcm128.init(&key);
    defer aead.deinit();
    var buf: [32]u8 = undefined;
    const ct_len = try aead.seal(&buf, &nonce, "right-ad", "msg");
    var out: [16]u8 = undefined;
    try std.testing.expectError(Error.Auth, aead.open(&out, &nonce, "wrong-ad", buf[0..ct_len]));
}
