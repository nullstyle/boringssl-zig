//! Single-block AES-ECB encryption and decryption.
//!
//! Used for QUIC header protection (RFC 9001 §5.4.3): a 16-byte sample is
//! AES-ECB-encrypted under the HP key, and the first 5 bytes of the
//! resulting block become the mask. The decrypt direction (added in
//! v0.6.0) supports QUIC-LB
//! ([draft-ietf-quic-load-balancers-21][quic-lb]) single-pass §5.5.1
//! load-balancer-side decoding, which inverts the §5.4.1 single-pass
//! encrypt the server uses to mint connection IDs.
//!
//! [quic-lb]: https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/
//!
//! **This is not a general-purpose encryption API** — ECB is unsafe for
//! messages longer than one block. Use `crypto.aead.*` for that.
//!
//! ## Encrypt vs decrypt schedules
//!
//! AES-128/256 use *different* round-key schedules for encrypt and
//! decrypt. `init` and `initDecrypt` populate the embedded `AES_KEY`
//! for one direction only; calling `encryptBlock` after `initDecrypt`
//! (or vice versa) produces undefined output without erroring. Use
//! the matched pair: `init` + `encryptBlock`, or `initDecrypt` +
//! `decryptBlock`.

const std = @import("std");
const c = @import("c");

pub const Error = error{
    /// BoringSSL returned a non-success status from `AES_set_encrypt_key`.
    /// Surfaces unexpected ABI drift; no internal detail is propagated.
    AesKeyInvalid,
};

pub const Aes128 = Block(128);
pub const Aes256 = Block(256);

pub fn Block(comptime key_bits: comptime_int) type {
    if (key_bits != 128 and key_bits != 256) {
        @compileError("Block requires key_bits 128 or 256");
    }
    return struct {
        const Self = @This();
        pub const key_size: usize = key_bits / 8;
        pub const block_size: usize = 16;
        pub const Key = [key_size]u8;
        pub const Block16 = [block_size]u8;

        inner: c.AES_KEY,

        pub fn init(key: *const Key) Error!Self {
            var self: Self = .{ .inner = undefined };
            // BoringSSL: returns 0 on success. The only documented
            // failure modes are invalid `bits` (we hard-code 128/256)
            // or null pointers (Zig's type system rules them out), but
            // surface a typed error rather than panic if BoringSSL ever
            // changes the contract.
            const rc = c.zbssl_AES_set_encrypt_key(key, key_bits, &self.inner);
            if (rc != 0) return Error.AesKeyInvalid;
            return self;
        }

        /// Initialise an `AES_KEY` for the **decrypt** direction.
        /// Same failure-mode contract as `init`, but the embedded
        /// schedule is set up via `AES_set_decrypt_key` so the cipher
        /// state can drive `decryptBlock`. Calling `encryptBlock` on
        /// a `Self` produced here is undefined behaviour — the
        /// schedules differ between the two directions.
        pub fn initDecrypt(key: *const Key) Error!Self {
            var self: Self = .{ .inner = undefined };
            const rc = c.zbssl_AES_set_decrypt_key(key, key_bits, &self.inner);
            if (rc != 0) return Error.AesKeyInvalid;
            return self;
        }

        pub fn encryptBlock(self: *const Self, in: *const Block16, out: *Block16) void {
            c.zbssl_AES_encrypt(in, out, &self.inner);
        }

        /// Decrypt a single 16-byte AES block. The receiver MUST have
        /// been built via `initDecrypt`; calling this on an `init`-
        /// constructed `Self` produces undefined output.
        pub fn decryptBlock(self: *const Self, in: *const Block16, out: *Block16) void {
            c.zbssl_AES_decrypt(in, out, &self.inner);
        }
    };
}

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "AES-128 single block: FIPS 197 Appendix B" {
    const key = fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    const pt = fromHex("3243f6a8885a308d313198a2e0370734");
    const want = fromHex("3925841d02dc09fbdc118597196a0b32");

    const aes = try Aes128.init(&key);
    var out: [16]u8 = undefined;
    aes.encryptBlock(&pt, &out);
    try std.testing.expectEqualSlices(u8, &want, &out);
}

test "AES-128 single block: FIPS 197 Appendix C.1" {
    const key = fromHex("000102030405060708090a0b0c0d0e0f");
    const pt = fromHex("00112233445566778899aabbccddeeff");
    const want = fromHex("69c4e0d86a7b0430d8cdb78070b4c55a");

    const aes = try Aes128.init(&key);
    var out: [16]u8 = undefined;
    aes.encryptBlock(&pt, &out);
    try std.testing.expectEqualSlices(u8, &want, &out);
}

test "AES-256 single block: FIPS 197 Appendix C.3" {
    const key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const pt = fromHex("00112233445566778899aabbccddeeff");
    const want = fromHex("8ea2b7ca516745bfeafc49904b496089");

    const aes = try Aes256.init(&key);
    var out: [16]u8 = undefined;
    aes.encryptBlock(&pt, &out);
    try std.testing.expectEqualSlices(u8, &want, &out);
}

test "AES-128 decrypt: FIPS 197 Appendix C.1 round-trip" {
    // §C.1 lists the encrypt direction; the decrypt direction is the
    // exact inverse — feeding the ciphertext through `decryptBlock`
    // under the same key recovers the plaintext byte-for-byte.
    const key = fromHex("000102030405060708090a0b0c0d0e0f");
    const ct = fromHex("69c4e0d86a7b0430d8cdb78070b4c55a");
    const want = fromHex("00112233445566778899aabbccddeeff");

    const aes = try Aes128.initDecrypt(&key);
    var out: [16]u8 = undefined;
    aes.decryptBlock(&ct, &out);
    try std.testing.expectEqualSlices(u8, &want, &out);
}

test "AES-256 decrypt: FIPS 197 Appendix C.3 round-trip" {
    const key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const ct = fromHex("8ea2b7ca516745bfeafc49904b496089");
    const want = fromHex("00112233445566778899aabbccddeeff");

    const aes = try Aes256.initDecrypt(&key);
    var out: [16]u8 = undefined;
    aes.decryptBlock(&ct, &out);
    try std.testing.expectEqualSlices(u8, &want, &out);
}

test "AES-128: encrypt/decrypt round-trip on a random plaintext" {
    // Reinforces the invariant that the encrypt and decrypt schedules
    // are inverses: encrypting then decrypting under the same key
    // returns the original bytes for any input, not just the FIPS
    // vectors.
    const key = fromHex("8f95f09245765f80256934e50c66207f");
    const pt = fromHex("ed793a51d49b8f5fee080dbf48c0d1e5");

    const enc = try Aes128.init(&key);
    var ct: [16]u8 = undefined;
    enc.encryptBlock(&pt, &ct);

    const dec = try Aes128.initDecrypt(&key);
    var out: [16]u8 = undefined;
    dec.decryptBlock(&ct, &out);
    try std.testing.expectEqualSlices(u8, &pt, &out);
}
