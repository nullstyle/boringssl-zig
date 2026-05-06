//! ChaCha20 stream cipher.
//!
//! Wraps BoringSSL's `CRYPTO_chacha_20`. Provides:
//! - `xor`: full stream cipher operation (XOR plaintext/ciphertext
//!   with a ChaCha20 keystream).
//! - `quicHpMask`: convenience for QUIC header protection per
//!   RFC 9001 §5.4.4. Treats the first 4 bytes of the sample as a
//!   little-endian counter and the last 12 bytes as the nonce, then
//!   produces 5 mask bytes.

const std = @import("std");
const c = @import("c");

pub const key_len: usize = 32;
pub const nonce_len: usize = 12;
pub const Key = [key_len]u8;
pub const Nonce = [nonce_len]u8;

pub const Error = error{
    /// `output.len != input.len`. Caller violated the keystream contract.
    LengthMismatch,
};

/// Run the ChaCha20 keystream over `input` and write the result to
/// `output`. `output.len` must equal `input.len`. `counter` selects
/// which 64-byte block of the keystream to start at; 0 is the first
/// block of the stream.
pub fn xor(
    output: []u8,
    input: []const u8,
    key: *const Key,
    nonce: *const Nonce,
    counter: u32,
) Error!void {
    if (output.len != input.len) return Error.LengthMismatch;
    c.zbssl_CRYPTO_chacha_20(output.ptr, input.ptr, input.len, key, nonce, counter);
}

/// QUIC header-protection mask (RFC 9001 §5.4.4):
///   counter = LE u32 from sample[0..4]
///   nonce   = sample[4..16]
///   mask    = first 5 bytes of ChaCha20(key, counter, nonce, all-zeros)
pub fn quicHpMask(key: *const Key, sample: *const [16]u8) [5]u8 {
    const counter = std.mem.readInt(u32, sample[0..4], .little);
    var nonce: Nonce = undefined;
    @memcpy(&nonce, sample[4..16]);
    var mask: [5]u8 = undefined;
    const zeros: [5]u8 = @splat(0);
    c.zbssl_CRYPTO_chacha_20(&mask, &zeros, mask.len, key, &nonce, counter);
    return mask;
}

// -- tests ---------------------------------------------------------------

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "ChaCha20 RFC 8439 §2.4.2 test vector" {
    // RFC 8439 §2.4.2: encrypt the well-known plaintext under the
    // canonical (key, nonce, counter=1) and assert the published
    // ciphertext matches.
    const key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const nonce = fromHex("000000000000004a00000000");
    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const want = fromHex(
        "6e2e359a2568f98041ba0728dd0d6981" ++
        "e97e7aec1d4360c20a27afccfd9fae0b" ++
        "f91b65c5524733ab8f593dabcd62b357" ++
        "1639d624e65152ab8f530c359f0861d8" ++
        "07ca0dbf500d6a6156a38e088a22b65e" ++
        "52bc514d16ccf806818ce91ab7793736" ++
        "5af90bbf74a35be6b40b8eedf2785e42" ++
        "874d",
    );
    var got: [114]u8 = undefined;
    try xor(&got, plaintext, &key, &nonce, 1);
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "quicHpMask: identity check via xor with sample" {
    // Synthetic round-trip: the mask is deterministic given
    // (key, sample), so two calls produce the same bytes.
    const key: Key = @splat(0x42);
    var sample: [16]u8 = undefined;
    var i: u8 = 0;
    while (i < 16) : (i += 1) sample[i] = i;
    const a = quicHpMask(&key, &sample);
    const b = quicHpMask(&key, &sample);
    try std.testing.expectEqualSlices(u8, &a, &b);
    // And it's not all zeros (would imply broken cipher).
    var any_nonzero = false;
    for (a) |byte| if (byte != 0) {
        any_nonzero = true;
        break;
    };
    try std.testing.expect(any_nonzero);
}

test "xor is involutive (encrypt twice = identity)" {
    const key: Key = @splat(0xa5);
    const nonce: Nonce = @splat(0x33);
    const plaintext = "the quick brown fox jumps over the lazy dog";
    var ct: [plaintext.len]u8 = undefined;
    try xor(&ct, plaintext, &key, &nonce, 0);
    var pt: [plaintext.len]u8 = undefined;
    try xor(&pt, &ct, &key, &nonce, 0);
    try std.testing.expectEqualSlices(u8, plaintext, &pt);
}

test "xor returns LengthMismatch on caller mismatch" {
    const key: Key = @splat(0);
    const nonce: Nonce = @splat(0);
    var out: [4]u8 = undefined;
    const in: [3]u8 = @splat(0);
    try std.testing.expectError(Error.LengthMismatch, xor(&out, &in, &key, &nonce, 0));
}
