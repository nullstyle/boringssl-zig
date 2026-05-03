//! Single-block AES-ECB encryption.
//!
//! Used for QUIC header protection (RFC 9001 §5.4.3): a 16-byte sample is
//! AES-ECB-encrypted under the HP key, and the first 5 bytes of the
//! resulting block become the mask. **This is not a general-purpose
//! encryption API** — ECB is unsafe for messages longer than one block.
//! Use `crypto.aead.*` for that.

const std = @import("std");
const c = @import("c");

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

        pub fn init(key: *const Key) Self {
            var self: Self = .{ .inner = undefined };
            // BoringSSL: returns 0 on success. The only failure modes are
            // invalid `bits` (we hard-code 128/256) or null pointers (Zig
            // type system rules them out), so we never expect non-zero.
            const rc = c.zbssl_AES_set_encrypt_key(key, key_bits, &self.inner);
            std.debug.assert(rc == 0);
            return self;
        }

        pub fn encryptBlock(self: *const Self, in: *const Block16, out: *Block16) void {
            c.zbssl_AES_encrypt(in, out, &self.inner);
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

    const aes = Aes128.init(&key);
    var out: [16]u8 = undefined;
    aes.encryptBlock(&pt, &out);
    try std.testing.expectEqualSlices(u8, &want, &out);
}

test "AES-128 single block: FIPS 197 Appendix C.1" {
    const key = fromHex("000102030405060708090a0b0c0d0e0f");
    const pt = fromHex("00112233445566778899aabbccddeeff");
    const want = fromHex("69c4e0d86a7b0430d8cdb78070b4c55a");

    const aes = Aes128.init(&key);
    var out: [16]u8 = undefined;
    aes.encryptBlock(&pt, &out);
    try std.testing.expectEqualSlices(u8, &want, &out);
}

test "AES-256 single block: FIPS 197 Appendix C.3" {
    const key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const pt = fromHex("00112233445566778899aabbccddeeff");
    const want = fromHex("8ea2b7ca516745bfeafc49904b496089");

    const aes = Aes256.init(&key);
    var out: [16]u8 = undefined;
    aes.encryptBlock(&pt, &out);
    try std.testing.expectEqualSlices(u8, &want, &out);
}
