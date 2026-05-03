//! Known-answer tests for HMAC-SHA-2 wrappers. Vectors from RFC 4231.

const std = @import("std");
const boringssl = @import("boringssl");

const HmacSha256 = boringssl.crypto.hmac.HmacSha256;
const HmacSha384 = boringssl.crypto.hmac.HmacSha384;
const HmacSha512 = boringssl.crypto.hmac.HmacSha512;

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "HMAC-SHA-256 RFC 4231 #1: key=0x0b*20, data=\"Hi There\"" {
    const key = [_]u8{0x0b} ** 20;
    const got = HmacSha256.auth(&key, "Hi There");
    const want = comptime fromHex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "HMAC-SHA-256 RFC 4231 #2: key=\"Jefe\"" {
    const got = HmacSha256.auth("Jefe", "what do ya want for nothing?");
    const want = comptime fromHex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "HMAC-SHA-256 RFC 4231 #4: keyed 25, data=0xcd*50" {
    var key: [25]u8 = undefined;
    for (&key, 0..) |*k, i| k.* = @intCast(i + 1);
    const data = [_]u8{0xcd} ** 50;
    const got = HmacSha256.auth(&key, &data);
    const want = comptime fromHex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "HMAC-SHA-384 RFC 4231 #1" {
    const key = [_]u8{0x0b} ** 20;
    const got = HmacSha384.auth(&key, "Hi There");
    const want = comptime fromHex("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "HMAC-SHA-512 RFC 4231 #1" {
    const key = [_]u8{0x0b} ** 20;
    const got = HmacSha512.auth(&key, "Hi There");
    const want = comptime fromHex("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "HMAC-SHA-256 streaming matches one-shot" {
    const key = "test-key-bytes";
    var h = HmacSha256.init(key);
    defer h.deinit();
    h.update("hello, ");
    h.update("world!");
    const streamed = h.finalDigest();
    const oneshot = HmacSha256.auth(key, "hello, world!");
    try std.testing.expectEqualSlices(u8, &oneshot, &streamed);
}
