//! Known-answer tests for SHA-2 wrappers. Vectors from FIPS 180-4 and
//! NIST CAVS.

const std = @import("std");
const boringssl = @import("boringssl");

const Sha256 = boringssl.crypto.hash.Sha256;
const Sha384 = boringssl.crypto.hash.Sha384;
const Sha512 = boringssl.crypto.hash.Sha512;

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "SHA-256 empty input" {
    const got = Sha256.hash("");
    const want = comptime fromHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "SHA-256 \"abc\"" {
    const got = Sha256.hash("abc");
    const want = comptime fromHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "SHA-256 56-byte message (FIPS 180-4)" {
    const got = Sha256.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    const want = comptime fromHex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "SHA-256 streaming over 'a' x 1_000_000" {
    var ctx = Sha256.init();
    var i: usize = 0;
    var chunk: [1024]u8 = @splat('a');
    while (i < 1_000_000) : (i += chunk.len) {
        const remaining = 1_000_000 - i;
        const n = @min(remaining, chunk.len);
        ctx.update(chunk[0..n]);
    }
    const got = ctx.finalDigest();
    const want = comptime fromHex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "SHA-384 \"abc\"" {
    const got = Sha384.hash("abc");
    const want = comptime fromHex("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "SHA-512 \"abc\"" {
    const got = Sha512.hash("abc");
    const want = comptime fromHex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "SHA-512 empty" {
    const got = Sha512.hash("");
    const want = comptime fromHex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    try std.testing.expectEqualSlices(u8, &want, &got);
}
