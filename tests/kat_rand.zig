const std = @import("std");
const boringssl = @import("boringssl");

test "rand.fillBytes 1024 bytes is plausibly random (entropy heuristic)" {
    var buf: [1024]u8 = @splat(0);
    try boringssl.crypto.rand.fillBytes(&buf);

    // Heuristic: byte histogram should be reasonably flat. Reject if any
    // byte value occurs more than 16x its expected count.
    var hist: [256]u32 = @splat(0);
    for (buf) |b| hist[b] += 1;

    const expected = buf.len / 256;
    for (hist) |count| {
        try std.testing.expect(count <= 16 * (expected + 1));
    }
}

test "rand.fillBytes two consecutive calls differ" {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    try boringssl.crypto.rand.fillBytes(&a);
    try boringssl.crypto.rand.fillBytes(&b);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}
