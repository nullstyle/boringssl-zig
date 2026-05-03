const std = @import("std");
const c = @import("c");

pub const Error = error{RandFailed};

/// Fill the buffer with cryptographically secure random bytes from
/// BoringSSL's RNG (BCM-backed on FIPS builds, getrandom/arc4random elsewhere).
pub fn fillBytes(buffer: []u8) Error!void {
    if (buffer.len == 0) return;
    const ok = c.zbssl_RAND_bytes(buffer.ptr, buffer.len);
    if (ok != 1) return Error.RandFailed;
}

test "fillBytes produces non-zero output for non-trivial buffers" {
    var buf: [64]u8 = @splat(0);
    try fillBytes(&buf);

    var any_set: bool = false;
    for (buf) |b| {
        if (b != 0) {
            any_set = true;
            break;
        }
    }
    try std.testing.expect(any_set);
}

test "fillBytes accepts an empty slice without calling RAND_bytes" {
    var empty: [0]u8 = .{};
    try fillBytes(&empty);
}
