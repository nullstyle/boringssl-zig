//! Tiny consumer of boringssl-zig — proves the package boundary works:
//! we import "boringssl" via build.zig.zon and call into the wrapper
//! and the underlying BoringSSL crypto.

const std = @import("std");
const Io = std.Io;
const boringssl = @import("boringssl");

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var stdout_buf: [256]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    const message = "hello, world!";
    const digest = try boringssl.crypto.hash.Sha256.hash(message);

    try stdout.print("consumer says: sha256(\"{s}\") = ", .{message});
    for (digest) |byte| try stdout.print("{x:0>2}", .{byte});
    try stdout.print("\n", .{});

    try stdout.flush();
}

test "consumer can compute SHA-256 of empty input" {
    const digest = try boringssl.crypto.hash.Sha256.hash("");
    const want = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    try std.testing.expectEqualSlices(u8, &want, &digest);
}

test "consumer can compute HMAC-SHA-256" {
    const got = try boringssl.crypto.hmac.HmacSha256.auth("Jefe", "what do ya want for nothing?");
    const want = [_]u8{
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "consumer can pull random bytes" {
    var buf: [16]u8 = undefined;
    try boringssl.crypto.rand.fillBytes(&buf);
}
