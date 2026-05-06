const std = @import("std");
const Io = std.Io;
const boringssl = @import("boringssl");

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var stdout_buffer: [512]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    const message = "hello from zig + boringssl";
    const digest = try boringssl.crypto.hash.Sha256.hash(message);

    try stdout.print("sha256(\"{s}\") = ", .{message});
    for (digest) |byte| try stdout.print("{x:0>2}", .{byte});
    try stdout.print("\n", .{});

    var rand_buf: [16]u8 = undefined;
    try boringssl.crypto.rand.fillBytes(&rand_buf);
    try stdout.print("random16 = ", .{});
    for (rand_buf) |byte| try stdout.print("{x:0>2}", .{byte});
    try stdout.print("\n", .{});

    try stdout.flush();
}
