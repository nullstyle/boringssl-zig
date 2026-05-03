//! HTTPS smoke executable. Connects to a real host (default
//! `example.com:443`) and prints the HTTP status line. Used to verify
//! that the TLS handshake, certificate verification, and SSL_read/write
//! all work end to end.
//!
//! Usage:
//!   tls-smoke [hostname] [port] [ca-file]
//!
//! Defaults: example.com 443 /etc/ssl/cert.pem (macOS / LibreSSL convention).

const std = @import("std");
const Io = std.Io;
const boringssl = @import("boringssl");

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try init.minimal.args.toSlice(arena);

    const host_str = if (args.len > 1) args[1] else "example.com";
    const port: u16 = if (args.len > 2)
        std.fmt.parseInt(u16, args[2], 10) catch 443
    else
        443;
    const ca_path: [:0]const u8 = if (args.len > 3)
        try arena.dupeZ(u8, args[3])
    else
        "/etc/ssl/cert.pem";

    const host = try arena.dupeZ(u8, host_str);

    try stdout.print("connecting to {s}:{d} ...\n", .{ host, port });
    try stdout.flush();

    const host_name = try Io.net.HostName.init(host);
    const stream = try host_name.connect(io, port, .{ .mode = .stream });
    defer stream.close(io);

    var ctx = try boringssl.tls.Context.initClient(.{
        .verify = .{ .ca_file = ca_path },
    });
    defer ctx.deinit();

    var conn = try ctx.newClient(.{
        .hostname = host,
        .fd = stream.socket.handle,
    });
    defer conn.deinit();

    try conn.handshake();

    try stdout.print("connected: {s} {s}\n", .{
        conn.protocolVersion(),
        conn.cipherName(),
    });

    var request_buf: [256]u8 = undefined;
    const request = try std.fmt.bufPrint(
        &request_buf,
        "GET / HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\nUser-Agent: boringssl-zig\r\n\r\n",
        .{host},
    );
    try conn.writeAll(request);

    var response_buf: [4096]u8 = undefined;
    const n = conn.read(&response_buf) catch |err| switch (err) {
        error.ConnectionClosed => 0,
        else => return err,
    };

    if (n == 0) {
        try stdout.print("(no response data)\n", .{});
    } else {
        const status_end = std.mem.indexOf(u8, response_buf[0..n], "\r\n") orelse n;
        try stdout.print("response: {s}\n", .{response_buf[0..status_end]});
    }

    _ = conn.shutdown() catch {};

    try stdout.flush();
    return 0;
}
