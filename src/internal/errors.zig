const std = @import("std");
const c = @import("c");

pub const Error = error{
    BoringSSL,
    OutOfMemory,
};

/// Drain the BoringSSL error queue and return the most recent error.
/// Returns null if the queue is empty.
pub fn lastError() ?u32 {
    const code = c.zbssl_ERR_get_error();
    if (code == 0) return null;
    return @intCast(code);
}

/// Drain all errors from BoringSSL's per-thread queue.
pub fn clearAll() void {
    while (c.zbssl_ERR_get_error() != 0) {}
}

/// Format the most recent BoringSSL error into the given buffer.
pub fn lastMessage(buffer: []u8) []const u8 {
    const code = c.zbssl_ERR_peek_last_error();
    if (code == 0 or buffer.len == 0) return buffer[0..0];
    c.zbssl_ERR_error_string_n(code, buffer.ptr, buffer.len);
    const term = std.mem.indexOfScalar(u8, buffer, 0) orelse buffer.len;
    return buffer[0..term];
}

/// Pop one error off the per-thread BoringSSL error queue and
/// format it into a heap-allocated string. Returns null if the
/// queue was empty. Caller frees with `allocator.free(...)`.
pub fn popErrorString(allocator: std.mem.Allocator) !?[]u8 {
    const code = c.zbssl_ERR_get_error();
    if (code == 0) return null;
    var buf: [256]u8 = undefined;
    _ = c.zbssl_ERR_error_string_n(code, &buf, buf.len);
    const term = std.mem.indexOfScalar(u8, &buf, 0) orelse buf.len;
    return try allocator.dupe(u8, buf[0..term]);
}

/// Like `popErrorString` but writes into a caller-provided buffer.
/// Returns the populated slice (a sub-slice of `buf`), or null when
/// the queue is empty.
pub fn popErrorStringInto(buf: []u8) ?[]const u8 {
    const code = c.zbssl_ERR_get_error();
    if (code == 0) return null;
    if (buf.len == 0) return buf[0..0];
    _ = c.zbssl_ERR_error_string_n(code, buf.ptr, buf.len);
    const term = std.mem.indexOfScalar(u8, buf, 0) orelse buf.len;
    return buf[0..term];
}

test "popErrorString returns null on empty queue" {
    clearAll();
    const got = try popErrorString(std.testing.allocator);
    try std.testing.expectEqual(@as(?[]u8, null), got);
}

test "popErrorString returns populated string after BoringSSL pushes one" {
    clearAll();
    // Trigger a deterministic error: ask the PEM parser to read an
    // X.509 cert out of a buffer that obviously isn't PEM.
    const garbage = "not a PEM-encoded certificate";
    const bio = c.zbssl_BIO_new_mem_buf(garbage.ptr, @intCast(garbage.len));
    defer _ = c.zbssl_BIO_free(bio);
    const cert = c.zbssl_PEM_read_bio_X509(bio, null, null, null);
    try std.testing.expectEqual(@as(?*c.X509, null), cert);

    const msg = try popErrorString(std.testing.allocator);
    defer if (msg) |m| std.testing.allocator.free(m);
    try std.testing.expect(msg != null);
    try std.testing.expect(msg.?.len > 0);
    // The remainder of the queue should now be drained (just the
    // one error pushed by the failing parse).
    clearAll();
}
