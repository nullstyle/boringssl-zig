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
