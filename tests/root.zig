test {
    _ = @import("kat_sha2.zig");
    _ = @import("kat_hmac_sha2.zig");
    _ = @import("kat_rand.zig");
    _ = @import("tls_server.zig");
    _ = @import("quic_bridge.zig");
    _ = @import("tls_session.zig");
    _ = @import("tls_keylog.zig");
    _ = @import("tls_early_data_callback.zig");
}
