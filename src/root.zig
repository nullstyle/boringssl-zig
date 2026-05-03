//! boringssl-zig: a Zig wrapper around BoringSSL.
//!
//! The high-level `crypto` namespace is the supported public surface.
//! `raw` exposes the translate-c output for advanced users; symbol names
//! there carry the BoringSSL prefix (e.g. `raw.zbssl_SHA256`) and the
//! shape may shift across releases.

pub const crypto = struct {
    pub const hash = @import("crypto/hash.zig");
    pub const hmac = @import("crypto/hmac.zig");
    pub const rand = @import("crypto/rand.zig");
    pub const aead = @import("crypto/aead.zig");
    pub const kdf = @import("crypto/kdf.zig");
    pub const aes = @import("crypto/aes.zig");
};

pub const tls = @import("tls.zig");

pub const errors = @import("internal/errors.zig");

pub const raw = @import("c");

test {
    _ = crypto.hash;
    _ = crypto.hmac;
    _ = crypto.rand;
    _ = crypto.aead;
    _ = crypto.kdf;
    _ = crypto.aes;
    _ = tls;
    _ = errors;
}
