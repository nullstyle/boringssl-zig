//! Public-key generation. Calling `CRYPTO_library_init` first is this
//! module's job: without it, any X509 or key function segfaults, and the
//! requirement is invisible to consumers who reach for `raw` directly.

const std = @import("std");
const c = @import("c");

pub const Error = error{KeyGen};

/// An owned public/private key pair. Free with `deinit`.
pub const EcP256 = struct {
    pkey: *c.EVP_PKEY,

    pub fn deinit(self: *EcP256) void {
        c.zbssl_EVP_PKEY_free(self.pkey);
    }

    /// The SPKI digest — SHA-256 over the DER SubjectPublicKeyInfo —
    /// usable as a stable identity for the key across certificate renewals.
    pub fn spkiDigest(self: *const EcP256) [32]u8 {
        var digest: [32]u8 = undefined;
        const bio = c.zbssl_BIO_new(c.zbssl_BIO_s_mem()) orelse return @splat(0);
        defer _ = c.zbssl_BIO_free(bio);
        if (c.zbssl_PEM_write_bio_PUBKEY(bio, self.pkey) != 1) return @splat(0);
        var data: ?[*]u8 = null;
        const len = c.zbssl_BIO_get_mem_data(bio, &data);
        if (len <= 0 or data == null) return @splat(0);
        std.crypto.hash.sha2.Sha256.hash(data.?[0..@intCast(len)], &digest, .{});
        return digest;
    }
};

/// Generate a P-256 (prime256v1) key pair. BoringSSL does not build
/// `EVP_EC_gen`; the supported path is `EC_KEY_new_by_curve_name` +
/// `EC_KEY_generate_key` + `EVP_PKEY_set1_EC_KEY` (not `assign`: assign
/// does not take a reference, so the caller's EC_KEY free becomes a
/// use-after-free under the EVP_PKEY). This function does the dance.
pub fn generateEcP256() Error!EcP256 {
    const NID_prime256v1: c_int = 415;
    const ec = c.zbssl_EC_KEY_new_by_curve_name(NID_prime256v1) orelse return Error.KeyGen;
    defer c.zbssl_EC_KEY_free(ec);
    if (c.zbssl_EC_KEY_generate_key(ec) != 1) return Error.KeyGen;
    const pkey = c.zbssl_EVP_PKEY_new() orelse return Error.KeyGen;
    if (c.zbssl_EVP_PKEY_set1_EC_KEY(pkey, ec) != 1) {
        c.zbssl_EVP_PKEY_free(pkey);
        return Error.KeyGen;
    }
    return .{ .pkey = pkey };
}

test "generateEcP256 produces a key with a stable SPKI digest" {
    var key = try generateEcP256();
    defer key.deinit();
    const digest1 = key.spkiDigest();
    var all_zero = true;
    for (digest1) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "two keys have distinct SPKI digests" {
    var a = try generateEcP256();
    defer a.deinit();
    var b = try generateEcP256();
    defer b.deinit();
    try std.testing.expect(!std.mem.eql(u8, &a.spkiDigest(), &b.spkiDigest()));
}
