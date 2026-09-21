//! PEM encode and decode through memory BIOs. BoringSSL's `BIO_new_file`
//! writes to the process's current working directory, which is wrong for
//! any caller holding a directory handle; these functions return and
//! accept bytes, and the caller does file I/O.

const std = @import("std");
const c = @import("c");

pub const Error = error{ PemEncode, PemDecode, OutOfMemory };

/// Encode an X509 certificate as PEM, allocated with `gpa`.
pub fn encodeCertificate(gpa: std.mem.Allocator, cert: *c.X509) Error![]u8 {
    const bio = c.zbssl_BIO_new(c.zbssl_BIO_s_mem()) orelse return Error.PemEncode;
    defer _ = c.zbssl_BIO_free(bio);
    if (c.zbssl_PEM_write_bio_X509(bio, cert) != 1) return Error.PemEncode;
    return bioBytes(gpa, bio);
}

/// Encode a private key as PEM, allocated with `gpa`.
pub fn encodePrivateKey(gpa: std.mem.Allocator, pkey: *c.EVP_PKEY) Error![]u8 {
    const bio = c.zbssl_BIO_new(c.zbssl_BIO_s_mem()) orelse return Error.PemEncode;
    defer _ = c.zbssl_BIO_free(bio);
    if (c.zbssl_PEM_write_bio_PrivateKey(bio, pkey, null, null, 0, null, null) != 1) return Error.PemEncode;
    return bioBytes(gpa, bio);
}

/// Decode a PEM certificate. The returned X509 is owned by the caller.
pub fn decodeCertificate(pem: []const u8) Error!*c.X509 {
    const bio = c.zbssl_BIO_new_mem_buf(pem.ptr, @intCast(pem.len)) orelse return Error.PemDecode;
    defer _ = c.zbssl_BIO_free(bio);
    return c.zbssl_PEM_read_bio_X509(bio, null, null, null) orelse Error.PemDecode;
}

/// Decode a PEM private key. The returned EVP_PKEY is owned by the caller.
pub fn decodePrivateKey(pem: []const u8) Error!*c.EVP_PKEY {
    const bio = c.zbssl_BIO_new_mem_buf(pem.ptr, @intCast(pem.len)) orelse return Error.PemDecode;
    defer _ = c.zbssl_BIO_free(bio);
    return c.zbssl_PEM_read_bio_PrivateKey(bio, null, null, null) orelse Error.PemDecode;
}

fn bioBytes(gpa: std.mem.Allocator, bio: *c.BIO) Error![]u8 {
    var data: ?[*]u8 = null;
    const len = c.zbssl_BIO_get_mem_data(bio, &data);
    if (len <= 0 or data == null) return Error.PemEncode;
    return gpa.dupe(u8, data.?[0..@intCast(len)]);
}

test "encode and decode round-trip a certificate" {
    const pkey = @import("pkey.zig");
    const x509 = @import("x509.zig");
    const gpa = std.testing.allocator;

    var key = try pkey.generateEcP256();
    defer key.deinit();
    var ca = try x509.CertificateBuilder.init()
        .selfSigned("Test CA")
        .ca()
        .build(&key);
    defer ca.deinit();

    const pem = try encodeCertificate(gpa, ca.cert);
    defer gpa.free(pem);
    try std.testing.expect(std.mem.startsWith(u8, pem, "-----BEGIN CERTIFICATE-----"));

    const decoded = try decodeCertificate(pem);
    defer c.zbssl_X509_free(decoded);
}

test "encode and decode round-trip a private key" {
    const pkey_mod = @import("pkey.zig");
    const gpa = std.testing.allocator;

    var key = try pkey_mod.generateEcP256();
    defer key.deinit();

    const pem = try encodePrivateKey(gpa, key.pkey);
    defer gpa.free(pem);
    try std.testing.expect(std.mem.startsWith(u8, pem, "-----BEGIN "));

    const decoded = try decodePrivateKey(pem);
    defer c.zbssl_EVP_PKEY_free(decoded);
}
