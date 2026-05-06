//! HKDF (HMAC-based Key Derivation Function) per RFC 5869.
//!
//! Two operations: extract (random IKM + salt → fixed-size PRK) and expand
//! (PRK + info + length → output keying material). RFC 9001 §5.2 derives
//! all QUIC initial keys via HKDF-SHA-256, so HkdfSha256 is the workhorse.

const std = @import("std");
const c = @import("c");
const hash_mod = @import("hash.zig");

pub const Algorithm = hash_mod.Algorithm;

pub const Error = error{
    /// `prk.len < prk_len` or `dst.len > 255 * prk_len`. Caller violated
    /// an RFC 5869 precondition.
    InvalidLength,
    /// BoringSSL returned a non-success status. No internal detail is
    /// propagated.
    KdfFailed,
};

pub const HkdfSha256 = Hkdf(.sha256);
pub const HkdfSha384 = Hkdf(.sha384);
pub const HkdfSha512 = Hkdf(.sha512);

pub fn Hkdf(comptime alg: Algorithm) type {
    return struct {
        pub const algorithm = alg;
        pub const prk_len = Algorithm.digestSize(alg);
        pub const Prk = [prk_len]u8;
        pub const max_expand_len: usize = 255 * prk_len;

        fn evpMd() ?*const c.EVP_MD {
            return switch (alg) {
                .sha256 => c.zbssl_EVP_sha256(),
                .sha384 => c.zbssl_EVP_sha384(),
                .sha512 => c.zbssl_EVP_sha512(),
            };
        }

        /// HKDF-Extract per RFC 5869 §2.2. Returns the pseudorandom key.
        ///
        /// `salt` may be empty (RFC 5869 says implementations should treat
        /// an empty salt as `[0; HashLen]`); BoringSSL handles this.
        pub fn extract(salt: []const u8, ikm: []const u8) Error!Prk {
            var out: Prk = undefined;
            var out_len: usize = 0;
            const ok = c.zbssl_HKDF_extract(
                &out,
                &out_len,
                evpMd(),
                ikm.ptr,
                ikm.len,
                salt.ptr,
                salt.len,
            );
            if (ok != 1 or out_len != prk_len) return Error.KdfFailed;
            return out;
        }

        /// HKDF-Expand per RFC 5869 §2.3. Writes `dst.len` bytes into `dst`.
        ///
        /// Returns `Error.InvalidLength` if `prk.len < prk_len` or
        /// `dst.len > 255 * prk_len`. Callers typically pass the output
        /// of `extract` as `prk`.
        pub fn expand(prk: []const u8, info: []const u8, dst: []u8) Error!void {
            if (prk.len < prk_len) return Error.InvalidLength;
            if (dst.len > max_expand_len) return Error.InvalidLength;
            const ok = c.zbssl_HKDF_expand(
                dst.ptr,
                dst.len,
                evpMd(),
                prk.ptr,
                prk.len,
                info.ptr,
                info.len,
            );
            if (ok != 1) return Error.KdfFailed;
        }
    };
}

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "HKDF-SHA-256 extract: RFC 5869 test case 1 PRK" {
    const ikm = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = fromHex("000102030405060708090a0b0c");
    const got = try HkdfSha256.extract(&salt, &ikm);
    const want = fromHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "HKDF-SHA-256 expand: RFC 5869 test case 1 OKM" {
    const prk = fromHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    const info = fromHex("f0f1f2f3f4f5f6f7f8f9");
    var okm: [42]u8 = undefined;
    try HkdfSha256.expand(&prk, &info, &okm);
    const want = fromHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    try std.testing.expectEqualSlices(u8, &want, &okm);
}

test "HKDF-SHA-256 extract: RFC 5869 test case 3 (zero salt)" {
    const ikm = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = "";
    const got = try HkdfSha256.extract(salt, &ikm);
    const want = fromHex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "HKDF-SHA-256 extract: RFC 9001 §A.1 QUIC v1 initial_secret" {
    // QUIC v1 uses a fixed initial salt and the connection's DCID as IKM.
    // initial_secret = HKDF-Extract(initial_salt_v1, dcid).
    const initial_salt_v1 = fromHex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    const dcid = fromHex("8394c8f03e515708");
    const got = try HkdfSha256.extract(&initial_salt_v1, &dcid);
    const want = fromHex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "HKDF-SHA-256 expand rejects oversize output" {
    const prk = @as([HkdfSha256.prk_len]u8, @splat(0x01));
    var huge: [HkdfSha256.max_expand_len + 1]u8 = undefined;
    try std.testing.expectError(Error.InvalidLength, HkdfSha256.expand(&prk, "", &huge));
}

test "HKDF-SHA-256 expand rejects short PRK" {
    const short_prk: [HkdfSha256.prk_len - 1]u8 = @splat(0x02);
    var dst: [16]u8 = undefined;
    try std.testing.expectError(Error.InvalidLength, HkdfSha256.expand(&short_prk, "", &dst));
}
