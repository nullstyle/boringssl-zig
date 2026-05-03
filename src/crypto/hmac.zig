const std = @import("std");
const c = @import("c");
const hash_mod = @import("hash.zig");

pub const Algorithm = hash_mod.Algorithm;

pub const HmacSha256 = Hmac(.sha256);
pub const HmacSha384 = Hmac(.sha384);
pub const HmacSha512 = Hmac(.sha512);

pub fn Hmac(comptime alg: Algorithm) type {
    return struct {
        const Self = @This();
        pub const algorithm = alg;
        pub const digest_size = Algorithm.digestSize(alg);
        pub const block_size = Algorithm.blockSize(alg);
        pub const Digest = [digest_size]u8;

        ctx: c.HMAC_CTX,

        fn evpMd() ?*const c.EVP_MD {
            return switch (alg) {
                .sha256 => c.zbssl_EVP_sha256(),
                .sha384 => c.zbssl_EVP_sha384(),
                .sha512 => c.zbssl_EVP_sha512(),
            };
        }

        pub fn init(key: []const u8) Self {
            var self: Self = .{ .ctx = undefined };
            c.zbssl_HMAC_CTX_init(&self.ctx);
            const ok = c.zbssl_HMAC_Init_ex(
                &self.ctx,
                key.ptr,
                key.len,
                evpMd(),
                null,
            );
            std.debug.assert(ok == 1);
            return self;
        }

        pub fn deinit(self: *Self) void {
            c.zbssl_HMAC_CTX_cleanup(&self.ctx);
        }

        pub fn update(self: *Self, data: []const u8) void {
            const ok = c.zbssl_HMAC_Update(&self.ctx, data.ptr, data.len);
            std.debug.assert(ok == 1);
        }

        pub fn finalDigest(self: *Self) Digest {
            var out: Digest = undefined;
            var out_len: c_uint = 0;
            const ok = c.zbssl_HMAC_Final(&self.ctx, &out, &out_len);
            std.debug.assert(ok == 1);
            std.debug.assert(out_len == digest_size);
            return out;
        }

        /// One-shot HMAC. Caller owns no resources.
        pub fn auth(key: []const u8, data: []const u8) Digest {
            var h = Self.init(key);
            defer h.deinit();
            h.update(data);
            return h.finalDigest();
        }
    };
}

test "HmacSha256 RFC 4231 test case 1" {
    const key = [_]u8{0x0b} ** 20;
    const got = HmacSha256.auth(&key, "Hi There");
    const want = [_]u8{
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    };
    try std.testing.expectEqualSlices(u8, &want, &got);
}
