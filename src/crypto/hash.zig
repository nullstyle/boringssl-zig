const std = @import("std");
const c = @import("c");

pub const Algorithm = enum {
    sha256,
    sha384,
    sha512,

    pub fn DigestOf(comptime alg: Algorithm) type {
        return [digestSize(alg)]u8;
    }

    pub fn digestSize(alg: Algorithm) usize {
        return switch (alg) {
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
        };
    }

    pub fn blockSize(alg: Algorithm) usize {
        return switch (alg) {
            .sha256 => 64,
            .sha384, .sha512 => 128,
        };
    }
};

pub const Sha256 = Hash(.sha256);
pub const Sha384 = Hash(.sha384);
pub const Sha512 = Hash(.sha512);

pub fn Hash(comptime alg: Algorithm) type {
    return struct {
        const Self = @This();
        pub const algorithm = alg;
        pub const digest_size = Algorithm.digestSize(alg);
        pub const block_size = Algorithm.blockSize(alg);
        pub const Digest = [digest_size]u8;

        ctx: Ctx,

        const Ctx = switch (alg) {
            .sha256 => c.SHA256_CTX,
            .sha384, .sha512 => c.SHA512_CTX,
        };

        pub fn init() Self {
            var self: Self = .{ .ctx = undefined };
            const ok = switch (alg) {
                .sha256 => c.zbssl_SHA256_Init(&self.ctx),
                .sha384 => c.zbssl_SHA384_Init(&self.ctx),
                .sha512 => c.zbssl_SHA512_Init(&self.ctx),
            };
            std.debug.assert(ok == 1);
            return self;
        }

        pub fn update(self: *Self, data: []const u8) void {
            const ok = switch (alg) {
                .sha256 => c.zbssl_SHA256_Update(&self.ctx, data.ptr, data.len),
                .sha384 => c.zbssl_SHA384_Update(&self.ctx, data.ptr, data.len),
                .sha512 => c.zbssl_SHA512_Update(&self.ctx, data.ptr, data.len),
            };
            std.debug.assert(ok == 1);
        }

        pub fn finalDigest(self: *Self) Digest {
            var out: Digest = undefined;
            const ok = switch (alg) {
                .sha256 => c.zbssl_SHA256_Final(&out, &self.ctx),
                .sha384 => c.zbssl_SHA384_Final(&out, &self.ctx),
                .sha512 => c.zbssl_SHA512_Final(&out, &self.ctx),
            };
            std.debug.assert(ok == 1);
            return out;
        }

        pub fn hash(input: []const u8) Digest {
            var s = Self.init();
            s.update(input);
            return s.finalDigest();
        }
    };
}

test "Sha256.hash returns the canonical 'abc' digest" {
    const got = Sha256.hash("abc");
    const want = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "Sha256 streaming matches one-shot" {
    var s = Sha256.init();
    s.update("a");
    s.update("b");
    s.update("c");
    const streamed = s.finalDigest();
    try std.testing.expectEqualSlices(u8, &Sha256.hash("abc"), &streamed);
}
