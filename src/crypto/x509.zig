//! X.509 certificate issuance. A builder covers the common development
//! path — a self-signed CA and leaves it signs — without requiring the
//! caller to know BoringSSL's X509_* call order or which extension NIDs
//! to use. `X509V3_EXT_nconf_nid` is the extension function (the
//! `_conf_nid` variant does not exist in this build).

const std = @import("std");
const c = @import("c");
const pkey = @import("pkey.zig");

pub const Error = error{ CertBuild, CertSign, CertExt, KeyGen };

/// An owned certificate. Free with `deinit`.
pub const Certificate = struct {
    cert: *c.X509,

    pub fn deinit(self: *Certificate) void {
        c.zbssl_X509_free(self.cert);
    }
};

/// An owned CA certificate and its key pair. The key signs leaves.
pub const Ca = struct {
    cert: Certificate,
    key: pkey.EcP256,

    pub fn deinit(self: *Ca) void {
        self.cert.deinit();
        self.key.deinit();
    }

    /// Start building a leaf signed by this CA.
    pub fn leaf(self: *const Ca, cn: []const u8) CertificateBuilder {
        return CertificateBuilder.init().signedBy(self, cn);
    }
};

const nid_key_usage: c_int = 83;
const nid_subject_alt_name: c_int = 85;
const nid_basic_constraints: c_int = 87;
const nid_ext_key_usage: c_int = 126;
const mbstring_asc: c_int = 0x1000 | 1;
const NID_prime256v1: c_int = 415;

/// Builds one certificate. The typical shapes:
///
/// ```zig
/// // A self-signed CA (mintCa does this in one call):
/// var ca = try CertificateBuilder.init()
///     .selfSigned("My Dev CA")
///     .validDays(3650)
///     .ca()
///     .build(&ca_key);   // pubkey AND signer are ca_key
///
/// // A leaf it signs — build takes the SUBJECT's key:
/// var leaf_cert = try ca.leaf("node-1")   // signer is ca.key
///     .san("my-cluster")                  // can repeat
///     .serverAuth().clientAuth()
///     .build(&node_key);                  // pubkey is node_key
/// ```
pub const CertificateBuilder = struct {
    subject: []const u8,
    issuer_ca: ?*const Ca = null,
    is_ca: bool = false,
    valid_days: c_long = 365,
    sans: [8][]const u8 = @splat(""),
    sans_len: usize = 0,
    ext_key_usage: []const u8 = "",

    pub fn init() CertificateBuilder {
        // The caller may be the first to touch BoringSSL's crypto tables.
        c.zbssl_CRYPTO_library_init();
        return .{ .subject = "" };
    }

    /// A self-signed certificate (subject and issuer are the same).
    pub fn selfSigned(self: CertificateBuilder, cn: []const u8) CertificateBuilder {
        var b = self;
        b.subject = cn;
        return b;
    }

    /// A certificate signed by `ca`: its subject becomes the issuer
    /// name and its key signs. `build` then takes the SUBJECT's key.
    pub fn signedBy(self: CertificateBuilder, issuer: *const Ca, cn: []const u8) CertificateBuilder {
        var b = self;
        b.subject = cn;
        b.issuer_ca = issuer;
        return b;
    }

    pub fn ca(self: CertificateBuilder) CertificateBuilder {
        var b = self;
        b.is_ca = true;
        return b;
    }

    pub fn validDays(self: CertificateBuilder, days: c_long) CertificateBuilder {
        var b = self;
        b.valid_days = days;
        return b;
    }

    /// Add a DNS subjectAltName; may be called up to 8 times.
    pub fn san(self: CertificateBuilder, name: []const u8) CertificateBuilder {
        var b = self;
        if (b.sans_len < b.sans.len) {
            b.sans[b.sans_len] = name;
            b.sans_len += 1;
        }
        return b;
    }

    pub fn serverAuth(self: CertificateBuilder) CertificateBuilder {
        var b = self;
        b.ext_key_usage = "serverAuth";
        return b;
    }

    pub fn clientAuth(self: CertificateBuilder) CertificateBuilder {
        var b = self;
        b.ext_key_usage = if (b.ext_key_usage.len > 0) "serverAuth,clientAuth" else "clientAuth";
        return b;
    }

    /// Build and sign. `subject_key` becomes the certificate's public
    /// key. A self-signed builder signs with that same key; a leaf
    /// builder (`signedBy`) signs with the CA's key instead.
    pub fn build(self: CertificateBuilder, subject_key: *const pkey.EcP256) Error!Certificate {
        const x = c.zbssl_X509_new() orelse return Error.CertBuild;
        errdefer c.zbssl_X509_free(x);

        if (c.zbssl_X509_set_version(x, 2) != 1) return Error.CertBuild; // v3
        setRandomSerial(x);
        _ = c.zbssl_X509_gmtime_adj(c.zbssl_X509_getm_notBefore(x), -60 * 60);
        _ = c.zbssl_X509_gmtime_adj(c.zbssl_X509_getm_notAfter(x), 60 * 60 * 24 * self.valid_days);
        if (c.zbssl_X509_set_pubkey(x, subject_key.pkey) != 1) return Error.CertBuild;
        try setSubject(x, self.subject);
        if (self.issuer_ca) |issuer| {
            const name = c.zbssl_X509_get_subject_name(issuer.cert.cert) orelse return Error.CertBuild;
            if (c.zbssl_X509_set_issuer_name(x, name) != 1) return Error.CertBuild;
        } else {
            try setSubjectAsIssuer(x);
        }
        if (self.is_ca) {
            try addExt(x, nid_basic_constraints, "critical,CA:TRUE");
            try addExt(x, nid_key_usage, "critical,keyCertSign,cRLSign");
        } else {
            try addExt(x, nid_basic_constraints, "critical,CA:FALSE");
            try addExt(x, nid_key_usage, "critical,digitalSignature,keyAgreement");
        }
        if (self.sans_len > 0) {
            var buffer: [512]u8 = @splat(0);
            var offset: usize = 0;
            for (self.sans[0..self.sans_len]) |name| {
                if (offset > 0 and offset < buffer.len) {
                    buffer[offset] = ',';
                    offset += 1;
                }
                const written = std.fmt.bufPrint(buffer[offset..], "DNS:{s}", .{name}) catch break;
                offset += written.len;
            }
            if (offset > 0) try addExt(x, nid_subject_alt_name, @ptrCast(&buffer));
        }
        if (self.ext_key_usage.len > 0) {
            var eku: [64]u8 = @splat(0);
            const n = @min(self.ext_key_usage.len, eku.len - 1);
            @memcpy(eku[0..n], self.ext_key_usage[0..n]);
            try addExt(x, nid_ext_key_usage, @ptrCast(&eku));
        }
        const signer = if (self.issuer_ca) |issuer| issuer.key.pkey else subject_key.pkey;
        if (c.zbssl_X509_sign(x, signer, c.zbssl_EVP_sha256()) == 0) return Error.CertSign;
        return .{ .cert = x };
    }

    /// Convenience: mint a self-signed CA with its own key pair.
    pub fn mintCa(cn: []const u8, days: c_long) Error!Ca {
        var key = try pkey.generateEcP256();
        errdefer key.deinit();
        const cert = try (CertificateBuilder.init()
            .selfSigned(cn)
            .validDays(days)
            .ca()
            .build(&key));
        return .{ .cert = cert, .key = key };
    }
};

fn setRandomSerial(x: *c.X509) void {
    var bytes: [8]u8 = undefined;
    if (c.zbssl_RAND_bytes(&bytes, bytes.len) != 1) return;
    const value: i64 = @intCast(std.mem.readInt(u64, &bytes, .little) & 0x3fff_ffff_ffff_ffff);
    _ = c.zbssl_ASN1_INTEGER_set(c.zbssl_X509_get_serialNumber(x), value);
}

fn setSubject(x: *c.X509, cn: []const u8) Error!void {
    const name = c.zbssl_X509_get_subject_name(x) orelse return Error.CertBuild;
    if (c.zbssl_X509_NAME_add_entry_by_txt(name, "CN", mbstring_asc, cn.ptr, @intCast(cn.len), -1, 0) != 1) return Error.CertBuild;
    if (c.zbssl_X509_set_subject_name(x, name) != 1) return Error.CertBuild;
}

fn setSubjectAsIssuer(x: *c.X509) Error!void {
    const name = c.zbssl_X509_get_subject_name(x) orelse return Error.CertBuild;
    if (c.zbssl_X509_set_issuer_name(x, name) != 1) return Error.CertBuild;
}

fn addExt(x: *c.X509, nid: c_int, value: [*:0]const u8) Error!void {
    const ext = c.zbssl_X509V3_EXT_nconf_nid(null, null, nid, value) orelse return Error.CertExt;
    defer c.zbssl_X509_EXTENSION_free(ext);
    if (c.zbssl_X509_add_ext(x, ext, -1) != 1) return Error.CertExt;
}

test "mint a CA and a leaf it signs" {
    const gpa = std.testing.allocator;
    const pem = @import("pem.zig");

    var ca = try CertificateBuilder.mintCa("Test Cluster CA", 3650);
    defer ca.deinit();

    var node_key = try pkey.generateEcP256();
    defer node_key.deinit();

    var leaf_cert = try ca.leaf("node-1").san("test-cluster").serverAuth().clientAuth().build(&node_key);
    defer leaf_cert.deinit();

    // The leaf carries the node's public key and the CA's signature:
    // verified with the CA's key, paired with the node's private key.
    try std.testing.expect(c.zbssl_X509_verify(leaf_cert.cert, ca.key.pkey) == 1);
    try std.testing.expect(c.zbssl_X509_check_private_key(leaf_cert.cert, node_key.pkey) == 1);

    // Both encode to PEM that starts correctly.
    const ca_pem = try pem.encodeCertificate(gpa, ca.cert.cert);
    defer gpa.free(ca_pem);
    try std.testing.expect(std.mem.startsWith(u8, ca_pem, "-----BEGIN CERTIFICATE-----"));

    const leaf_pem = try pem.encodeCertificate(gpa, leaf_cert.cert);
    defer gpa.free(leaf_pem);
    try std.testing.expect(std.mem.startsWith(u8, leaf_pem, "-----BEGIN CERTIFICATE-----"));

    // The leaf decodes back.
    const decoded = try pem.decodeCertificate(leaf_pem);
    defer c.zbssl_X509_free(decoded);
}

test "two CAs minted with the same name have different serials" {
    var ca1 = try CertificateBuilder.mintCa("Same Name CA", 365);
    defer ca1.deinit();
    var ca2 = try CertificateBuilder.mintCa("Same Name CA", 365);
    defer ca2.deinit();
    // Different random serials means different certificates.
    const gpa = std.testing.allocator;
    const pem = @import("pem.zig");
    const pem1 = try pem.encodeCertificate(gpa, ca1.cert.cert);
    defer gpa.free(pem1);
    const pem2 = try pem.encodeCertificate(gpa, ca2.cert.cert);
    defer gpa.free(pem2);
    try std.testing.expect(!std.mem.eql(u8, pem1, pem2));
}
