const std = @import("std");
const build_boringssl = @import("build_boringssl.zig");

const prefix = "zbssl";

const Source = enum { zig, cmake };

/// Entries every prebuilt BoringSSL directory holds, relative to its root.
const prebuilt_entries = [_][]const u8{ "lib/libcrypto.a", "lib/libssl.a", "include" };

/// A directory of CMake-built BoringSSL artifacts, resolved either through
/// this package's `vendor/` convention or from an embedder-supplied path.
const PrebuiltDir = union(enum) {
    /// Relative to this package's root: `vendor/boringssl-prebuilt/<target>`,
    /// populated by `just boringssl-cmake`. Only a checkout has it — the
    /// `.paths` whitelist in build.zig.zon omits `vendor/`, so a fetched copy
    /// of this package never carries prebuilt archives.
    package: []const u8,
    /// Absolute path from `-Dboringssl-prebuilt-path`, outside the package.
    external: []const u8,

    fn lazyPath(dir: PrebuiltDir, b: *std.Build, sub: []const u8) std.Build.LazyPath {
        return switch (dir) {
            .package => |rel| b.path(b.pathJoin(&.{ rel, sub })),
            .external => |abs| .{ .cwd_relative = b.pathJoin(&.{ abs, sub }) },
        };
    }

    /// Absolute path to `sub`, for configure-time probing and diagnostics.
    fn absPath(dir: PrebuiltDir, b: *std.Build, sub: []const u8) []const u8 {
        return switch (dir) {
            .package => |rel| b.root.joinString(
                b.allocator,
                b.pathJoin(&.{ rel, sub }),
            ) catch @panic("OOM"),
            .external => |abs| b.pathJoin(&.{ abs, sub }),
        };
    }

    fn isPopulated(dir: PrebuiltDir, b: *std.Build) bool {
        for (prebuilt_entries) |entry| {
            std.Io.Dir.cwd().access(b.graph.io, dir.absPath(b, entry), .{}) catch return false;
        }
        return true;
    }
};

/// Locate the prebuilt archives for `-Dboringssl-source=cmake`. An explicit
/// `-Dboringssl-prebuilt-path` wins over the `vendor/` convention; either the
/// directory itself or a `<dir>/<boringssl-target>` subdirectory may hold the
/// artifacts, so both a single-target package and a vendor-shaped tree work.
fn resolvePrebuiltDir(b: *std.Build, prebuilt_path: ?[]const u8, boringssl_target: []const u8) PrebuiltDir {
    if (prebuilt_path) |supplied| {
        if (!std.fs.path.isAbsolute(supplied)) {
            std.debug.panic(
                \\-Dboringssl-prebuilt-path must be absolute (got '{s}').
                \\It is resolved against the build runner's working directory, which is
                \\not the package root when boringssl-zig is built as a dependency.
            , .{supplied});
        }

        const direct: PrebuiltDir = .{ .external = supplied };
        if (direct.isPopulated(b)) return direct;

        const per_target: PrebuiltDir = .{ .external = b.pathJoin(&.{ supplied, boringssl_target }) };
        if (per_target.isPopulated(b)) return per_target;

        std.debug.panic(
            \\-Dboringssl-prebuilt-path='{s}' holds no BoringSSL prebuilt.
            \\  probed: {s}
            \\  probed: {s}
            \\A prebuilt directory holds lib/libcrypto.a, lib/libssl.a and include/.
            \\Produce one from a boringssl-zig checkout: scripts/build-boringssl.sh {s}
        , .{
            supplied,
            direct.absPath(b, "lib/libcrypto.a"),
            per_target.absPath(b, "lib/libcrypto.a"),
            boringssl_target,
        });
    }

    const vendor: PrebuiltDir = .{ .package = b.fmt("vendor/boringssl-prebuilt/{s}", .{boringssl_target}) };
    if (vendor.isPopulated(b)) return vendor;

    std.debug.panic(
        \\-Dboringssl-source=cmake found no BoringSSL prebuilt for target '{s}'.
        \\  probed: {s}
        \\In a boringssl-zig checkout, populate that directory with:
        \\  just boringssl-cmake {s}
        \\A fetched copy of this package has no vendor/ directory at all (build.zig.zon
        \\.paths omits it), so point at the archives explicitly:
        \\  -Dboringssl-prebuilt-path=/abs/dir   with dir/lib/lib{{crypto,ssl}}.a + dir/include
        \\Otherwise drop -Dboringssl-source=cmake and let Zig build BoringSSL from source.
    , .{ boringssl_target, vendor.absPath(b, "lib/libcrypto.a"), boringssl_target });
}

fn parseSanitizeC(value: []const u8) std.zig.SanitizeC {
    if (std.mem.eql(u8, value, "off")) return .off;
    if (std.mem.eql(u8, value, "trap")) return .trap;
    if (std.mem.eql(u8, value, "full")) return .full;
    std.debug.panic("invalid -Dsanitize-c value '{s}' (expected off, trap, or full)", .{value});
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const sanitize_c: ?std.zig.SanitizeC = if (b.option(
        []const u8,
        "sanitize-c",
        "Override C/UB sanitizer mode for BoringSSL and wrapper modules: off, trap, or full",
    )) |mode| parseSanitizeC(mode) else null;

    const requested_source = b.option(
        Source,
        "boringssl-source",
        "How to build BoringSSL: 'zig' (native build.zig) or 'cmake' (prebuilt archives).",
    );

    const boringssl_target = b.option(
        []const u8,
        "boringssl-target",
        "When --boringssl-source=cmake, names the prebuilt directory: vendor/boringssl-prebuilt/<dir>/, " ++
            "or <dir> under --boringssl-prebuilt-path (default: native).",
    ) orelse "native";

    const prebuilt_path = b.option(
        []const u8,
        "boringssl-prebuilt-path",
        "Absolute path to prebuilt BoringSSL archives (<dir>/lib/lib{crypto,ssl}.a + <dir>/include). " ++
            "Implies --boringssl-source=cmake and bypasses vendor/, so it works from a fetched package.",
    );

    const source: Source = requested_source orelse
        if (prebuilt_path != null) .cmake else .zig;

    if (source == .zig and prebuilt_path != null) {
        std.debug.panic(
            \\-Dboringssl-prebuilt-path is only consumed by -Dboringssl-source=cmake;
            \\the zig path compiles BoringSSL from source and links no prebuilt archives.
        , .{});
    }

    const Libs = struct {
        libcrypto_path: ?std.Build.LazyPath = null,
        libssl_path: ?std.Build.LazyPath = null,
        libcrypto_compile: ?*std.Build.Step.Compile = null,
        libssl_compile: ?*std.Build.Step.Compile = null,
        include_path: std.Build.LazyPath,
    };

    const libs: Libs = switch (source) {
        .cmake => blk: {
            if (sanitize_c != null and sanitize_c != .off) {
                std.debug.panic("-Dsanitize-c={t} requires -Dboringssl-source=zig; prebuilt cmake archives cannot be instrumented", .{sanitize_c.?});
            }
            const prebuilt = resolvePrebuiltDir(b, prebuilt_path, boringssl_target);
            break :blk .{
                .libcrypto_path = prebuilt.lazyPath(b, "lib/libcrypto.a"),
                .libssl_path = prebuilt.lazyPath(b, "lib/libssl.a"),
                .include_path = prebuilt.lazyPath(b, "include"),
            };
        },
        .zig => blk: {
            const boringssl_src_dep = b.dependency("boringssl_src", .{});
            const native = build_boringssl.build(b, .{
                .target = target,
                .optimize = optimize,
                .sanitize_c = sanitize_c,
                .boringssl_prefix = prefix,
                .src = .{ .dependency = boringssl_src_dep },
            });
            break :blk .{
                .libcrypto_compile = native.libcrypto,
                .libssl_compile = native.libssl,
                .include_path = native.include_path,
            };
        },
    };

    // C bindings via translate-c. Headers come from BoringSSL's source tree
    // (zig path) or the prebuilt include dir (cmake path); both are
    // semantically identical since BoringSSL ships pre-generated prefix
    // headers in include/openssl/.
    const translate_c = b.addTranslateC(.{
        .root_source_file = b.path("src/c_imports.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    translate_c.addIncludePath(libs.include_path);
    translate_c.defineCMacro("BORINGSSL_PREFIX", prefix);
    const c_mod = translate_c.createModule();
    c_mod.sanitize_c = sanitize_c;

    // Public wrapper module.
    const boringssl_mod = b.addModule("boringssl", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_c = sanitize_c,
        .link_libc = true,
        .link_libcpp = true,
    });
    boringssl_mod.addImport("c", c_mod);
    if (target.result.os.tag == .windows) {
        boringssl_mod.linkSystemLibrary("ws2_32", .{});
    }

    // Wrapper glue over BoringSSL's bssl::-namespaced entry points. Built the
    // same way for both sources — whichever way libssl arrived, the shim is
    // compiled against its headers and linked here, so the two paths cannot
    // disagree about which glue exists.
    boringssl_mod.linkLibrary(build_boringssl.buildShim(b, .{
        .target = target,
        .optimize = optimize,
        .sanitize_c = sanitize_c,
        .boringssl_prefix = prefix,
        .include_path = libs.include_path,
    }));

    if (libs.libssl_compile) |c| boringssl_mod.linkLibrary(c);
    if (libs.libcrypto_compile) |c| boringssl_mod.linkLibrary(c);
    if (libs.libssl_path) |p| boringssl_mod.addObjectFile(p);
    if (libs.libcrypto_path) |p| boringssl_mod.addObjectFile(p);

    // Smoke executable.
    const smoke_mod = b.createModule(.{
        .root_source_file = b.path("cli/smoke.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_c = sanitize_c,
    });
    smoke_mod.addImport("boringssl", boringssl_mod);
    const smoke_exe = b.addExecutable(.{
        .name = "boringssl-smoke",
        .root_module = smoke_mod,
    });
    b.installArtifact(smoke_exe);

    const run_smoke = b.addRunArtifact(smoke_exe);
    run_smoke.addPassthruArgs();
    const smoke_step = b.step("run-smoke", "Run BoringSSL smoke executable");
    smoke_step.dependOn(&run_smoke.step);

    // TLS smoke executable: HTTPS round-trip to a real host.
    const tls_smoke_mod = b.createModule(.{
        .root_source_file = b.path("cli/tls_smoke.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_c = sanitize_c,
    });
    tls_smoke_mod.addImport("boringssl", boringssl_mod);
    const tls_smoke_exe = b.addExecutable(.{
        .name = "tls-smoke",
        .root_module = tls_smoke_mod,
    });
    b.installArtifact(tls_smoke_exe);

    const run_tls_smoke = b.addRunArtifact(tls_smoke_exe);
    run_tls_smoke.addPassthruArgs();
    const tls_smoke_step = b.step("run-tls-smoke", "HTTPS round-trip smoke test");
    tls_smoke_step.dependOn(&run_tls_smoke.step);

    // Tests: wrapper inline tests + tests/ KATs.
    const test_step = b.step("test", "Run wrapper and KAT tests");

    const wrapper_tests = b.addTest(.{ .root_module = boringssl_mod });
    const run_wrapper_tests = b.addRunArtifact(wrapper_tests);
    test_step.dependOn(&run_wrapper_tests.step);

    const kat_mod = b.createModule(.{
        .root_source_file = b.path("tests/root.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_c = sanitize_c,
    });
    kat_mod.addImport("boringssl", boringssl_mod);
    const kat_tests = b.addTest(.{ .root_module = kat_mod });
    const run_kat_tests = b.addRunArtifact(kat_tests);
    test_step.dependOn(&run_kat_tests.step);
}
