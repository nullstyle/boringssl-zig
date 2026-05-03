const std = @import("std");
const build_boringssl = @import("build_boringssl.zig");

const prefix = "zbssl";

const Source = enum { zig, cmake };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const source = b.option(
        Source,
        "boringssl-source",
        "How to build BoringSSL: 'zig' (native build.zig) or 'cmake' (vendor/ prebuilts).",
    ) orelse .zig;

    const boringssl_target = b.option(
        []const u8,
        "boringssl-target",
        "When --boringssl-source=cmake, picks vendor/boringssl-prebuilt/<dir>/ (default: native).",
    ) orelse "native";

    const Libs = struct {
        libcrypto_path: ?std.Build.LazyPath = null,
        libssl_path: ?std.Build.LazyPath = null,
        libcrypto_compile: ?*std.Build.Step.Compile = null,
        libssl_compile: ?*std.Build.Step.Compile = null,
        include_path: std.Build.LazyPath,
    };

    const libs: Libs = switch (source) {
        .cmake => blk: {
            const vendor_dir = b.fmt("vendor/boringssl-prebuilt/{s}", .{boringssl_target});
            break :blk .{
                .libcrypto_path = b.path(b.fmt("{s}/lib/libcrypto.a", .{vendor_dir})),
                .libssl_path = b.path(b.fmt("{s}/lib/libssl.a", .{vendor_dir})),
                .include_path = b.path(b.fmt("{s}/include", .{vendor_dir})),
            };
        },
        .zig => blk: {
            const boringssl_src_dep = b.dependency("boringssl_src", .{});
            const native = build_boringssl.build(b, .{
                .target = target,
                .optimize = optimize,
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
    // (zig path) or the vendored prebuilt include dir (cmake path); both are
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

    // Public wrapper module.
    const boringssl_mod = b.addModule("boringssl", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });
    boringssl_mod.addImport("c", c_mod);

    if (libs.libssl_compile) |c| boringssl_mod.linkLibrary(c);
    if (libs.libcrypto_compile) |c| boringssl_mod.linkLibrary(c);
    if (libs.libssl_path) |p| boringssl_mod.addObjectFile(p);
    if (libs.libcrypto_path) |p| boringssl_mod.addObjectFile(p);

    // Smoke executable.
    const smoke_mod = b.createModule(.{
        .root_source_file = b.path("cli/smoke.zig"),
        .target = target,
        .optimize = optimize,
    });
    smoke_mod.addImport("boringssl", boringssl_mod);
    const smoke_exe = b.addExecutable(.{
        .name = "boringssl-smoke",
        .root_module = smoke_mod,
    });
    b.installArtifact(smoke_exe);

    const run_smoke = b.addRunArtifact(smoke_exe);
    if (b.args) |args| run_smoke.addArgs(args);
    const smoke_step = b.step("run-smoke", "Run BoringSSL smoke executable");
    smoke_step.dependOn(&run_smoke.step);

    // TLS smoke executable: HTTPS round-trip to a real host.
    const tls_smoke_mod = b.createModule(.{
        .root_source_file = b.path("cli/tls_smoke.zig"),
        .target = target,
        .optimize = optimize,
    });
    tls_smoke_mod.addImport("boringssl", boringssl_mod);
    const tls_smoke_exe = b.addExecutable(.{
        .name = "tls-smoke",
        .root_module = tls_smoke_mod,
    });
    b.installArtifact(tls_smoke_exe);

    const run_tls_smoke = b.addRunArtifact(tls_smoke_exe);
    if (b.args) |args| run_tls_smoke.addArgs(args);
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
    });
    kat_mod.addImport("boringssl", boringssl_mod);
    const kat_tests = b.addTest(.{ .root_module = kat_mod });
    const run_kat_tests = b.addRunArtifact(kat_tests);
    test_step.dependOn(&run_kat_tests.step);
}
