//! Standalone consumer of boringssl via build.zig.zon.
//!
//! This exists as a regression test for the package boundary: if
//! something in the parent project breaks consumability (paths,
//! exposed module name, transitive defines), this consumer will fail
//! to build, and `just test-consumer` flags it.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Forwarded straight through, the way a real downstream package (quic-zig)
    // does, so `just test-consumer-prebuilt` can exercise the prebuilt-linking
    // options from outside the boringssl package. Unset options stay unset.
    const boringssl_dep = b.dependency("boringssl", .{
        .target = target,
        .optimize = optimize,
        .@"boringssl-source" = b.option(
            []const u8,
            "boringssl-source",
            "Forwarded to boringssl: 'zig' or 'cmake'",
        ),
        .@"boringssl-target" = b.option(
            []const u8,
            "boringssl-target",
            "Forwarded to boringssl: prebuilt directory name",
        ),
        .@"boringssl-prebuilt-path" = b.option(
            []const u8,
            "boringssl-prebuilt-path",
            "Forwarded to boringssl: absolute path to prebuilt BoringSSL archives",
        ),
    });
    const boringssl_mod = boringssl_dep.module("boringssl");

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("boringssl", boringssl_mod);

    const exe = b.addExecutable(.{
        .name = "consumer",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.addPassthruArgs();
    const run_step = b.step("run", "Run consumer demo");
    run_step.dependOn(&run.step);

    const tests = b.addTest(.{ .root_module = exe_mod });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run consumer KAT against the imported package");
    test_step.dependOn(&run_tests.step);
}
