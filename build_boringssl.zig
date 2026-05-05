//! Native build of BoringSSL: compiles libcrypto.a + libssl.a using
//! Zig's build system from `deps/boringssl/`, no CMake required.
//!
//! Reads source lists from `deps/boringssl/gen/sources.json`, BoringSSL's
//! pregenerated, build-system-agnostic source manifest.

const std = @import("std");
const Build = std.Build;
const Step = Build.Step;
const Compile = Step.Compile;
const LazyPath = Build.LazyPath;
const Module = Build.Module;

pub const Result = struct {
    libcrypto: *Compile,
    libssl: *Compile,
    include_path: LazyPath,
};

pub const Options = struct {
    target: Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    boringssl_prefix: []const u8 = "zbssl",
    /// BoringSSL source location. Either a `Build.Dependency` (the
    /// `zig fetch`-tracked tarball, default for published consumers) or
    /// a `LazyPath` to a local source tree (for when this repo's own
    /// `deps/boringssl` submodule is in use).
    src: Src,

    pub const Src = union(enum) {
        dependency: *Build.Dependency,
        local: []const u8,
    };
};

/// Top-level: build libcrypto + libssl as static libraries from BoringSSL
/// sources. Returns Compile steps that can be linked into other modules.
pub fn build(b: *Build, options: Options) Result {
    const sources = loadSources(b, options.src);

    const include_path = sourcePath(b, options.src, "include");

    // Per-language flags. We deliberately do NOT pass BoringSSL's full
    // upstream warning set (-Werror, -Wshadow, ...): zig cc is built on a
    // newer Clang and surfaces warnings BoringSSL hasn't yet quieted on its
    // tip-of-tree commit. Treating warnings as errors would couple our build
    // to BoringSSL's exact tested clang version. The library code itself is
    // unchanged.
    const cxx_flags = [_][]const u8{
        "-std=c++17",
        "-fno-strict-aliasing",
        "-fno-common",
        "-fno-exceptions",
        "-fno-rtti",
        "-fvisibility=hidden",
        "-Wno-everything",
    };
    const asm_flags = [_][]const u8{};

    const libcrypto_mod = b.createModule(.{
        .target = options.target,
        .optimize = options.optimize,
        .link_libc = true,
        .link_libcpp = true,
    });
    libcrypto_mod.addIncludePath(include_path);
    libcrypto_mod.addCMacro("BORINGSSL_IMPLEMENTATION", "1");
    libcrypto_mod.addCMacro("BORINGSSL_PREFIX", options.boringssl_prefix);
    libcrypto_mod.addCMacro("_GNU_SOURCE", "1");

    const libcrypto = b.addLibrary(.{
        .linkage = .static,
        .name = "crypto",
        .root_module = libcrypto_mod,
    });

    addSection(b, libcrypto_mod, sources, "crypto", options.src, &cxx_flags, &asm_flags);
    addSection(b, libcrypto_mod, sources, "bcm", options.src, &cxx_flags, &asm_flags);

    const libssl_mod = b.createModule(.{
        .target = options.target,
        .optimize = options.optimize,
        .link_libc = true,
        .link_libcpp = true,
    });
    libssl_mod.addIncludePath(include_path);
    libssl_mod.addCMacro("BORINGSSL_IMPLEMENTATION", "1");
    libssl_mod.addCMacro("BORINGSSL_PREFIX", options.boringssl_prefix);
    libssl_mod.addCMacro("_GNU_SOURCE", "1");

    const libssl = b.addLibrary(.{
        .linkage = .static,
        .name = "ssl",
        .root_module = libssl_mod,
    });

    addSection(b, libssl_mod, sources, "ssl", options.src, &cxx_flags, &asm_flags);
    libssl_mod.addCSourceFile(.{
        .file = b.path("src/ssl_shim.cc"),
        .flags = &cxx_flags,
        .language = .cpp,
    });
    libssl_mod.linkLibrary(libcrypto);

    return .{
        .libcrypto = libcrypto,
        .libssl = libssl,
        .include_path = include_path,
    };
}

fn loadSources(b: *Build, src: Options.Src) std.json.Value {
    const io = b.graph.io;
    const json_path = absolutePath(b, src, "gen/sources.json");
    const json_bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        json_path,
        b.allocator,
        .limited(8 << 20),
    ) catch |err|
        std.debug.panic("failed to read {s}: {t}", .{ json_path, err });

    return std.json.parseFromSliceLeaky(
        std.json.Value,
        b.allocator,
        json_bytes,
        .{},
    ) catch |err| std.debug.panic("failed to parse {s}: {t}", .{ json_path, err });
}

/// Resolves a sub-path inside the BoringSSL source tree to a Zig
/// `LazyPath` suitable for include/source attachment in build steps.
fn sourcePath(b: *Build, src: Options.Src, sub: []const u8) Build.LazyPath {
    return switch (src) {
        .dependency => |d| d.path(sub),
        .local => |root| b.path(b.fmt("{s}/{s}", .{ root, sub })),
    };
}

/// Absolute filesystem path for configure-time file reads (e.g. parsing
/// sources.json).
fn absolutePath(b: *Build, src: Options.Src, sub: []const u8) []const u8 {
    return switch (src) {
        .dependency => |d| std.fs.path.join(
            b.allocator,
            &.{ d.builder.build_root.path orelse ".", sub },
        ) catch @panic("OOM"),
        .local => |root| b.pathFromRoot(b.fmt("{s}/{s}", .{ root, sub })),
    };
}

fn addSection(
    b: *Build,
    mod: *Module,
    sources: std.json.Value,
    key: []const u8,
    src: Options.Src,
    cxx_flags: []const []const u8,
    asm_flags: []const []const u8,
) void {
    _ = asm_flags;

    const section = sources.object.get(key) orelse {
        std.debug.panic("sources.json missing section '{s}'", .{key});
    };

    if (section.object.get("srcs")) |srcs| {
        for (srcs.array.items) |item| {
            const rel = item.string;
            // Only compile .cc files; .cc.inc are textually included by their parent.
            if (!std.mem.endsWith(u8, rel, ".cc")) continue;
            mod.addCSourceFile(.{
                .file = sourcePath(b, src, rel),
                .flags = cxx_flags,
                .language = .cpp,
            });
        }
    }

    // Assembly: include all .S files. Each is gated by preprocessor
    // directives (OPENSSL_X86_64, __APPLE__, __ELF__, etc.) so files for
    // other targets compile to no-ops on this target.
    if (section.object.get("asm")) |asm_files| {
        for (asm_files.array.items) |item| {
            const rel = item.string;
            mod.addAssemblyFile(sourcePath(b, src, rel));
        }
    }

    // We deliberately skip "nasm" — Windows-only, requires NASM tool, and
    // we don't support Windows in Phase 0/1/2.
}
