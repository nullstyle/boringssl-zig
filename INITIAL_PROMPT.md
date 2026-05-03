Below is a Codex-ready brief. Save it as something like `docs/BORINGSSL_ZIG_LOCAL_BUILD_PLAN.md` or paste it directly into Codex Desktop as the implementation prompt.

---

# Local BoringSSL + Zig Integration Plan

## Goal

Build a first-pass local integration of BoringSSL into a Zig codebase using:

* Zig’s bundled C compiler: `zig cc`
* Zig’s bundled C++ compiler: `zig c++`
* CMake + Ninja for BoringSSL’s native build system
* `just` as the repo-facing command surface
* No Docker
* No host Clang/GCC/MSVC requirement for ordinary local development

BoringSSL’s upstream CMake build currently requires CMake 3.22+, recommends Ninja, and requires C11 plus C++17-capable compilers; we will satisfy the compiler requirement with `zig cc` and `zig c++`. ([BoringSSL][1])

BoringSSL also warns that it does not guarantee API or ABI stability for third-party consumers, so this integration should pin a BoringSSL commit and hide direct BoringSSL usage behind a small Zig wrapper module. ([GitHub][2])

## Non-goals for the first attempt

Do not attempt to:

* Rewrite BoringSSL’s build system in `build.zig`.
* Remove BoringSSL’s C++ usage.
* Support Windows.
* Support Android/iOS.
* Support FIPS mode.
* Run the full upstream BoringSSL test suite.
* Depend on OpenSSL ABI compatibility.
* Expose raw BoringSSL APIs throughout the application.

The first version should prove:

1. BoringSSL can be built locally with `zig cc` and `zig c++`.
2. `libcrypto.a` and `libssl.a` can be copied into a predictable vendor directory.
3. Zig tests can link against those static libraries.
4. A small wrapper can call at least one BoringSSL API successfully.

## Proposed repo layout

```text
repo/
  justfile
  build.zig
  build.zig.zon

  deps/
    boringssl/                       # git submodule, pinned commit

  scripts/
    build-boringssl.sh

  vendor/
    boringssl-prebuilt/
      native/
        include/
          openssl/
            ...
        lib/
          libcrypto.a
          libssl.a
        manifest.json
        LICENSE

  src/
    boringssl/
      root.zig
      c.zig
      hash.zig
    main.zig
```

## Tool requirements

For the first local pass:

```text
zig
just
cmake >= 3.22
ninja
git
bash
```

Go is not needed for the first pass if we configure BoringSSL with `-DBUILD_TESTING=OFF`. BoringSSL’s own docs list Go as required for running upstream tests, and Perl is only needed when modifying pregenerated perlasm-related files. ([BoringSSL][1])

## Git submodule setup

Use BoringSSL as a pinned submodule:

```sh
git submodule add https://boringssl.googlesource.com/boringssl deps/boringssl
git submodule update --init --recursive deps/boringssl
git -C deps/boringssl rev-parse HEAD
```

Do not track a moving branch as the integration contract. Store the exact commit in `vendor/boringssl-prebuilt/native/manifest.json`.

## `justfile`

Create this at repo root:

```just
set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    just --list

check-tools:
    command -v zig
    command -v cmake
    command -v ninja
    command -v git

deps:
    git submodule update --init --recursive deps/boringssl

boringssl target="native": check-tools deps
    scripts/build-boringssl.sh {{target}}

boringssl-clean:
    rm -rf .cache/boringssl vendor/boringssl-prebuilt

test target="native": boringssl
    zig build test -Dboringssl-target={{target}}

smoke target="native": boringssl
    zig build run-smoke -Dboringssl-target={{target}}

ci-local: boringssl test smoke
```

First local workflow:

```sh
just boringssl
just test
just smoke
```

## `scripts/build-boringssl.sh`

Create this script and mark it executable.

```sh
#!/usr/bin/env bash
set -euo pipefail

target="${1:-native}"
build_type="${BUILD_TYPE:-Release}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="$repo_root/deps/boringssl"

if [[ ! -d "$src" ]]; then
  echo "missing deps/boringssl; run: git submodule update --init --recursive deps/boringssl" >&2
  exit 1
fi

build_root="$repo_root/.cache/boringssl"
build_dir="$build_root/build/$target"
wrapper_dir="$build_root/wrappers/$target"
toolchain_dir="$build_root/toolchains"
toolchain_file="$toolchain_dir/$target.cmake"

out_dir="$repo_root/vendor/boringssl-prebuilt/$target"
out_include="$out_dir/include"
out_lib="$out_dir/lib"

rm -rf "$build_dir" "$wrapper_dir" "$out_dir"
mkdir -p "$build_dir" "$wrapper_dir" "$toolchain_dir" "$out_include" "$out_lib"

target_arg=""
cmake_system_name=""

if [[ "$target" != "native" ]]; then
  target_arg="-target $target"

  case "$target" in
    *linux*) cmake_system_name="Linux" ;;
    *macos*) cmake_system_name="Darwin" ;;
    *windows*) cmake_system_name="Windows" ;;
    *)
      echo "unknown non-native target '$target'; add a CMAKE_SYSTEM_NAME mapping" >&2
      exit 1
      ;;
  esac
fi

cat > "$wrapper_dir/cc" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec zig cc $target_arg "\$@"
EOF

cat > "$wrapper_dir/cxx" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec zig c++ $target_arg "\$@"
EOF

cat > "$wrapper_dir/ar" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec zig ar "$@"
EOF

cat > "$wrapper_dir/ranlib" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec zig ranlib "$@"
EOF

chmod +x "$wrapper_dir/cc" "$wrapper_dir/cxx" "$wrapper_dir/ar" "$wrapper_dir/ranlib"

cat > "$toolchain_file" <<EOF
set(CMAKE_C_COMPILER "$wrapper_dir/cc")
set(CMAKE_CXX_COMPILER "$wrapper_dir/cxx")
set(CMAKE_AR "$wrapper_dir/ar")
set(CMAKE_RANLIB "$wrapper_dir/ranlib")
EOF

if [[ -n "$cmake_system_name" ]]; then
  cat >> "$toolchain_file" <<EOF
set(CMAKE_SYSTEM_NAME "$cmake_system_name")
EOF
fi

cmake \
  -S "$src" \
  -B "$build_dir" \
  -GNinja \
  -DCMAKE_TOOLCHAIN_FILE="$toolchain_file" \
  -DCMAKE_BUILD_TYPE="$build_type" \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON

cmake --build "$build_dir" --target crypto ssl --parallel

crypto_lib="$(find "$build_dir" -type f -name 'libcrypto.a' | head -n 1)"
ssl_lib="$(find "$build_dir" -type f -name 'libssl.a' | head -n 1)"

if [[ -z "$crypto_lib" || -z "$ssl_lib" ]]; then
  echo "failed to locate built libcrypto.a or libssl.a under $build_dir" >&2
  find "$build_dir" -type f | sort >&2
  exit 1
fi

cp "$crypto_lib" "$out_lib/libcrypto.a"
cp "$ssl_lib" "$out_lib/libssl.a"
cp -R "$src/include/"* "$out_include/"

if [[ -f "$src/LICENSE" ]]; then
  cp "$src/LICENSE" "$out_dir/LICENSE"
fi

boringssl_commit="$(git -C "$src" rev-parse HEAD 2>/dev/null || echo unknown)"
zig_version="$(zig version)"

cat > "$out_dir/manifest.json" <<EOF
{
  "target": "$target",
  "build_type": "$build_type",
  "boringssl_commit": "$boringssl_commit",
  "zig_version": "$zig_version",
  "cc": "zig cc $target_arg",
  "cxx": "zig c++ $target_arg",
  "cmake_generator": "Ninja",
  "build_testing": false,
  "shared": false
}
EOF

echo "BoringSSL built:"
echo "  target: $target"
echo "  output: $out_dir"
echo "  crypto: $out_lib/libcrypto.a"
echo "  ssl:    $out_lib/libssl.a"
```

Then:

```sh
chmod +x scripts/build-boringssl.sh
```

## Zig wrapper module

### `src/boringssl/c.zig`

```zig
pub usingnamespace @cImport({
    @cInclude("openssl/base.h");
    @cInclude("openssl/crypto.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/sha.h");
    @cInclude("openssl/ssl.h");
});
```

### `src/boringssl/hash.zig`

```zig
const std = @import("std");
const c = @import("c.zig");

pub fn sha256(input: []const u8) [32]u8 {
    var out: [32]u8 = undefined;

    // BoringSSL SHA256 returns a pointer to the output buffer.
    _ = c.SHA256(input.ptr, input.len, &out);

    return out;
}

test "sha256 abc" {
    const digest = sha256("abc");

    const expected = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };

    try std.testing.expectEqualSlices(u8, &expected, &digest);
}
```

### `src/boringssl/root.zig`

```zig
pub const c = @import("c.zig");
pub const hash = @import("hash.zig");

test {
    _ = hash;
}
```

## Example smoke executable

### `src/main.zig`

```zig
const std = @import("std");
const boringssl = @import("boringssl");

pub fn main() !void {
    const digest = boringssl.hash.sha256("hello from zig + boringssl");

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("sha256: ", .{});
    for (digest) |b| {
        try stdout.print("{x:0>2}", .{b});
    }
    try stdout.print("\n", .{});

    try stdout.flush();
}
```

## `build.zig` first-pass shape

Adjust for the exact Zig version in use, but the build should do this conceptually:

```zig
const std = @import("std");

fn boringTargetDir(b: *std.Build) []const u8 {
    const target_name = b.option(
        []const u8,
        "boringssl-target",
        "BoringSSL vendor target directory",
    ) orelse "native";

    return b.fmt("vendor/boringssl-prebuilt/{s}", .{target_name});
}

fn linkBoringSSL(
    b: *std.Build,
    step: *std.Build.Step.Compile,
    boring_dir: []const u8,
) void {
    step.addIncludePath(b.path(b.fmt("{s}/include", .{boring_dir})));
    step.addLibraryPath(b.path(b.fmt("{s}/lib", .{boring_dir})));

    // Order matters for some linkers: ssl depends on crypto.
    step.linkSystemLibrary("ssl");
    step.linkSystemLibrary("crypto");
    step.linkLibC();
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const boring_dir = boringTargetDir(b);

    const boringssl_mod = b.createModule(.{
        .root_source_file = b.path("src/boringssl/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "boringssl-smoke",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("boringssl", boringssl_mod);
    linkBoringSSL(b, exe, boring_dir);

    b.installArtifact(exe);

    const run_exe = b.addRunArtifact(exe);
    const run_step = b.step("run-smoke", "Run BoringSSL smoke executable");
    run_step.dependOn(&run_exe.step);

    const tests = b.addTest(.{
        .root_source_file = b.path("src/boringssl/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    linkBoringSSL(b, tests, boring_dir);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
}
```

## First Codex implementation tasks

Implement this in the repo:

1. Add `justfile`.
2. Add `scripts/build-boringssl.sh`.
3. Add `src/boringssl/c.zig`.
4. Add `src/boringssl/hash.zig`.
5. Add `src/boringssl/root.zig`.
6. Add or update `src/main.zig` as a smoke executable.
7. Update `build.zig` so:

   * tests link against `vendor/boringssl-prebuilt/<target>/lib`
   * C imports see `vendor/boringssl-prebuilt/<target>/include`
   * `-Dboringssl-target=native` defaults correctly
8. Add a small README section explaining:

```sh
just boringssl
just test
just smoke
```

## Acceptance criteria

The following must work from a clean checkout after initializing the submodule:

```sh
just boringssl
```

Expected result:

```text
vendor/boringssl-prebuilt/native/include/openssl/...
vendor/boringssl-prebuilt/native/lib/libcrypto.a
vendor/boringssl-prebuilt/native/lib/libssl.a
vendor/boringssl-prebuilt/native/manifest.json
```

Then:

```sh
just test
```

Expected result:

```text
SHA-256 wrapper test passes.
```

Then:

```sh
just smoke
```

Expected result:

```text
sha256: <64 hex chars>
```

## Implementation notes

Prefer the wrapper-script approach over passing `zig cc -target ...` directly to CMake. CMake expects compiler paths in many places, and wrapper scripts avoid edge cases around compiler commands with spaces.

Use `BUILD_TESTING=OFF` for the first pass. The goal is to build `crypto` and `ssl`, not to validate all of BoringSSL upstream.

Do not commit `.cache/boringssl`.

Commit `vendor/boringssl-prebuilt/native` only if this repo wants checked-in binary artifacts. Otherwise add it to `.gitignore` and treat it as locally generated.

Suggested `.gitignore` entries:

```gitignore
.cache/
zig-cache/
zig-out/

# Choose one policy:
# Ignore generated BoringSSL artifacts:
vendor/boringssl-prebuilt/

# Or, if committing artifacts, remove the line above.
```

## Future work after first pass

After the first local pass works:

1. Add named targets:

   * `aarch64-macos`
   * `x86_64-macos`
   * `x86_64-linux-musl`
   * `aarch64-linux-musl`

2. Add `just boringssl-all`.

3. Add CI caching keyed by:

   * BoringSSL commit
   * Zig version
   * target triple
   * `scripts/build-boringssl.sh` hash

4. Add a TLS client smoke test using `SSL_CTX`, `SSL`, and ALPN.

5. Consider BoringSSL symbol prefixing only if this codebase may link multiple BoringSSL copies into one process. BoringSSL documents symbol prefixing as experimental and subject to change, so keep it out of the first pass. ([BoringSSL][1])

[1]: https://boringssl.googlesource.com/boringssl/%2B/HEAD/BUILDING.md "Building BoringSSL"
[2]: https://github.com/google/boringssl "GitHub - google/boringssl: Mirror of BoringSSL · GitHub"
