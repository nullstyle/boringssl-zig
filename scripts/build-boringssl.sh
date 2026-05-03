#!/usr/bin/env bash
# Build BoringSSL with zig cc / zig c++ via CMake+Ninja, and stage the
# resulting static libraries + headers into vendor/boringssl-prebuilt/<target>/.
#
# Usage: scripts/build-boringssl.sh [target]
#   target: "native" (default) or a Zig target triple, e.g.
#           aarch64-macos, x86_64-macos, aarch64-linux-musl, x86_64-linux-musl

set -euo pipefail

target="${1:-native}"
build_type="${BUILD_TYPE:-Release}"
prefix="${BORINGSSL_PREFIX:-zbssl}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="$repo_root/deps/boringssl"

if [[ ! -d "$src/.git" && ! -f "$src/CMakeLists.txt" ]]; then
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

# Map Zig target triple -> CMake system identification.
zig_target_arg=""
cmake_system_name=""
cmake_system_processor=""
compiler_target=""

case "$target" in
  native)
    : # let CMake detect host
    ;;
  aarch64-macos|aarch64-macos-none)
    zig_target_arg="-target aarch64-macos"
    cmake_system_name="Darwin"
    cmake_system_processor="arm64"
    ;;
  x86_64-macos|x86_64-macos-none)
    zig_target_arg="-target x86_64-macos"
    cmake_system_name="Darwin"
    cmake_system_processor="x86_64"
    ;;
  aarch64-linux-musl)
    zig_target_arg="-target aarch64-linux-musl"
    cmake_system_name="Linux"
    cmake_system_processor="aarch64"
    ;;
  x86_64-linux-musl)
    zig_target_arg="-target x86_64-linux-musl"
    cmake_system_name="Linux"
    cmake_system_processor="x86_64"
    ;;
  *)
    echo "unknown target '$target'; add a mapping in scripts/build-boringssl.sh" >&2
    exit 1
    ;;
esac

# Reproducibility: stamp using BoringSSL's commit timestamp.
boringssl_commit="$(git -C "$src" rev-parse HEAD 2>/dev/null || echo unknown)"
boringssl_dirty="clean"
if ! git -C "$src" diff-index --quiet HEAD -- 2>/dev/null; then
  boringssl_dirty="dirty"
fi
boringssl_dirty_hash="$(git -C "$src" diff HEAD 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}' || echo none)"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$src" log -1 --format=%ct 2>/dev/null || echo 0)}"

# Wrapper scripts that route CMake's compiler/archiver invocations through Zig.
cat > "$wrapper_dir/cc" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec zig cc $zig_target_arg "\$@"
EOF

cat > "$wrapper_dir/cxx" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec zig c++ $zig_target_arg "\$@"
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

# CMake toolchain file. CMAKE_C_COMPILER_TARGET is set so CMake's compiler
# probe doesn't fail on a host-arch-incompatible test binary during cross.
{
  echo "set(CMAKE_C_COMPILER \"$wrapper_dir/cc\")"
  echo "set(CMAKE_CXX_COMPILER \"$wrapper_dir/cxx\")"
  echo "set(CMAKE_ASM_COMPILER \"$wrapper_dir/cc\")"
  echo "set(CMAKE_AR \"$wrapper_dir/ar\")"
  echo "set(CMAKE_RANLIB \"$wrapper_dir/ranlib\")"
  if [[ -n "$cmake_system_name" ]]; then
    echo "set(CMAKE_SYSTEM_NAME \"$cmake_system_name\")"
    echo "set(CMAKE_SYSTEM_PROCESSOR \"$cmake_system_processor\")"
    # Target is handled inside the cc/cxx wrappers via -target; we must NOT
    # set CMAKE_C_COMPILER_TARGET because Zig only accepts its own triple
    # form (e.g. "aarch64-macos"), and CMake would set both, doubling them.
    echo "set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)"
    echo "set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)"
    echo "set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)"
    echo "set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)"
    echo "set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)"
  fi
} > "$toolchain_file"

# Configure.
cmake \
  -S "$src" \
  -B "$build_dir" \
  -GNinja \
  -DCMAKE_TOOLCHAIN_FILE="$toolchain_file" \
  -DCMAKE_BUILD_TYPE="$build_type" \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBORINGSSL_PREFIX="$prefix"

# Build only the static libraries we ship. Avoids the verify_boringssl_prefix
# ALL target, which we treat as opt-in via `just verify`.
cmake --build "$build_dir" --target crypto ssl --parallel

crypto_lib="$(find "$build_dir" -type f -name 'libcrypto.a' | head -n 1)"
ssl_lib="$(find "$build_dir" -type f -name 'libssl.a' | head -n 1)"

if [[ -z "$crypto_lib" || -z "$ssl_lib" ]]; then
  echo "failed to locate built libcrypto.a or libssl.a under $build_dir" >&2
  find "$build_dir" -type f -name '*.a' >&2
  exit 1
fi

cp "$crypto_lib" "$out_lib/libcrypto.a"
cp "$ssl_lib"    "$out_lib/libssl.a"
cp -R "$src/include/"* "$out_include/"

if [[ -f "$src/LICENSE" ]]; then
  cp "$src/LICENSE" "$out_dir/LICENSE"
fi

zig_version="$(zig version)"

# Use shasum on macOS, sha256sum on Linux.
sha256() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

crypto_sha="$(sha256 "$out_lib/libcrypto.a")"
ssl_sha="$(sha256 "$out_lib/libssl.a")"

cat > "$out_dir/manifest.json" <<EOF
{
  "schema_version": 1,
  "target": "$target",
  "build_type": "$build_type",
  "boringssl_commit": "$boringssl_commit",
  "boringssl_state": "$boringssl_dirty",
  "boringssl_diff_sha256": "$boringssl_dirty_hash",
  "source_date_epoch": "$SOURCE_DATE_EPOCH",
  "zig_version": "$zig_version",
  "cc": "$(echo "zig cc $zig_target_arg" | sed 's/[[:space:]]*$//')",
  "cxx": "$(echo "zig c++ $zig_target_arg" | sed 's/[[:space:]]*$//')",
  "cmake_generator": "Ninja",
  "boringssl_prefix": "$prefix",
  "build_testing": false,
  "shared": false,
  "artifacts": {
    "libcrypto.a": "$crypto_sha",
    "libssl.a": "$ssl_sha"
  }
}
EOF

echo
echo "BoringSSL built:"
echo "  target:   $target"
echo "  prefix:   $prefix"
echo "  output:   $out_dir"
echo "  crypto:   $out_lib/libcrypto.a  ($crypto_sha)"
echo "  ssl:      $out_lib/libssl.a     ($ssl_sha)"
echo "  manifest: $out_dir/manifest.json"
