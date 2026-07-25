#!/usr/bin/env bash
# Assert the two BoringSSL pins agree.
#
# This repo pins BoringSSL twice, for two different build paths:
#
#   build.zig.zon   .boringssl_src URL tarball  -> the native zig path
#   .gitmodules     deps/boringssl submodule    -> the CMake prebuilt path
#
# `just verify-paths` compares KAT results across those paths and is only
# meaningful if both are the same BoringSSL. If they drift, the comparison
# silently becomes apples-to-oranges and stops being parity at all.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

zon_sha="$(grep -oE 'boringssl/archive/[0-9a-f]{40}\.tar\.gz' build.zig.zon |
  head -n 1 | grep -oE '[0-9a-f]{40}' || true)"

if [[ -z "$zon_sha" ]]; then
  echo "could not find a boringssl archive commit in build.zig.zon" >&2
  echo "expected a .url like https://github.com/google/boringssl/archive/<sha40>.tar.gz" >&2
  exit 1
fi

# The gitlink SHA recorded in the tree — no submodule checkout required.
sub_sha="$(git rev-parse HEAD:deps/boringssl 2>/dev/null || true)"

if [[ -z "$sub_sha" ]]; then
  echo "could not read the deps/boringssl submodule pin from git" >&2
  exit 1
fi

if [[ "$zon_sha" != "$sub_sha" ]]; then
  cat >&2 <<EOF
MISMATCH: the two BoringSSL pins disagree.

  build.zig.zon  (zig path):   $zon_sha
  deps/boringssl (cmake path): $sub_sha

\`just verify-paths\` would compare two different BoringSSL versions, so a
pass would not mean the paths agree. Move whichever pin is stale:

  # to match build.zig.zon:
  git -C deps/boringssl fetch origin $zon_sha && \\
    git -C deps/boringssl checkout $zon_sha && \\
    git add deps/boringssl
EOF
  exit 1
fi

echo "ok  BoringSSL pins agree  $zon_sha"
