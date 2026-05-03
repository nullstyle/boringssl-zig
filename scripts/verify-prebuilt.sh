#!/usr/bin/env bash
# Verify that vendor/boringssl-prebuilt/<target>/ matches its manifest.json.

set -euo pipefail

target="${1:-native}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="$repo_root/vendor/boringssl-prebuilt/$target"
manifest="$out_dir/manifest.json"

if [[ ! -f "$manifest" ]]; then
  echo "no manifest at $manifest; run: just boringssl $target" >&2
  exit 1
fi

sha256() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Tiny portable JSON value extractor for our flat manifest.artifacts table.
# Format we emit:  "libcrypto.a": "<sha>",
get_sha() {
  local file="$1"
  awk -v key="\"$file\":" '
    $0 ~ key {
      n = split($0, parts, "\"");
      print parts[4];
      exit;
    }
  ' "$manifest"
}

fail=0
for f in libcrypto.a libssl.a; do
  expected="$(get_sha "$f")"
  actual="$(sha256 "$out_dir/lib/$f")"
  if [[ "$expected" != "$actual" ]]; then
    echo "MISMATCH $f"
    echo "  expected: $expected"
    echo "  actual:   $actual"
    fail=1
  else
    echo "ok  $f  $actual"
  fi
done

exit "$fail"
