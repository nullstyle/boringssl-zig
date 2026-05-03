set shell := ["bash", "-euo", "pipefail", "-c"]

# Default surface: native zig build of BoringSSL. CMake recipes
# (boringssl-cmake, verify-cmake) remain for cross-checking and CI.

default:
    @just --list

check-tools:
    @command -v zig    >/dev/null || { echo "missing zig";   exit 1; }
    @command -v git    >/dev/null || { echo "missing git";   exit 1; }
    @echo "tools ok: $(zig version)"

check-cmake-tools:
    @command -v cmake  >/dev/null || { echo "missing cmake"; exit 1; }
    @command -v ninja  >/dev/null || { echo "missing ninja"; exit 1; }
    @command -v go     >/dev/null || { echo "missing go (required for BORINGSSL_PREFIX)"; exit 1; }

deps:
    git submodule update --init --recursive deps/boringssl

# Run the wrapper test suite + KAT tests against the native zig build.
test:
    zig build test

# Run smoke executable (SHA-256, RAND).
smoke:
    zig build run-smoke

# HTTPS round-trip smoke (TLS 1.3 to a public host).
tls-smoke host="example.com":
    zig build run-tls-smoke -- {{host}}

# Build BoringSSL via CMake (Phase-0 path). Output:
#   vendor/boringssl-prebuilt/<target>/libcrypto.a
#   vendor/boringssl-prebuilt/<target>/libssl.a
boringssl-cmake target="native": check-cmake-tools deps
    scripts/build-boringssl.sh {{target}}

verify-cmake target="native":
    scripts/verify-prebuilt.sh {{target}}

# Verify the CMake-built archive and the zig-built archive produce the
# same KAT pass rate. Both paths must succeed.
verify-paths: boringssl-cmake
    zig build test -Dboringssl-source=cmake
    zig build test -Dboringssl-source=zig

# Build the standalone consumer in examples/consumer/ — proves the
# build.zig.zon package boundary works end-to-end.
test-consumer:
    cd examples/consumer && zig build test

ci-local: deps test smoke test-consumer verify-paths

# Run the GitHub Actions workflow locally with act + Docker.
# `act` picks the container architecture matching the host, so on Apple
# Silicon this runs an arm64 ubuntu image (Rosetta otherwise hits a
# bss_size overflow during `zig translate-c`).
act-ci job="native":
    act -j {{job}} -P ubuntu-latest=catthehacker/ubuntu:act-latest

clean:
    rm -rf .zig-cache zig-out

distclean: clean
    rm -rf .cache/boringssl vendor/boringssl-prebuilt
