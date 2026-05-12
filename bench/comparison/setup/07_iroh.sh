#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build the in-tree iroh echo binary at `bench/comparison/p2p/
# iroh-echo/`. Stages an upstream pointer for the DX LOC count
# and runs cargo build.

set -euo pipefail

root="$(git rev-parse --show-toplevel)"
proj_src="$root/bench/comparison/p2p/iroh-echo"
proj_out="${GN_BENCH_P2P_DIR:-$root/build-release/p2p-bench}/iroh-echo"
cache="${GN_BENCH_REFS_DIR:-$HOME/.cache/goodnet-bench-refs}/iroh"
mkdir -p "$cache" "$proj_out"

if [[ ! -d "$cache/upstream/.git" ]]; then
    git clone --depth 1 https://github.com/n0-computer/iroh "$cache/upstream"
else
    (cd "$cache/upstream" && git fetch --depth 1 origin \
        && git reset --hard origin/HEAD) >/dev/null
fi
if [[ -f "$cache/upstream/iroh/examples/echo.rs" ]]; then
    ln -sf "$cache/upstream/iroh/examples/echo.rs" "$cache/echo_example.rs"
elif [[ -f "$cache/upstream/examples/echo.rs" ]]; then
    ln -sf "$cache/upstream/examples/echo.rs" "$cache/echo_example.rs"
fi

rm -rf "$proj_out"
cp -R "$proj_src" "$proj_out"

cargo_cmd="cargo"
if ! command -v cargo >/dev/null 2>&1; then
    if command -v nix >/dev/null 2>&1; then
        cargo_cmd="nix shell nixpkgs#cargo nixpkgs#rustc nixpkgs#pkg-config nixpkgs#openssl --command cargo"
    else
        echo "ERROR: cargo not in PATH and nix unavailable — install Rust to build the iroh baseline" >&2
        exit 1
    fi
fi

(
    cd "$proj_out"
    CARGO_TARGET_DIR="${GN_BENCH_P2P_DIR:-$root/build-release/p2p-bench}/target" \
        $cargo_cmd build --release 2>&1 | tail -5
)

echo "iroh baseline ready:"
echo "  dx-source = $cache/echo_example.rs"
echo "  bin       = ${GN_BENCH_P2P_DIR:-$root/build-release/p2p-bench}/target/release/iroh-echo"
