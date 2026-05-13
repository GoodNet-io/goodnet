#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build the in-tree libp2p echo binary at `bench/comparison/p2p/
# libp2p-echo/`. The source lives in the repo so reviewers see what
# the benchmark actually measures; this script only stages an
# upstream pointer for the DX LOC counter and runs cargo.
#
# Output: $GN_BENCH_P2P_DIR/target/release/libp2p-echo
# Defaults: $GN_BENCH_P2P_DIR = build-release/p2p-bench
#
# The DX-LOC reference points at upstream's canonical hello-world
# (`examples/ping/src/main.rs`) so the dx_loc table treats libp2p
# with the same yardstick as openssl, libuv, libssh.

set -euo pipefail

root="$(git rev-parse --show-toplevel)"
proj_src="$root/bench/comparison/p2p/libp2p-echo"
proj_out="${GN_BENCH_P2P_DIR:-$root/build-release/p2p-bench}/libp2p-echo"
cache="${GN_BENCH_REFS_DIR:-$HOME/.cache/goodnet-bench-refs}/libp2p-rs"
mkdir -p "$cache" "$proj_out"

if [[ ! -d "$cache/upstream/.git" ]]; then
    git clone --depth 1 https://github.com/libp2p/rust-libp2p "$cache/upstream"
else
    (cd "$cache/upstream" && git fetch --depth 1 origin \
        && git reset --hard origin/HEAD) >/dev/null
fi
ln -sf "$cache/upstream/examples/ping/src/main.rs" "$cache/echo_example.rs"

# Mirror the in-tree project into the build dir so cargo's target
# tree stays outside the repo. cp -RT keeps src/ at the right path.
rm -rf "$proj_out"
cp -R "$proj_src" "$proj_out"

cargo_cmd="cargo"
if ! command -v cargo >/dev/null 2>&1; then
    if command -v nix >/dev/null 2>&1; then
        cargo_cmd="nix shell nixpkgs#cargo nixpkgs#rustc nixpkgs#pkg-config nixpkgs#openssl --command cargo"
    else
        echo "ERROR: cargo not in PATH and nix unavailable — install Rust to build the libp2p baseline" >&2
        exit 1
    fi
fi

(
    cd "$proj_out"
    CARGO_TARGET_DIR="${GN_BENCH_P2P_DIR:-$root/build-release/p2p-bench}/target" \
        $cargo_cmd build --release 2>&1 | tail -5
)

echo "libp2p baseline ready:"
echo "  dx-source = $cache/echo_example.rs"
echo "  bin       = ${GN_BENCH_P2P_DIR:-$root/build-release/p2p-bench}/target/release/libp2p-echo"
