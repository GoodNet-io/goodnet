#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Emit a JSON table of "deployment weight" for every comparison
# stack the bench tree compares GoodNet against. The same axes
# `binary_sizes.sh` applies to the GoodNet build are applied here:
#
#   * binary_bytes    — the executable image on disk
#   * libs_sum_bytes  — sum of every distinct .so the binary maps
#                       at runtime (from `ldd`), excluding the
#                       linux-vdso. Captures the runtime closure
#                       cost; the GoodNet dynamic build's plugin
#                       `.so` sum is the apples-to-apples mirror.
#   * total_bytes     — binary + libs_sum. The number an operator
#                       actually copies onto a fresh host (the
#                       `ld-linux` interpreter pulls in everything
#                       else automatically).
#
# Rust binaries (libp2p, iroh) statically link their crates into
# the executable, so `binary_bytes` is the meaningful "weight"
# number and `libs_sum_bytes` only counts glibc + libgcc_s + libm.
# C tools (iperf3, socat, openssl) take the opposite shape — small
# binary, large library closure.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

p2p_root="${GN_BENCH_P2P_DIR:-$(pwd)/build-release/p2p-bench}/target/release"

# Resolve each comparison stack to a list of binaries to weigh.
declare -A stacks
[[ -x "$p2p_root/libp2p-echo" ]] && stacks[libp2p_rust]="$p2p_root/libp2p-echo"
[[ -x "$p2p_root/iroh-echo"  ]] && stacks[iroh_rust]="$p2p_root/iroh-echo"
if command -v iperf3 >/dev/null 2>&1; then
    stacks[iperf3]="$(readlink -f "$(command -v iperf3)")"
fi
if command -v socat >/dev/null 2>&1; then
    stacks[socat]="$(readlink -f "$(command -v socat)")"
fi
if command -v openssl >/dev/null 2>&1; then
    stacks[openssl]="$(readlink -f "$(command -v openssl)")"
fi

weigh_one() {
    local path="$1"
    [[ -f "$path" ]] || { echo "0 0"; return; }
    local binary_bytes libs_bytes
    binary_bytes=$(stat -c %s "$path")
    libs_bytes=$(ldd "$path" 2>/dev/null \
        | awk '/=>/ { print $3 }' \
        | grep -v '^$' \
        | sort -u \
        | xargs -r stat -c %s 2>/dev/null \
        | awk '{s+=$1} END {print s+0}')
    echo "$binary_bytes ${libs_bytes:-0}"
}

# Emit JSON. Stack name → { binary_bytes, libs_sum_bytes,
# total_bytes }.
{
    echo '{'
    echo '  "metric": "comparison_weights",'
    echo '  "stacks": {'
    first=1
    for name in libp2p_rust iroh_rust iperf3 socat openssl; do
        path="${stacks[$name]:-}"
        if [[ -z "$path" ]]; then continue; fi
        read -r b l < <(weigh_one "$path")
        total=$((b + l))
        if [[ $first -eq 0 ]]; then echo ','; fi
        first=0
        printf '    "%s": { "path": "%s", "binary_bytes": %d, "libs_sum_bytes": %d, "total_bytes": %d }' \
            "$name" "$path" "$b" "$l" "$total"
    done
    echo
    echo '  }'
    echo '}'
}
