#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run the staged iroh echo binary across the standard payload sweep
# and emit aggregate.py-compatible JSON. iroh's open_bi()-per-round
# pattern is RPC-shaped; small payloads carry the QUIC stream open
# overhead disproportionately, which the row's `note` flags.
#
# Usage: iroh.sh [duration_s]

set -euo pipefail

duration="${1:-3}"
root="$(git rev-parse --show-toplevel 2>/dev/null || echo .)"
bin="${GN_BENCH_P2P_DIR:-$root/build-release/p2p-bench}/target/release/iroh-echo"

if [[ ! -x "$bin" ]]; then
    cat <<EOF
{"rows": [], "metric": "iroh_echo_throughput",
 "note": "iroh-echo bin not found at $bin — run bench/comparison/setup/07_iroh.sh first"}
EOF
    exit 0
fi

rows=()
for sz in 64 1024 8192 65536; do
    line=$(ECHO_PAYLOAD="$sz" ECHO_DURATION="$duration" "$bin" 2>/dev/null) || {
        rows+=("{\"stack\":\"iroh\",\"payload\":$sz,\"bytes_per_sec\":0,\"handshake_ms\":0,\"error\":\"bin failed\"}")
        continue
    }
    bps=$(echo "$line" | grep -oP 'bps=\K[0-9.]+'           || echo 0)
    hs=$(echo  "$line" | grep -oP 'handshake_ms=\K[0-9.-]+' || echo 0)
    bytes_per_sec=$(python3 -c "print(int(${bps:-0} * 1024 * 1024))")
    rows+=("{\"stack\":\"iroh\",\"payload\":$sz,\"bytes_per_sec\":$bytes_per_sec,\"handshake_ms\":$hs}")
done

joined=$(IFS=','; echo "${rows[*]}")
cat <<EOF
{"metric": "iroh_echo_throughput",
 "note": "iroh 0.32 (QUIC + TLS 1.3) loopback echo, ${duration}s per size, RPC-style open_bi per round",
 "rows": [${joined}]}
EOF
