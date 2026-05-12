#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run the staged libp2p echo binary across the standard payload
# sweep and emit JSON in the `tables` schema aggregate.py expects.
# Each row: stack, payload_size, bytes_per_sec, handshake_ms.
#
# Usage: libp2p_rs.sh [duration_s]

set -euo pipefail

duration="${1:-3}"
root="$(git rev-parse --show-toplevel 2>/dev/null || echo .)"
bin="${GN_BENCH_P2P_DIR:-$root/build-release/p2p-bench}/target/release/libp2p-echo"

if [[ ! -x "$bin" ]]; then
    cat <<EOF
{"rows": [], "metric": "libp2p_echo_throughput",
 "note": "libp2p-echo bin not found at $bin — run bench/comparison/setup/06_libp2p_rs.sh first"}
EOF
    exit 0
fi

rows=()
for sz in 64 1024 8192 65536; do
    line=$(ECHO_PAYLOAD="$sz" ECHO_DURATION="$duration" "$bin" 2>/dev/null) || {
        rows+=("{\"stack\":\"libp2p\",\"payload\":$sz,\"bytes_per_sec\":0,\"handshake_ms\":0,\"error\":\"bin failed\"}")
        continue
    }
    bps=$(echo "$line"   | grep -oP 'bps=\K[0-9.]+'           || echo 0)
    hs=$(echo "$line"    | grep -oP 'handshake_ms=\K[0-9.-]+' || echo 0)
    # bps in MiB/s — convert to bytes/sec
    bytes_per_sec=$(python3 -c "print(int(${bps:-0} * 1024 * 1024))")
    rows+=("{\"stack\":\"libp2p\",\"payload\":$sz,\"bytes_per_sec\":$bytes_per_sec,\"handshake_ms\":$hs}")
done

joined=$(IFS=','; echo "${rows[*]}")
cat <<EOF
{"metric": "libp2p_echo_throughput",
 "note": "rust-libp2p 0.55 (TCP + Noise + Yamux + libp2p-stream) loopback echo, ${duration}s per size",
 "rows": [${joined}]}
EOF
