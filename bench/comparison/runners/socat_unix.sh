#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# socat AF_UNIX echo throughput — baseline for bench_ipc. Sends
# `count` * `size` bytes from /dev/zero through a socat-mediated
# UNIX socket and measures wall time.

set -euo pipefail

size="${1:-1024}"        # bytes per send
count="${2:-100000}"     # sends

if ! command -v socat >/dev/null 2>&1; then
    echo '{"error":"socat missing"}' >&2
    exit 1
fi

sockpath="/tmp/goodnet-bench-socat-$$.sock"
rm -f "$sockpath"

# Server: echo bytes back
socat -U "UNIX-LISTEN:$sockpath,fork" "EXEC:cat" >/dev/null 2>&1 &
server_pid=$!
trap 'kill $server_pid 2>/dev/null || true; rm -f $sockpath' EXIT
sleep 0.1

# Client: send `count * size` bytes, measure wall time
t0=$(date +%s%N)
head -c $((size * count)) /dev/zero | \
    socat -u - "UNIX-CONNECT:$sockpath" >/dev/null
t1=$(date +%s%N)

elapsed_ns=$((t1 - t0))
total_bytes=$((size * count))
bytes_per_sec=$(awk -v b=$total_bytes -v n=$elapsed_ns \
    'BEGIN{printf "%.0f", b * 1e9 / n}')

cat <<EOF
{
  "stack": "socat (AF_UNIX echo)",
  "metric": "ipc_throughput_bps",
  "payload_size": $size,
  "iterations": $count,
  "total_bytes": $total_bytes,
  "elapsed_ns": $elapsed_ns,
  "bytes_per_sec": $bytes_per_sec
}
EOF
