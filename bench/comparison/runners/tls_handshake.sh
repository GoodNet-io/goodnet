#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Measures TLS handshake time on the same loopback both GoodNet's
# bench_tls and openssl s_client run over. Output is JSON so the
# aggregator can merge with google-benchmark output.
#
# Usage: tls_handshake.sh [iterations]
# Default: 100 iterations per side.

set -euo pipefail

iters="${1:-100}"
cache="${GN_BENCH_REFS_DIR:-$HOME/.cache/goodnet-bench-refs}/openssl"
port="${GN_BENCH_TLS_PORT:-14443}"

if [[ ! -f "$cache/cert.pem" ]]; then
    echo "{\"error\":\"run bench/comparison/setup/01_openssl.sh first\"}" >&2
    exit 1
fi

# Start s_server in the background. Wait until the listening port
# accepts a connection before driving the loop.
openssl s_server \
    -accept "$port" \
    -cert "$cache/cert.pem" -key "$cache/key.pem" \
    -quiet -no_dhe 2>/dev/null &
server_pid=$!
trap 'kill $server_pid 2>/dev/null || true' EXIT

# Wait for the listener.
for _ in $(seq 1 50); do
    if echo q | openssl s_client -connect "127.0.0.1:$port" -quiet \
         2>/dev/null >/dev/null; then
        break
    fi
    sleep 0.05
done

# Drive the loop. `time` gives ms precision; we use `date +%s%N` for ns.
declare -a samples
for i in $(seq 1 "$iters"); do
    t0=$(date +%s%N)
    echo "" | openssl s_client -connect "127.0.0.1:$port" -quiet \
        2>/dev/null >/dev/null
    t1=$(date +%s%N)
    samples+=("$((t1 - t0))")
done

# Build JSON output. P50 = sort + middle.
sorted=$(printf '%s\n' "${samples[@]}" | sort -n)
p50=$(echo "$sorted" | awk -v n="${#samples[@]}" 'NR==int(n/2)+1{print; exit}')
p99=$(echo "$sorted" | awk -v n="${#samples[@]}" 'NR==int(n*0.99)+1{print; exit}')
sum=$(echo "$sorted" | awk '{s+=$1} END{print s}')
mean=$((sum / iters))

cat <<EOF
{
  "stack": "openssl s_client",
  "iterations": $iters,
  "metric": "handshake_ns",
  "mean": $mean,
  "p50": $p50,
  "p99": $p99,
  "min": $(echo "$sorted" | head -1),
  "max": $(echo "$sorted" | tail -1)
}
EOF
