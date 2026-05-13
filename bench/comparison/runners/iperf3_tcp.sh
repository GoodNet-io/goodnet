#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Raw TCP throughput via iperf3. Industry-standard baseline that
# every TCP-stack benchmark gets compared against. Output is JSON
# for the aggregator.
#
# Usage: iperf3_tcp.sh [seconds]
# Default: 5 seconds, single stream, 8 KB sends.

set -euo pipefail

duration="${1:-5}"
port="${GN_BENCH_IPERF3_PORT:-5201}"

# Server in background
iperf3 -s -p "$port" --one-off >/dev/null 2>&1 &
server_pid=$!
trap 'kill $server_pid 2>/dev/null || true' EXIT
sleep 0.2

# Client emits JSON via -J
iperf3 -c 127.0.0.1 -p "$port" -t "$duration" -J 2>&1 | \
    python3 -c "
import json, sys
j = json.load(sys.stdin)
e = j['end']
streams = e['streams'][0]
print(json.dumps({
    'stack': 'iperf3 (raw TCP)',
    'metric': 'tcp_throughput_bps',
    'duration_s': $duration,
    'bytes_per_sec': streams['sender']['bits_per_second'] / 8,
    'bits_per_sec': streams['sender']['bits_per_second'],
    'retransmits': streams['sender'].get('retransmits', 0),
}, indent=2))
"
