#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Raw UDP throughput via iperf3. Defaults to 1 Gbps target rate so
# the run isn't network-bound on loopback.

set -euo pipefail

duration="${1:-5}"
port="${GN_BENCH_IPERF3_PORT:-5201}"
rate="${GN_BENCH_IPERF3_UDP_RATE:-1000M}"

iperf3 -s -p "$port" --one-off >/dev/null 2>&1 &
server_pid=$!
trap 'kill $server_pid 2>/dev/null || true' EXIT
sleep 0.2

iperf3 -c 127.0.0.1 -p "$port" -u -b "$rate" -t "$duration" -J 2>&1 | \
    python3 -c "
import json, sys
j = json.load(sys.stdin)
e = j['end']
streams = e['streams'][0]
udp = streams['udp']
print(json.dumps({
    'stack': 'iperf3 (raw UDP)',
    'metric': 'udp_throughput_bps',
    'duration_s': $duration,
    'bytes_per_sec': udp['bits_per_second'] / 8,
    'bits_per_sec': udp['bits_per_second'],
    'lost_packets': udp.get('lost_packets', 0),
    'lost_percent': udp.get('lost_percent', 0),
    'jitter_ms': udp.get('jitter_ms', 0),
}, indent=2))
"
