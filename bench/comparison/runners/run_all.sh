#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Orchestrator: runs every GoodNet bench + every comparison
# baseline + aggregates all JSON outputs into one markdown report.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

sha=$(git rev-parse --short HEAD)
out="${1:-bench/reports/$sha.md}"
tmp=$(mktemp -d)
trap 'rm -rf $tmp' EXIT

mkdir -p bench/reports

echo "=== GoodNet plugin matrix ==="
for b in bench_tcp bench_tcp_scale bench_udp bench_ipc bench_ws bench_tls \
         bench_dtls bench_quic bench_ice bench_wss_over_tls; do
    # Prefer Release-build binaries when available. Debug runs
    # through the same syscalls and gets within ~5% on throughput
    # benches but skews crypto-heavy numbers (Noise handshake) by
    # 5-10%. The Release path is build-release/bench/<b>; falls
    # back to plain build/bench/<b> when the Release tree is absent.
    binary=""
    if [[ -x "build-release/bench/$b" ]]; then
        binary="build-release/bench/$b"
    elif [[ -x "build/bench/$b" ]]; then
        binary="build/bench/$b"
    fi
    if [[ -n "$binary" ]]; then
        echo "  running $binary..."
        /usr/bin/env -i HOME="$HOME" PATH="/run/current-system/sw/bin:/usr/bin" \
            "$binary" \
            --benchmark_min_time=0.3s \
            --benchmark_format=json 2>/dev/null \
            > "$tmp/$b.json" || echo "  $b failed (continuing)"
    fi
done

echo "=== External baselines ==="
if command -v iperf3 >/dev/null 2>&1; then
    echo "  iperf3 TCP..."
    bench/comparison/runners/iperf3_tcp.sh 3 > "$tmp/iperf3_tcp.json" \
        2>/dev/null || true
    echo "  iperf3 UDP..."
    bench/comparison/runners/iperf3_udp.sh 3 > "$tmp/iperf3_udp.json" \
        2>/dev/null || true
fi
if command -v socat >/dev/null 2>&1; then
    echo "  socat UNIX..."
    bench/comparison/runners/socat_unix.sh 1024 50000 > "$tmp/socat.json" \
        2>/dev/null || true
fi
if command -v openssl >/dev/null 2>&1; then
    if [[ -f "$HOME/.cache/goodnet-bench-refs/openssl/cert.pem" ]]; then
        echo "  openssl s_client handshake..."
        bench/comparison/runners/tls_handshake.sh 20 > "$tmp/openssl_tls.json" \
            2>/dev/null || true
    fi
fi

# Rust P2P stacks (libp2p, iroh) — fair-compare echo round-trip
# baselines for the EchoRoundtrip fixtures in bench_udp / bench_ws.
# Setup scripts build the binaries into $GN_BENCH_P2P_DIR; the
# runners no-op gracefully if the bins are absent.
p2p_root="${GN_BENCH_P2P_DIR:-$(pwd)/build-release/p2p-bench}/target/release"
if [[ -x "$p2p_root/libp2p-echo" ]]; then
    echo "  libp2p (rust) echo..."
    bench/comparison/runners/libp2p_rs.sh 3 > "$tmp/libp2p_rs.json" \
        2>/dev/null || true
fi
if [[ -x "$p2p_root/iroh-echo" ]]; then
    echo "  iroh (rust) echo..."
    bench/comparison/runners/iroh.sh 3 > "$tmp/iroh.json" \
        2>/dev/null || true
fi

echo "=== DX LOC count ==="
bench/comparison/runners/dx_loc_count.sh > "$tmp/dx_loc.json"

echo "=== Binary sizes / closure / docker ==="
bench/comparison/runners/binary_sizes.sh > "$tmp/binary_sizes.json"
echo "=== Comparison stack weights ==="
bench/comparison/runners/comparison_weights.sh > "$tmp/comparison_weights.json"

echo "=== Aggregating ==="
python3 bench/comparison/reports/aggregate.py \
    "$sha" "$out" "$tmp"/*.json
echo "report: $out"
