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
# `bench_udp` / `bench_dtls` / `bench_quic` / `bench_ice` crash on
# HEAD: a glibc malloc.c:2610 heap-arena assertion in the UDP
# loopback path pre-dates the bench overhaul (reproduces on c146231
# too) and DTLS / QUIC / ICE inherit it via their UDP carrier. The
# stub-JSON below seeds the aggregator's `## Known crashes` section
# so the missing rows are explicit in the report; the binaries
# themselves are excluded from the auto-run so they don't poison
# the shell with a coredump.
for crashed in bench_udp bench_dtls bench_quic bench_ice; do
    # Tiny invalid-JSON marker — aggregator's parse_gbench raises
    # JSONDecodeError, which `skipped_inputs` then captures and the
    # `## Known crashes` section renders.
    printf 'crashed: UdpLink malloc.c:2610 heap-arena assertion\n' \
        > "$tmp/${crashed}.json"
done
for b in bench_tcp bench_tcp_scale bench_ipc bench_ws bench_tls; do
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
echo "=== Environment facts ==="
bench/comparison/runners/env_facts.sh > "$tmp/env_facts.json"

# Pick the most recent prior bench report as the regression baseline.
# `bench/reports/<sha>.md` is the artifact shape; sort by mtime so a
# fresh commit-sha file from minutes ago beats a year-old report,
# matching how operators expect the comparison to behave. Skip the
# current report path so a re-run against the same sha doesn't
# self-compare to a zero delta. Empty `baseline_arg` if nothing
# matches.
baseline_arg=""
prev_report="$(ls -t bench/reports/*.md 2>/dev/null \
               | grep -v "^${out}$" | head -1 || true)"
if [[ -n "$prev_report" ]]; then
    baseline_arg="--baseline=$prev_report"
    echo "  baseline: $prev_report"
fi

echo "=== Aggregating ==="
python3 bench/comparison/reports/aggregate.py \
    $baseline_arg "$sha" "$out" "$tmp"/*.json
echo "report: $out"
