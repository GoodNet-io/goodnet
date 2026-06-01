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
# Sequential ordering: cheap / pure-CPU benches first, UDP-carrier
# benches (bench_udp, bench_dtls, bench_quic) at the END. The earlier
# rc5 cycle parked these three behind stub-JSON because a glibc
# malloc.c:2610 heap-arena assertion in UdpLink crashed them; that
# assertion was fixed in the rc5 bench-overhaul (bench_ice was unblocked
# in the same cycle). Running them at the tail keeps any residual
# instability from poisoning the cheaper-bench numbers above.
#
# Belt-and-braces: between binaries we drain TIME_WAIT entries from
# the prior run (capped at 30s) so the next binary's listen / bind
# doesn't trip over a saturated ephemeral-port pool. asio's TCP
# acceptor already sets `reuse_address(true)`; the wait below covers
# the UDP-side ephemeral-port pressure that builds up in the
# loopback-heavy benches.
#
# `bench_sustained` stays opt-in because of its ~60-second wall time
# (gate via `GOODNET_BENCH_SUSTAINED` so the runner only includes it
# when explicitly requested).
default_set=(bench_tcp bench_tcp_scale bench_ipc bench_ws bench_tls
             bench_ice bench_subprocess bench_failover
             bench_udp bench_dtls bench_quic
             bench_real_e2e bench_wss_over_tls bench_noise
             bench_handler_registry)
if [[ "${GOODNET_BENCH_SUSTAINED:-0}" == "1" ]]; then
    default_set+=(bench_sustained)
fi

# Drain wait between binaries. Polls `ss -tan state time-wait` and
# sleeps until the count falls below 100, capped at 30s so a stuck
# kernel doesn't stall the whole gauntlet. No-op if `ss` is absent
# (sandboxed CI without iproute2).
drain_time_wait() {
    if ! command -v ss >/dev/null 2>&1; then return; fi
    local waited=0
    while [[ $waited -lt 30 ]]; do
        local n
        n=$(ss -tan state time-wait 2>/dev/null | wc -l)
        if [[ $n -lt 100 ]]; then return; fi
        sleep 1
        waited=$((waited + 1))
    done
}

for b in "${default_set[@]}"; do
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
        drain_time_wait
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

# Showcase benches (opt-in) — architectural capability demos with their
# own CSV side-channels and a separate showcase_aggregate.py report.
# Enable with GOODNET_BENCH_SHOWCASE=1.
if [[ "${GOODNET_BENCH_SHOWCASE:-0}" == "1" ]]; then
    echo "=== Showcase benches ==="
    showcase_bin=""
    if [[ -x "build-release/bench/bench_showcase" ]]; then
        showcase_bin="build-release/bench/bench_showcase"
    elif [[ -x "build/bench/bench_showcase" ]]; then
        showcase_bin="build/bench/bench_showcase"
    fi
    if [[ -n "$showcase_bin" ]]; then
        echo "  running $showcase_bin..."
        /usr/bin/env -i HOME="$HOME" PATH="/run/current-system/sw/bin:/usr/bin" \
            "$showcase_bin" \
            --benchmark_min_time=0.3s \
            --benchmark_format=json 2>/dev/null \
            > "$tmp/bench_showcase.json" || echo "  bench_showcase failed (continuing)"
        python3 bench/comparison/reports/showcase_aggregate.py \
            "$sha" "bench/reports/${sha}-showcase.md" \
            "$tmp/bench_showcase.json" \
            "$tmp"/showcase-b*.csv 2>/dev/null || true
        echo "  showcase report: bench/reports/${sha}-showcase.md"
        drain_time_wait
    else
        echo "  bench_showcase binary not found (skipping)"
    fi
fi

# Rust P2P stacks (libp2p, iroh) — fair-compare echo round-trip
# baselines for the EchoRoundtrip fixtures in bench_udp / bench_ws.
# Build the Rust binaries once with:
#   cd bench/comparison/baselines/libp2p && cargo build --release
#   cd bench/comparison/baselines/iroh   && cargo build --release
# or set GN_BENCH_P2P_DIR to your pre-built target directory.
# Runners no-op gracefully when binaries are absent.
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
