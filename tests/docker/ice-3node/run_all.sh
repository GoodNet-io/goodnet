#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Iterate every scenario override under scenarios/*.yml against the
# base docker-compose.yml. The list is glob-driven and sorted
# alphabetically, so new scenarios get picked up automatically by
# dropping a fresh `<name>.yml` under `scenarios/`. The current set:
#
#   all_relay              both peers symmetric  → relay ↔ relay
#   full_cone              both peers full-cone  → srflx ↔ srflx
#   hairpin                shared NAT            → host ↔ host (hairpin)
#   ice_lite_gateway       B is ICE-lite         → A drives nomination
#   ipv6_mdns              dual-stack v4+v6      → mDNS-hidden host pair
#   multi_turn_failover    primary TURN flaky    → secondary takes over
#   no_udp_fallback        UDP blocked end-to-end→ relay-TCP+TLS
#   port_prediction        symmetric-stride NAT  → predicted port pair
#   quic_over_ice          quic://<peer-pk> URI  → QUIC handshake over ICE pair
#   restricted_mtu         path MTU 900          → DPLPMTUD discovery
#   symmetric_relay        A symmetric / B cone  → relay ↔ srflx
#
# For each scenario:
#
#   1. tear down any leftover stack
#   2. `up -d --build` with the scenario override layered in
#   3. wait up to TIMEOUT_S for the signal-dir to show
#      `${peer_a}.done` AND `${peer_b}.done`
#   4. emit pass / fail line, scrape `docker compose logs` on fail
#   5. tear down before the next scenario
#
# Exit code:
#   0  — every scenario produced both .done files
#   1  — at least one scenario timed out / failed
#
# The peer harness binary is built on the host from the dev shell
# (`peer/build-harness.sh`) and copied into `peer/` alongside the
# required plugin .so set before the first `compose up --build`.
# Docker caches the resulting image so subsequent scenarios reuse
# the layer.

set -uo pipefail

cd "$(dirname "$0")"

# Preflight: verify the host can forward inter-bridge UDP.
# Advisory only — TURN-relayed scenarios survive even without the fix.
if [ "${SKIP_FIREWALL_CHECK:-0}" != "1" ]; then
    fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)
    if [ "${fwd}" != "1" ]; then
        echo "WARN: net.ipv4.ip_forward is 0 — inter-container UDP will fail"
        echo "      Fix: sudo sysctl -w net.ipv4.ip_forward=1"
    fi
    br_nf=$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || echo 0)
    if [ "${br_nf}" = "1" ] && command -v nft >/dev/null 2>&1; then
        if ! nft list ruleset 2>/dev/null | grep -q "10.20.0.0/24"; then
            echo "WARN: bridge-nf-call-iptables=1 and no nftables accept rules"
            echo "      found for 10.20.0.0/24. Inter-bridge UDP may be dropped."
            echo "      On NixOS: import tests/docker/ice-3node/nixos-firewall.nix"
            echo "      Set SKIP_FIREWALL_CHECK=1 to suppress."
        fi
    fi
fi

TIMEOUT_S="${ICE3_TIMEOUT_S:-30}"
SCENARIOS_DIR="scenarios"
SIGNAL_VOL="ice3node_signal"
PASS=0
FAIL=0

# Build the peer harness on the host and stage the binary + plugin
# .so set into `peer/` next to the Dockerfile so `COPY harness` and
# `COPY plugins/` resolve at image-build time. Skipping this on
# `SKIP_HARNESS_BUILD=1` is a developer convenience for iterating on
# the orchestrator without rebuilding C++.
if [ "${SKIP_HARNESS_BUILD:-0}" != "1" ]; then
    echo "=== building peer harness ==="
    bash peer/build-harness.sh

    repo_root="$(cd ../../.. && pwd)"
    build_dir="${BUILD_DIR:-${repo_root}/build-release}"

    # Stage the plugin .so set the harness manifest expects.
    # Plugin set kept narrow: security (null + noise), link (udp +
    # tcp + ice + optional quic), handler-heartbeat. Anything else
    # the dev shell built is dropped — small image layer + the
    # harness mints SHA-256 per-file at start-up so spurious .so
    # bytes are pure overhead.
    mkdir -p peer/plugins
    rm -f peer/plugins/*.so
    for plugin in libgoodnet_security_null.so \
                  libgoodnet_security_noise.so \
                  libgoodnet_link_udp.so \
                  libgoodnet_link_tcp.so \
                  libgoodnet_link_portmap.so \
                  libgoodnet_link_ice.so \
                  libgoodnet_link_quic.so \
                  libgoodnet_handler_heartbeat.so ; do
        if [ -f "${build_dir}/plugins/${plugin}" ]; then
            cp -f "${build_dir}/plugins/${plugin}" "peer/plugins/${plugin}"
        else
            echo "  WARN: missing ${plugin} in ${build_dir}/plugins/" >&2
        fi
    done

    # Stage a statically-linked busybox for the peer image's `ip`
    # / `route` applets. `goodnet:nix-static` ships only coreutils;
    # the peer entrypoint uses `ip route add default via …` to
    # swing the default route through the per-LAN NAT container
    # before invoking the harness. nix's `pkgsStatic.busybox` is
    # the musl + scratch variant; canonical `busybox:latest` is
    # dynamically-linked debian and fails to exec against the
    # nix-store interpreter the base image embeds.
    if [ ! -x peer/busybox-static ]; then
        nix develop --command bash -c \
            'cp -f "$(nix-build --no-link --expr "with import <nixpkgs> {}; pkgsStatic.busybox")/bin/busybox" peer/busybox-static'
        chmod +x peer/busybox-static
    fi

    # Stage the runtime .so closure that the base image (built from
    # rc3) lacks. Run ldd with LD_LIBRARY_PATH cleared so the dynamic
    # linker follows each binary's RUNPATH — not any gcc-15 lib that
    # nix buildInputs inject into the caller's environment — and
    # therefore resolves to the same gcc-16 libstdc++ the harness was
    # compiled against (GLIBCXX_3.4.35).
    mkdir -p peer/libs
    rm -f peer/libs/*.so*
    {
        env -i PATH="${PATH}" LD_LIBRARY_PATH="" ldd peer/harness 2>/dev/null
        for so in peer/plugins/*.so; do
            env -i PATH="${PATH}" LD_LIBRARY_PATH="" ldd "$so" 2>/dev/null
        done
    } | awk '$3 ~ /^\/nix\// { print $3 }' \
      | sort -u \
      | while IFS= read -r lib; do
            cp -L "$lib" "peer/libs/$(basename "$lib")" 2>/dev/null || true
        done

    echo "=== staged $(ls peer/plugins | wc -l) plugin(s) + $(ls peer/libs | wc -l) lib(s) + harness + busybox ==="
fi

# Discover every override; alphabetical so the order is stable.
mapfile -t SCENARIOS < <(find "${SCENARIOS_DIR}" -maxdepth 1 -name "*.yml" | sort)

teardown() {
    docker compose -f docker-compose.yml down --volumes --remove-orphans \
        >/dev/null 2>&1 || true
}

for override in "${SCENARIOS[@]}"; do
    name="$(basename "${override}" .yml)"
    echo "── scenario: ${name} ─────────────────────────────────────────"
    if [ "${name}" = "quic_over_ice" ] && [ "${QUIC_ENABLED:-0}" != "1" ]; then
        echo "  ${name}: SKIP (QUIC_ENABLED not set; set QUIC_ENABLED=1 to run)"
        continue
    fi
    teardown
    if ! docker compose -f docker-compose.yml -f "${override}" \
            up -d --build 2>&1 | sed 's/^/  /'; then
        echo "  ${name}: docker compose up FAILED"
        FAIL=$((FAIL+1))
        continue
    fi

    # Wait for both `.done` markers in the shared volume. The
    # peer harness writes them on first inbound byte from the
    # other peer; absence past TIMEOUT_S means the connect
    # never completed. A `.fail` marker on either side is a
    # hard error — the daemon refused to start or the connect
    # attempt produced a deterministic error — so we break
    # early rather than waste the full timeout.
    deadline=$(( $(date +%s) + TIMEOUT_S ))
    a_done=n; b_done=n; a_fail=n; b_fail=n
    # Read marker files from the shared signal volume directly — avoids
    # the `docker compose exec` race where the command fails on an already-
    # stopped container and the &&-chain echoes n even if the file exists.
    sig_read() {
        docker run --rm -v "${SIGNAL_VOL}:/sig" busybox \
            sh -c "test -f /sig/$1 && echo y || echo n" 2>/dev/null || echo n
    }
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        a_done=$(sig_read A.done)
        b_done=$(sig_read B.done)
        a_fail=$(sig_read A.fail)
        b_fail=$(sig_read B.fail)
        if [ "${a_done}" = "y" ] && [ "${b_done}" = "y" ]; then
            break
        fi
        if [ "${a_fail}" = "y" ] || [ "${b_fail}" = "y" ]; then
            break
        fi
        sleep 1
    done

    if [ "${a_done:-n}" = "y" ] && [ "${b_done:-n}" = "y" ]; then
        echo "  ${name}: PASS"
        PASS=$((PASS+1))
    elif [ "${a_fail:-n}" = "y" ] || [ "${b_fail:-n}" = "y" ]; then
        echo "  ${name}: FAIL (a.fail=${a_fail:-n} b.fail=${b_fail:-n})"
        echo "  --- peer_a logs ---"
        docker compose -f docker-compose.yml logs --tail=50 peer_a | sed 's/^/    /'
        echo "  --- peer_b logs ---"
        docker compose -f docker-compose.yml logs --tail=50 peer_b | sed 's/^/    /'
        FAIL=$((FAIL+1))
    else
        echo "  ${name}: TIMEOUT (a=${a_done:-n} b=${b_done:-n})"
        echo "  --- peer_a logs ---"
        docker compose -f docker-compose.yml logs --tail=50 peer_a | sed 's/^/    /'
        echo "  --- peer_b logs ---"
        docker compose -f docker-compose.yml logs --tail=50 peer_b | sed 's/^/    /'
        FAIL=$((FAIL+1))
    fi
done

teardown
echo
echo "── summary ──────────────────────────────────────────────"
echo "  pass: ${PASS}"
echo "  fail: ${FAIL}"
[ "${FAIL}" -eq 0 ]
