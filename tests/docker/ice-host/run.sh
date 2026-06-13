#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# ice-host runner — single scenario, two peers on one bridge with
# no NAT / STUN / TURN. Pass = both peers exchange host candidates
# through the signal volume, run the RFC 8445 connectivity-check
# salvo, nominate a pair, and exchange a byte. Smallest possible
# ICE smoke test.
#
# Exit code:
#   0 — both peers wrote `.done` markers within TIMEOUT_S
#   1 — at least one side timed out or wrote `.fail`
#
# The peer image is shared with tests/docker/ice-3node — this
# script stages the harness binary + plugin .so set + busybox-static
# into ../ice-3node/peer/ if they're not already there.

set -uo pipefail
cd "$(dirname "$0")"

TIMEOUT_S="${ICEHOST_TIMEOUT_S:-30}"

# Stage the peer image artefacts via the 3-node builder. Idempotent —
# if the binary + plugins are already in place the builder skips
# rebuilds. SKIP_HARNESS_BUILD=1 lets a developer iterate on this
# script without rebuilding C++.
if [ "${SKIP_HARNESS_BUILD:-0}" != "1" ]; then
    echo "=== staging peer image artefacts via ice-3node ==="
    bash ../ice-3node/peer/build-harness.sh

    repo_root="$(cd ../../.. && pwd)"
    build_dir="${BUILD_DIR:-${repo_root}/build-release}"

    mkdir -p ../ice-3node/peer/plugins
    rm -f ../ice-3node/peer/plugins/*.so
    # ice-host needs only the host-candidate path — narrow the
    # plugin set accordingly. portmap / tcp / quic stay opt-in
    # for the harder scenarios.
    for plugin in libgoodnet_security_null.so \
                  libgoodnet_security_noise.so \
                  libgoodnet_link_udp.so \
                  libgoodnet_link_tcp.so \
                  libgoodnet_link_portmap.so \
                  libgoodnet_link_ice.so \
                  libgoodnet_handler_heartbeat.so ; do
        if [ -f "${build_dir}/plugins/${plugin}" ]; then
            cp -f "${build_dir}/plugins/${plugin}" \
                  "../ice-3node/peer/plugins/${plugin}"
        else
            echo "  WARN: missing ${plugin} in ${build_dir}/plugins/" >&2
        fi
    done

    if [ ! -x ../ice-3node/peer/busybox-static ]; then
        nix develop --command bash -c \
            'cp -f "$(nix-build --no-link --expr "with import <nixpkgs> {}; pkgsStatic.busybox")/bin/busybox" ../ice-3node/peer/busybox-static'
        chmod +x ../ice-3node/peer/busybox-static
    fi
fi

teardown() {
    docker compose -f docker-compose.yml down --volumes --remove-orphans \
        >/dev/null 2>&1 || true
}

echo "── scenario: ice-host ──────────────────────────────────────"
teardown
if ! docker compose -f docker-compose.yml up -d --build 2>&1 | sed 's/^/  /'; then
    echo "  ice-host: docker compose up FAILED"
    teardown
    exit 1
fi

# Poll for the report.json markers via the coordinator container.
# Peers exit ~0.2 s after success, so `docker compose exec peer_a`
# would race against their shutdown; the coordinator stays up via
# `sleep infinity` and shares the signal volume.
deadline=$(( $(date +%s) + TIMEOUT_S ))
a_seen=n; b_seen=n
while [ "$(date +%s)" -lt "${deadline}" ]; do
    a_seen=$(docker compose -f docker-compose.yml exec -T coordinator \
        test -f /var/lib/ice3-signal/A.report.json && echo y || echo n)
    b_seen=$(docker compose -f docker-compose.yml exec -T coordinator \
        test -f /var/lib/ice3-signal/B.report.json && echo y || echo n)
    if [ "${a_seen}" = "y" ] && [ "${b_seen}" = "y" ]; then break; fi
    sleep 1
done

if [ "${a_seen}" != "y" ] || [ "${b_seen}" != "y" ]; then
    echo "  ice-host: TIMEOUT (a.report=${a_seen} b.report=${b_seen})"
    echo "  --- peer_a logs ---"
    docker compose -f docker-compose.yml logs --tail=80 peer_a | sed 's/^/    /'
    echo "  --- peer_b logs ---"
    docker compose -f docker-compose.yml logs --tail=80 peer_b | sed 's/^/    /'
    teardown
    exit 1
fi

# Fetch report bodies from the coordinator. Cat-from-container avoids
# the host-vs-container UID + volume-permission tangle.
report_a=$(docker compose -f docker-compose.yml exec -T coordinator \
    cat /var/lib/ice3-signal/A.report.json)
report_b=$(docker compose -f docker-compose.yml exec -T coordinator \
    cat /var/lib/ice3-signal/B.report.json)

# Pretty-print a per-peer line. Format:
#   A: host/host udp rtt=1.8ms relay=0 first_byte=152ms (cand l=h2/s0/r0 r=h2/s0/r0)
format_line() {
    local label="$1"
    local body="$2"
    jq -r --arg label "${label}" '
        def ms(us): if us == null then "n/a"
                    else ((us | tonumber) / 1000 | tostring) + "ms" end;
        "  \($label): " +
        "\(.local_type)/\(.remote_type) \(.transport) " +
        "rtt=\(ms(.rtt_us)) " +
        "relay=\(if .uses_relay then 1 else 0 end) " +
        "first_byte=\(ms(.first_byte_rx_us)) " +
        "(cand l=h\(.candidates.local.host)/s\(.candidates.local.srflx)/r\(.candidates.local.relay) " +
        "r=h\(.candidates.remote.host)/s\(.candidates.remote.srflx)/r\(.candidates.remote.relay))" +
        (if .nominated then " OK" else " NOT-NOMINATED" end) +
        (if .fail_reason then " fail=\(.fail_reason)" else "" end)
    ' <<< "${body}"
}

format_line "A" "${report_a}"
format_line "B" "${report_b}"

# Scenario pass criteria. ice-host: both nominated, neither used relay,
# host-to-host pair on UDP. Stay loose on transport (TCP fallback is
# acceptable on the local docker bridge) but strict on relay.
pass=1
for body in "${report_a}" "${report_b}"; do
    nominated=$(jq -r '.nominated' <<< "${body}")
    uses_relay=$(jq -r '.uses_relay' <<< "${body}")
    local_type=$(jq -r '.local_type' <<< "${body}")
    remote_type=$(jq -r '.remote_type' <<< "${body}")
    if [ "${nominated}" != "true" ]; then pass=0; fi
    if [ "${uses_relay}" != "false" ]; then pass=0; fi
    case "${local_type}" in host|host_mdns) ;; *) pass=0 ;; esac
    case "${remote_type}" in host|host_mdns) ;; *) pass=0 ;; esac
done

if [ "${pass}" = "1" ]; then
    echo "  ice-host: PASS"
    teardown
    exit 0
fi

echo "  ice-host: FAIL (criteria: nominated=true, uses_relay=false, host-only pair)"
echo "  --- peer_a logs ---"
docker compose -f docker-compose.yml logs --tail=80 peer_a | sed 's/^/    /'
echo "  --- peer_b logs ---"
docker compose -f docker-compose.yml logs --tail=80 peer_b | sed 's/^/    /'
teardown
exit 1
