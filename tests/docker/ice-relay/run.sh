#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# ice-relay runner — two peers, each behind its own symmetric NAT,
# with STUN + TURN servers reachable. Symmetric NAT randomises the
# WAN port per destination, so the srflx tuple a peer learns from
# the STUN check is useless against the other peer's contact. The
# only working path is via TURN — both peers allocate a relay and
# nominate the relay/relay pair.
#
# Exit code:
#   0 — both peers produced report.json AND nominated a relay pair
#   1 — at least one side timed out, failed, or nominated something
#       other than a relay pair

set -uo pipefail
cd "$(dirname "$0")"

TIMEOUT_S="${ICERELAY_TIMEOUT_S:-75}"

if [ "${SKIP_HARNESS_BUILD:-0}" != "1" ]; then
    echo "=== staging peer image artefacts via ice-3node ==="
    bash ../ice-3node/peer/build-harness.sh

    repo_root="$(cd ../../.. && pwd)"
    build_dir="${BUILD_DIR:-${repo_root}/build-release}"

    mkdir -p ../ice-3node/peer/plugins
    rm -f ../ice-3node/peer/plugins/*.so
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

echo "── scenario: ice-relay ─────────────────────────────────────"
teardown
if ! docker compose -f docker-compose.yml up -d --build 2>&1 | sed 's/^/  /'; then
    echo "  ice-relay: docker compose up FAILED"
    teardown
    exit 1
fi

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
    echo "  ice-relay: TIMEOUT (a.report=${a_seen} b.report=${b_seen})"
    echo "  --- peer_a logs ---"
    docker compose -f docker-compose.yml logs --tail=80 peer_a | sed 's/^/    /'
    echo "  --- peer_b logs ---"
    docker compose -f docker-compose.yml logs --tail=80 peer_b | sed 's/^/    /'
    teardown
    exit 1
fi

report_a=$(docker compose -f docker-compose.yml exec -T coordinator \
    cat /var/lib/ice3-signal/A.report.json)
report_b=$(docker compose -f docker-compose.yml exec -T coordinator \
    cat /var/lib/ice3-signal/B.report.json)

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

# ice-relay pass criteria: both nominated, relay candidate gathered
# locally (proves TURN allocation), uses_relay=true on both sides.
# We don't pin local_type/remote_type because the controlled side's
# pair retains its signaled candidate types — what matters is the
# uses_relay flag on the effective transport.
pass=1
for body in "${report_a}" "${report_b}"; do
    nominated=$(jq -r '.nominated' <<< "${body}")
    uses_relay=$(jq -r '.uses_relay' <<< "${body}")
    local_relay=$(jq -r '.candidates.local.relay' <<< "${body}")
    if [ "${nominated}"  != "true" ]; then pass=0; fi
    if [ "${uses_relay}" != "true" ]; then pass=0; fi
    if [ "${local_relay}" -lt 1 ];    then pass=0; fi
done

if [ "${pass}" = "1" ]; then
    echo "  ice-relay: PASS"
    teardown
    exit 0
fi

echo "  ice-relay: FAIL (criteria: nominated=true, uses_relay=true, relay gathered)"
echo "  --- peer_a logs ---"
docker compose -f docker-compose.yml logs --tail=80 peer_a | sed 's/^/    /'
echo "  --- peer_b logs ---"
docker compose -f docker-compose.yml logs --tail=80 peer_b | sed 's/^/    /'
teardown
exit 1
