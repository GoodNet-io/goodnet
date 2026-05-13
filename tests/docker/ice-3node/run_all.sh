#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Iterate every scenario override under scenarios/*.yml against the
# base docker-compose.yml. For each one:
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
# Slice-1 scope: the loop machinery + per-scenario teardown lands
# now; the actual connect-and-write-done logic depends on the peer
# harness binary (`peer/run.sh` placeholder) which is a follow-up.
# Running this script today brings up the topology cleanly and
# always reports timeout — useful for shape-checking the compose
# wiring before the harness binary exists.

set -uo pipefail

cd "$(dirname "$0")"

TIMEOUT_S="${ICE3_TIMEOUT_S:-60}"
SCENARIOS_DIR="scenarios"
SIGNAL_VOL="ice3node_signal"
PASS=0
FAIL=0

# Discover every override; alphabetical so the order is stable.
mapfile -t SCENARIOS < <(find "${SCENARIOS_DIR}" -maxdepth 1 -name "*.yml" | sort)

teardown() {
    docker compose -f docker-compose.yml down --volumes --remove-orphans \
        >/dev/null 2>&1 || true
}

for override in "${SCENARIOS[@]}"; do
    name="$(basename "${override}" .yml)"
    echo "── scenario: ${name} ─────────────────────────────────────────"
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
    # never completed.
    deadline=$(( $(date +%s) + TIMEOUT_S ))
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        a_done=$(docker compose -f docker-compose.yml exec -T peer_a \
            test -f /var/lib/ice3-signal/A.done && echo y || echo n)
        b_done=$(docker compose -f docker-compose.yml exec -T peer_b \
            test -f /var/lib/ice3-signal/B.done && echo y || echo n)
        if [ "${a_done}" = "y" ] && [ "${b_done}" = "y" ]; then
            break
        fi
        sleep 1
    done

    if [ "${a_done:-n}" = "y" ] && [ "${b_done:-n}" = "y" ]; then
        echo "  ${name}: PASS"
        PASS=$((PASS+1))
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
