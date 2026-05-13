#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Peer entrypoint. Three responsibilities:
#
# 1. Template the kernel config out of environment vars handed in
#    by docker-compose (PEER_NAME, STUN_URI, TURN_URI, WAIT_FOR_PEER,
#    SIGNAL_DIR).
# 2. Boot the goodnet kernel with ICE + heartbeat + noise loaded.
# 3. Run the harness:
#    * publish our pubkey to the shared signal dir
#    * wait for the peer's pubkey
#    * trigger an ICE connect to it
#    * on first inbound byte, write `${SIGNAL_DIR}/${PEER_NAME}.done`
#
# Exits 0 on success, non-zero on timeout. The scenario test scripts
# assert on the `.done` file in run_all.sh.
#
# Slice-1 scope: scaffolding only — the harness binary that does the
# connect dance is intentionally not in tree yet; this script prints
# the template config + a placeholder waiter so an operator running
# `docker compose up` sees the wiring is correct before the C++
# harness lands.

set -eu

: "${PEER_NAME:?PEER_NAME unset}"
: "${SIGNAL_DIR:=/var/lib/ice3-signal}"
: "${STUN_URI:=stun://10.10.0.10:3478}"
: "${TURN_URI:=turn://goodnet:bench-only-credentials@10.10.0.11:3478}"
: "${WAIT_FOR_PEER:=B}"

mkdir -p "${SIGNAL_DIR}" /etc/goodnet /var/lib/goodnet

# Materialise the per-peer config out of the template.
sed \
    -e "s|@PEER_NAME@|${PEER_NAME}|g" \
    -e "s|@STUN_URI@|${STUN_URI}|g" \
    -e "s|@TURN_URI@|${TURN_URI}|g" \
    -e "s|@TURN_USER@|${TURN_USER:-goodnet}|g" \
    -e "s|@TURN_PASS@|${TURN_PASS:-bench-only-credentials}|g" \
    -e "s|@WAIT_FOR_PEER@|${WAIT_FOR_PEER}|g" \
    -e "s|@SIGNAL_DIR@|${SIGNAL_DIR}|g" \
    /etc/goodnet/peer.json.tmpl > /etc/goodnet/peer.json

echo "[peer-${PEER_NAME}] config:"
cat /etc/goodnet/peer.json

# Boot the kernel. Production builds wire the harness binary in
# place of this stub which only prints + sleeps so the
# scaffolding can be inspected with `docker compose logs peer_a`.
if command -v goodnet >/dev/null 2>&1; then
    echo "[peer-${PEER_NAME}] starting goodnet kernel"
    exec goodnet --config /etc/goodnet/peer.json
fi

echo "[peer-${PEER_NAME}] NOTE: goodnet binary not in PATH" \
     "— peer harness stub keeps container alive for inspection." \
     "Replace with the harness binary in a follow-up slice."
exec sleep infinity
