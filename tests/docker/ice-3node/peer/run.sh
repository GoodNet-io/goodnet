#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Peer entrypoint. Three responsibilities:
#
# 1. Template the kernel config out of environment vars handed in
#    by docker-compose (PEER_NAME, STUN_URI, TURN_URI, WAIT_FOR_PEER,
#    SIGNAL_DIR, plus optional knobs for rc5 scenarios).
# 2. Boot the goodnetd daemon with ICE + heartbeat + noise loaded.
# 3. Run the harness:
#    * publish our pubkey to the shared signal dir
#    * wait for the peer's pubkey
#    * trigger an ICE connect to it
#    * on first inbound byte, write `${SIGNAL_DIR}/${PEER_NAME}.done`
#
# Exits 0 on success, non-zero on timeout. The scenario test scripts
# assert on the `.done` file in run_all.sh.
#
# Scaffolding only — the harness binary that does the connect
# dance is not in tree yet; this script prints the template
# config + a placeholder waiter so an operator running
# `docker compose up` sees the wiring is correct before the C++
# harness lands.

set -eu

: "${PEER_NAME:?PEER_NAME unset}"
: "${SIGNAL_DIR:=/var/lib/ice3-signal}"
: "${STUN_URI:=stun://10.10.0.10:3478}"
: "${TURN_URI:=turn://goodnet:bench-only-credentials@10.10.0.11:3478}"
: "${WAIT_FOR_PEER:=B}"

# Optional secondary STUN / TURN — empty unless the scenario sets
# them. Comma-separated lists are accepted for either knob; the
# loop below splits and emits each as a JSON string literal.
: "${STUN_URI_EXTRA:=}"
: "${TURN_URI_EXTRA:=}"

# rc5 ICE knobs — every scenario picks safe defaults so the
# existing fixtures don't have to know about them. The schema
# treats missing keys as defaults too, but emitting them with
# explicit values keeps the rendered config diffable.
: "${TURN_BACKUP_INTERVAL_S:=5}"
: "${ICE_LITE_MODE:=false}"
: "${ICE_MDNS_OBFUSCATE:=false}"
: "${ICE_ENABLE_IPV6:=false}"
: "${ICE_PMTU_ACTIVE_PROBING:=false}"
: "${ICE_PORT_PREDICTION_STRIDE_MAX:=0}"
: "${ICE_TCP_TLS_ONLY:=false}"

# QUIC-over-ICE knob. When true, load gn.link.quic alongside
# gn.link.ice and switch the default connect scheme to
# `quic://<peer-pk>` — the 64-hex peer-pk in the URI triggers
# carrier=ice routing inside the QUIC composer, so the handshake
# rides the UDP socket ICE nominated rather than opening a fresh
# one.
: "${QUIC_OVER_ICE:=false}"
if [ "${QUIC_OVER_ICE}" = "true" ]; then
    QUIC_PLUGIN_ENTRY=', { "name": "goodnet_link_quic", "path": "/plugins/libgoodnet_link_quic.so" }'
    CONNECT_SCHEME="quic"
else
    QUIC_PLUGIN_ENTRY=""
    CONNECT_SCHEME="udp"
fi

mkdir -p "${SIGNAL_DIR}" /etc/goodnet /var/lib/goodnet

# Build a JSON-array body for the stun/turn server lists by
# concatenating the primary URI with anything in STUN_URI_EXTRA /
# TURN_URI_EXTRA (comma separated). Quoting is plain "..." since
# every URI in the harness is ASCII.
join_uris() {
    primary="$1"
    extras="$2"
    out="\"${primary}\""
    if [ -n "${extras}" ]; then
        IFS=','
        for u in ${extras}; do
            u=$(echo "${u}" | sed 's/^ *//;s/ *$//')
            [ -z "${u}" ] && continue
            out="${out}, \"${u}\""
        done
        unset IFS
    fi
    printf '%s' "${out}"
}

STUN_SERVERS_JSON="$(join_uris "${STUN_URI}" "${STUN_URI_EXTRA}")"
TURN_SERVERS_JSON="$(join_uris "${TURN_URI}" "${TURN_URI_EXTRA}")"

# Materialise the per-peer config out of the template.
sed \
    -e "s|@PEER_NAME@|${PEER_NAME}|g" \
    -e "s|@STUN_SERVERS_JSON@|${STUN_SERVERS_JSON}|g" \
    -e "s|@TURN_SERVERS_JSON@|${TURN_SERVERS_JSON}|g" \
    -e "s|@TURN_USER@|${TURN_USER:-goodnet}|g" \
    -e "s|@TURN_PASS@|${TURN_PASS:-bench-only-credentials}|g" \
    -e "s|@WAIT_FOR_PEER@|${WAIT_FOR_PEER}|g" \
    -e "s|@SIGNAL_DIR@|${SIGNAL_DIR}|g" \
    -e "s|@TURN_BACKUP_INTERVAL_S@|${TURN_BACKUP_INTERVAL_S}|g" \
    -e "s|@ICE_LITE_MODE@|${ICE_LITE_MODE}|g" \
    -e "s|@ICE_MDNS_OBFUSCATE@|${ICE_MDNS_OBFUSCATE}|g" \
    -e "s|@ICE_ENABLE_IPV6@|${ICE_ENABLE_IPV6}|g" \
    -e "s|@ICE_PMTU_ACTIVE_PROBING@|${ICE_PMTU_ACTIVE_PROBING}|g" \
    -e "s|@ICE_PORT_PREDICTION_STRIDE_MAX@|${ICE_PORT_PREDICTION_STRIDE_MAX}|g" \
    -e "s|@ICE_TCP_TLS_ONLY@|${ICE_TCP_TLS_ONLY}|g" \
    -e "s|@QUIC_PLUGIN_ENTRY@|${QUIC_PLUGIN_ENTRY}|g" \
    -e "s|@CONNECT_SCHEME@|${CONNECT_SCHEME}|g" \
    /etc/goodnet/peer.json.tmpl > /etc/goodnet/peer.json

echo "[peer-${PEER_NAME}] config:"
cat /etc/goodnet/peer.json

# Boot the kernel. Production builds wire the harness binary in
# place of this stub which only prints + sleeps so the
# scaffolding can be inspected with `docker compose logs peer_a`.
#
# On normal exit the harness has already written
# `${SIGNAL_DIR}/${PEER_NAME}.done` for inbound-byte success.
# A non-zero exit (or daemon refusal to start) drops a
# `${SIGNAL_DIR}/${PEER_NAME}.fail` marker so the orchestrator
# can distinguish hard failure from a slow connect.
if command -v goodnetd >/dev/null 2>&1; then
    echo "[peer-${PEER_NAME}] starting goodnetd"
    set +e
    goodnetd run --config /etc/goodnet/peer.json
    rc=$?
    set -e
    if [ "${rc}" -ne 0 ]; then
        echo "[peer-${PEER_NAME}] goodnetd exited rc=${rc} — writing .fail"
        : > "${SIGNAL_DIR}/${PEER_NAME}.fail"
    fi
    exit "${rc}"
fi

echo "[peer-${PEER_NAME}] NOTE: goodnetd binary not in PATH" \
     "— peer harness stub keeps container alive for inspection." \
     "Replace with the harness binary when it lands."
exec sleep infinity
