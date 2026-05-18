#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Boot the real coturn on loopback:3479 in the background, then
# exec the flaky shim on the wildcard 3478 port so peers hit the
# shim first. Shim flips from "respond 500" to "passthrough" once
# TURN_FAIL_COUNT requests have arrived.
set -eu

: "${TURN_FAIL_COUNT:=5}"
export TURN_FAIL_COUNT

# Render the conf at runtime so realm/user/pass env overrides win
# over the build-time defaults baked into the image.
sed \
    -e "s|\${TURN_REALM}|${TURN_REALM:-ice3.local}|g" \
    -e "s|\${TURN_USER}|${TURN_USER:-goodnet}|g" \
    -e "s|\${TURN_PASS}|${TURN_PASS:-bench-only-credentials}|g" \
    /etc/turnserver.conf > /etc/turnserver.conf.rendered
mv /etc/turnserver.conf.rendered /etc/turnserver.conf

turnserver -c /etc/turnserver.conf &
COTURN_PID=$!

# If coturn dies the shim should die with it so the container
# restarts as one unit.
trap "kill ${COTURN_PID} 2>/dev/null || true" EXIT TERM INT

exec python3 /usr/local/bin/flaky-shim.py
