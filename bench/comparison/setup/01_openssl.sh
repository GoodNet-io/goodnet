#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Stage OpenSSL s_server / s_client as the TLS baseline. Operators
# already have `openssl` on path almost everywhere — this script just
# generates the self-signed cert + key the throughput / handshake
# runners reuse.

set -euo pipefail

cache="${GN_BENCH_REFS_DIR:-$HOME/.cache/goodnet-bench-refs}/openssl"
mkdir -p "$cache"

cd "$cache"

# Idempotent: re-run is a no-op when the cert is already present.
if [[ ! -f cert.pem || ! -f key.pem ]]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout key.pem -out cert.pem -days 30 \
        -subj "/CN=goodnet-bench-openssl" \
        -addext "subjectAltName=IP:127.0.0.1" \
        >/dev/null 2>&1
fi

cat <<EOF
openssl baseline ready:
  cert = $cache/cert.pem
  key  = $cache/key.pem

# Run server (in another terminal):
openssl s_server -accept 14443 -cert $cache/cert.pem -key $cache/key.pem -quiet

# Run client one-shot:
echo hello | openssl s_client -connect 127.0.0.1:14443 -quiet 2>/dev/null
EOF
