#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fetch OpenSSL's demos/ tree for the sslecho example — the
# canonical "minimal OpenSSL TLS hello echo" upstream ships.

set -euo pipefail

cache="${GN_BENCH_REFS_DIR:-$HOME/.cache/goodnet-bench-refs}/openssl"
mkdir -p "$cache"

if [[ ! -d "$cache/upstream/.git" ]]; then
    # `--filter=blob:none` would be ideal but some hosts don't have
    # partial-clone support; depth 1 is small enough.
    git clone --depth 1 https://github.com/openssl/openssl "$cache/upstream"
else
    (cd "$cache/upstream" && git fetch --depth 1 origin && git reset --hard origin/HEAD) >/dev/null
fi

# sslecho is the upstream "hello world" — one source file with both
# client + server roles selected by argv[1]. Symlink it twice so the
# LOC counter sees a "client" + "server" pair (both halves live in
# the same TU, which is itself a DX comment — split into two files
# in any non-toy production setup).
ln -sf "$cache/upstream/demos/sslecho/main.c" "$cache/sample_client.c"
ln -sf "$cache/upstream/demos/sslecho/main.c" "$cache/sample_server.c"

echo "openssl sslecho baseline ready (single-file client+server):"
echo "  $cache/sample_{client,server}.c -> demos/sslecho/main.c"
