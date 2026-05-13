#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fetch libuv into the bench cache so dx_loc_count.sh can read the
# canonical "echo" upstream example. The actual libuv build is not
# needed — we only count source lines from one client + server pair.

set -euo pipefail

cache="${GN_BENCH_REFS_DIR:-$HOME/.cache/goodnet-bench-refs}/libuv"
mkdir -p "$cache"

if [[ ! -d "$cache/upstream/.git" ]]; then
    git clone --depth 1 https://github.com/libuv/libuv "$cache/upstream"
else
    (cd "$cache/upstream" && git fetch --depth 1 origin && git reset --hard origin/HEAD) >/dev/null
fi

# libuv's "echo" example lives in docs/code/tcp-echo-server. We
# point at the two split files the dx_loc_count.sh expects.
ln -sf "$cache/upstream/docs/code/tcp-echo-server/main.c" "$cache/echo_server.c"
# libuv has no symmetric echo client example shipped — the simplest
# upstream "hello world" client lives under uvcat (one source file
# does both connect + read + print). Treat the uvcat sample as the
# DX baseline for the client side.
ln -sf "$cache/upstream/docs/code/uvcat/main.c" "$cache/echo_client.c"

echo "libuv baseline ready:"
echo "  server = $cache/echo_server.c"
echo "  client = $cache/echo_client.c"
