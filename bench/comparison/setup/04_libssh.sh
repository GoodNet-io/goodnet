#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fetch libssh upstream mirror for DX LOC reference. The examples
# directory has both client + server samples (exec_main.c +
# sshd_direct-tcpip.c). We pick the smallest pair that maps cleanly
# to "connect, send buffer, print response, shut down".

set -euo pipefail

cache="${GN_BENCH_REFS_DIR:-$HOME/.cache/goodnet-bench-refs}/libssh"
mkdir -p "$cache"

# GitLab mirror is the upstream; GitHub has read-only mirrors that
# work as a fallback.
url="https://git.libssh.org/projects/libssh.git/"
fallback="https://github.com/libssh/libssh-mirror.git"

if [[ ! -d "$cache/upstream/.git" ]]; then
    if ! git clone --depth 1 "$url" "$cache/upstream" 2>/dev/null; then
        git clone --depth 1 "$fallback" "$cache/upstream"
    fi
else
    (cd "$cache/upstream" && git pull --depth 1 origin HEAD) >/dev/null 2>&1 || true
fi

# exec_main + sshd_direct-tcpip cover client + server respectively.
ln -sf "$cache/upstream/examples/exec_main.c"          "$cache/exec_client.c"
ln -sf "$cache/upstream/examples/sshd_direct-tcpip.c"  "$cache/exec_server.c"

echo "libssh baseline ready:"
echo "  client = $cache/exec_client.c"
echo "  server = $cache/exec_server.c"
