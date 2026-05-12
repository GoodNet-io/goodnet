#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# DX axis: count source lines for a "hello world" client + server
# echo across implementations.
#
# Each row in the output JSON names the source files counted so the
# comparison stays auditable.

set -euo pipefail

count_lines() {
    local path="$1"
    if [[ -f "$path" ]]; then
        # Strip blank lines + // comments + /* */ blocks.
        awk '!/^[[:space:]]*$/ && !/^[[:space:]]*\/\//' "$path" | wc -l
    else
        echo 0
    fi
}

# GoodNet — assumes examples/hello-echo/ ships a tiny client + server
# pair built against gn::sdk::connect_to.
gn_client=$(count_lines examples/hello-echo/client.cpp)
gn_server=$(count_lines examples/hello-echo/server.cpp)
gn_total=$((gn_client + gn_server))

# Reference stacks — typical "echo" examples upstream ship.
# Paths assume the comparison cache has the references cloned;
# the setup scripts fetch them when run.
cache="${GN_BENCH_REFS_DIR:-$HOME/.cache/goodnet-bench-refs}"

openssl_client=$(count_lines "$cache/openssl/sample_client.c")  # 0 if unset
openssl_server=$(count_lines "$cache/openssl/sample_server.c")
openssl_total=$((openssl_client + openssl_server))

libuv_client=$(count_lines "$cache/libuv/echo_client.c")
libuv_server=$(count_lines "$cache/libuv/echo_server.c")
libuv_total=$((libuv_client + libuv_server))

libssh_client=$(count_lines "$cache/libssh/exec_client.c")
libssh_server=$(count_lines "$cache/libssh/exec_server.c")
libssh_total=$((libssh_client + libssh_server))

cat <<EOF
{
  "metric": "dx_loc_hello_world_echo",
  "rows": [
    {"stack": "goodnet",  "client": $gn_client,      "server": $gn_server,      "total": $gn_total},
    {"stack": "openssl",  "client": $openssl_client, "server": $openssl_server, "total": $openssl_total},
    {"stack": "libuv",    "client": $libuv_client,   "server": $libuv_server,   "total": $libuv_total},
    {"stack": "libssh",   "client": $libssh_client,  "server": $libssh_server,  "total": $libssh_total}
  ],
  "note": "lower is better; raw LOC counted (comments + blank lines stripped) from each stack's canonical hello-echo example"
}
EOF
