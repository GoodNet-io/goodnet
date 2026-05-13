#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Emit a JSON describing every shippable artifact's size: kernel
# binary, plugin .so files, the all-in-one static build, the Nix
# store closure for the kernel derivation, and (optionally) a
# Docker image built from the static binary. Output flows into
# `aggregate.py` and lands as the `## Binary sizes` section of the
# bench report.
#
# Caveat: closure size reflects the Nix store dependency tree
# (libsodium, libstdc++, asio, …) — the bytes a fresh `nix profile
# install` would copy. The local-disk install can de-duplicate
# against existing store entries, so this number is the *worst
# case* an operator would pay, not what they actually pay.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

dyn_kernel=""
dyn_plugins_total=0
dyn_plugin_count=0
static_kernel=""
static_stripped=""
closure_kb=""
docker_image_kb=""

if [[ -f build-release/bin/goodnet ]]; then
    dyn_kernel=$(stat -c %s build-release/bin/goodnet)
fi
_plugin_so_count=$(find build-release/plugins -maxdepth 1 -name 'lib*.so' 2>/dev/null | wc -l)
if [[ ${_plugin_so_count:-0} -gt 0 ]]; then
    dyn_plugins_total=$(find build-release/plugins -maxdepth 1 -name 'lib*.so' \
        -printf '%s\n' 2>/dev/null |
        awk '{s+=$1} END {print s+0}')
    dyn_plugin_count=$_plugin_so_count
fi
if [[ -f build-static/bin/goodnet ]]; then
    static_kernel=$(stat -c %s build-static/bin/goodnet)
    tmp_strip=$(mktemp)
    cp build-static/bin/goodnet "$tmp_strip"
    strip "$tmp_strip" 2>/dev/null || true
    static_stripped=$(stat -c %s "$tmp_strip")
    rm -f "$tmp_strip"
fi

# Nix store closure for the kernel derivation. `nix path-info -S
# --closure-size` reports the full transitive closure in bytes.
# Run inside the dev shell so the same nix binary that built the
# tree resolves the derivation path.
if command -v nix >/dev/null 2>&1; then
    if closure_path=$(nix build --no-link --print-out-paths .#goodnet-core 2>/dev/null); then
        if [[ -n "$closure_path" ]]; then
            closure_kb=$(nix path-info -S "$closure_path" 2>/dev/null |
                awk '{print int($2/1024)}')
        fi
    fi
fi

# Optional Docker image from the static binary. The Dockerfile
# pins a `gcr.io/distroless/cc-debian12` base (~22 MiB) and copies
# only the binary on top. We build it as `goodnet:bench-static`
# and report the resulting image size; the build is best-effort
# and silently skipped when docker is unreachable.
if command -v docker >/dev/null 2>&1 && \
   docker info >/dev/null 2>&1 && \
   [[ -f build-static/bin/goodnet ]] && \
   [[ -f dist/Dockerfile.static ]]; then
    tmpctx=$(mktemp -d)
    cp build-static/bin/goodnet "$tmpctx/goodnet"
    cp dist/Dockerfile.static "$tmpctx/Dockerfile"
    if docker build -q -t goodnet:bench-static "$tmpctx" >/dev/null 2>&1; then
        # docker image inspect's `Size` is the layer-summed bytes,
        # ignoring shared base layers — matches what `docker images`
        # would charge an operator.
        docker_image_kb=$(docker image inspect goodnet:bench-static \
            --format '{{.Size}}' 2>/dev/null |
            awk '{print int($1/1024)}')
    fi
    rm -rf "$tmpctx"
fi

cat <<EOF
{
  "metric": "binary_sizes",
  "kernel_dynamic_bytes": ${dyn_kernel:-null},
  "plugins_sum_bytes":    ${dyn_plugins_total:-0},
  "plugin_count":         ${dyn_plugin_count:-0},
  "kernel_static_bytes":  ${static_kernel:-null},
  "kernel_static_stripped_bytes": ${static_stripped:-null},
  "nix_closure_kb":       ${closure_kb:-null},
  "docker_image_kb":      ${docker_image_kb:-null}
}
EOF
