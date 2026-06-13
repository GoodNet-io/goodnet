#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build the ice-3node peer harness via the dev shell and stage it
# next to the Dockerfile so `COPY harness` in the image build
# resolves. Prints the final staged path on stdout for callers that
# want to verify.
#
# Idempotent — re-running just re-invokes ninja, which short-circuits
# when nothing changed.

set -euo pipefail

# Resolve the repo root (`..`/`..`/`..`/`..` from this script).
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../../.." && pwd)"

build_dir="${BUILD_DIR:-${repo_root}/build-release}"
staged_binary="${script_dir}/harness"

if [ ! -d "${build_dir}" ]; then
    echo "build-harness: ${build_dir} does not exist — run cmake configure first" >&2
    exit 1
fi

# `nix develop --command` resolves the dev shell tools (cmake, gcc15,
# ninja, OpenSSL headers, libsodium, …) before invoking ninja.
echo "[build-harness] ninja peer_harness in ${build_dir}"
(
    cd "${repo_root}"
    nix develop --command bash -c "cd '${build_dir}' && ninja peer_harness"
)

built_binary="${build_dir}/tests/docker/ice-3node/peer/harness"
if [ ! -x "${built_binary}" ]; then
    echo "build-harness: expected binary at ${built_binary} not found" >&2
    exit 1
fi

cp -f "${built_binary}" "${staged_binary}"
chmod +x "${staged_binary}"

# Stage the discovery plugin .so alongside the other plugins.
# goodnet_link_ice depends on the gn.discovery.mdns extension for
# mDNS host-candidate obfuscation (ipv6_mdns scenario).
mdns_so="${build_dir}/plugins/libgoodnet_discovery_mdns.so"
if [[ -f "${mdns_so}" ]]; then
    cp -f "${mdns_so}" "${script_dir}/plugins/libgoodnet_discovery_mdns.so"
    echo "[build-harness] staged libgoodnet_discovery_mdns.so"
fi

echo "[build-harness] staged ${staged_binary} ($(stat -c '%s' "${staged_binary}") bytes)"
echo "${staged_binary}"
