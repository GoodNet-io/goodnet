#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# iperf3 — universal TCP / UDP throughput baseline. Most distros
# carry it; this setup script just verifies the binary is on path
# and prints version info.

set -euo pipefail

if ! command -v iperf3 >/dev/null 2>&1; then
    echo "iperf3 missing — install via your package manager" >&2
    echo "  nixos: nix-env -iA nixpkgs.iperf3" >&2
    echo "  debian: apt install iperf3" >&2
    echo "  arch: pacman -S iperf3" >&2
    exit 1
fi

iperf3 --version | head -1
echo "iperf3 baseline ready"
