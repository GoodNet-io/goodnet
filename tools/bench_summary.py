#!/usr/bin/env python3
"""Print a one-line-per-benchmark summary from a Google Benchmark JSON.

Used by the `bench-smoke` CI job when no baseline file is committed
for a given binary — instead of gating on regression, the job just
echoes the numbers so the run is still useful as a smoke check that
the bench harness produced non-zero metering.

Usage:
    python3 tools/bench_summary.py path/to/bench.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: bench_summary.py <bench.json>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.exists():
        print(f"bench_summary: {path} not found", file=sys.stderr)
        return 1
    data = json.loads(path.read_text())
    rows = [
        b for b in data.get("benchmarks", [])
        if b.get("run_type") == "iteration"
    ]
    if not rows:
        print(f"  (no iteration rows in {path.name})")
        return 0
    name_w = max(len(b.get("name", "")) for b in rows)
    for b in rows:
        name = b.get("name", "")
        cpu_ns = b.get("cpu_time", 0.0)
        bps = b.get("bytes_per_second")
        bps_str = f"  {bps / (1024 * 1024):.1f} MiB/s" if bps else ""
        print(f"  {name:<{name_w}}  {cpu_ns:>10.0f} ns{bps_str}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
