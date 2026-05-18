#!/usr/bin/env python3
"""Compare two Google Benchmark JSON outputs and flag regressions.

Usage:
    python3 tools/bench_compare.py baseline.json current.json [--threshold-pct 5]

Reads two `--benchmark_format=json` outputs from Google Benchmark
runs (the kernel's `bench_*` binaries emit this natively) and
prints a per-benchmark table with delta in cpu_time. Exits
non-zero when any benchmark's cpu_time regressed by more than
the threshold (default 5 percent).

Designed for the `bench-CI` regression gate: store a baseline
JSON next to the kernel source tree (committed to main on
intentional perf changes), run `bench_*` on PR, feed both to
this tool. The exit code is the CI signal — print output stays
informational so reviewers can see which benchmark moved.

The script does not require dependencies beyond the standard
library so it runs in any Nix devShell or CI runner without
extra setup. Picks the median (`real_time` if present else
`cpu_time`) and discards Google Benchmark's aggregate rows
(suffix `_mean`, `_median`, `_stddev`) to avoid double-counting.

Smoke tests live in `tests/tools/test_bench_compare.py` (8
cases pinning the regression detection + new/gone annotations
+ zero-baseline absolute-delta fallback).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Sample:
    """Selected metric per benchmark identity."""

    name: str
    cpu_time_us: float
    real_time_us: float


def load_samples(path: Path) -> dict[str, Sample]:
    """Parse the Google Benchmark JSON at @p path into a name → Sample map."""
    raw = json.loads(path.read_text())
    out: dict[str, Sample] = {}
    for entry in raw.get("benchmarks", []):
        name = entry.get("name", "")
        # Skip aggregate rows — they double-count individual iterations.
        if name.endswith(("_mean", "_median", "_stddev", "_cv")):
            continue
        if entry.get("aggregate_name") in ("mean", "median", "stddev", "cv"):
            continue
        # Google Benchmark reports cpu_time in time_unit; convert to us.
        unit = entry.get("time_unit", "ns")
        scale = {"ns": 1e-3, "us": 1.0, "ms": 1e3, "s": 1e6}.get(unit, 1.0)
        cpu = float(entry.get("cpu_time", 0.0)) * scale
        real = float(entry.get("real_time", 0.0)) * scale
        out[name] = Sample(name=name, cpu_time_us=cpu, real_time_us=real)
    return out


def compare(baseline: dict[str, Sample],
            current: dict[str, Sample],
            threshold_pct: float) -> int:
    """Print delta table and return non-zero exit code on regression.

    Each benchmark present in both inputs is reported. Benchmarks
    only in `current` are noted as new (no regression check).
    Benchmarks only in `baseline` are noted as removed.
    """
    regressions = 0
    print(f"{'benchmark':<60} {'baseline_us':>14} {'current_us':>14} {'delta_pct':>10}")
    print("-" * 100)

    for name in sorted(baseline.keys() | current.keys()):
        b = baseline.get(name)
        c = current.get(name)
        if b is None:
            print(f"{name:<60} {'(new)':>14} {c.cpu_time_us:14.2f} {'':>10}")
            continue
        if c is None:
            print(f"{name:<60} {b.cpu_time_us:14.2f} {'(gone)':>14} {'':>10}")
            continue

        if b.cpu_time_us == 0:
            # Edge case: baseline reported zero (sub-tick benchmark).
            # Skip the percent comparison; report the absolute delta.
            delta_us = c.cpu_time_us - b.cpu_time_us
            print(
                f"{name:<60} {b.cpu_time_us:14.2f} {c.cpu_time_us:14.2f} "
                f"{delta_us:+10.2f}us"
            )
            continue

        delta_pct = (c.cpu_time_us - b.cpu_time_us) / b.cpu_time_us * 100.0
        marker = ""
        if delta_pct > threshold_pct:
            marker = "  REGRESSION"
            regressions += 1
        elif delta_pct < -threshold_pct:
            marker = "  improvement"
        print(
            f"{name:<60} {b.cpu_time_us:14.2f} {c.cpu_time_us:14.2f} "
            f"{delta_pct:+9.2f}%{marker}"
        )

    print("-" * 100)
    if regressions > 0:
        print(
            f"FAIL: {regressions} benchmark(s) regressed beyond "
            f"{threshold_pct}% threshold",
            file=sys.stderr,
        )
        return 1
    print(f"OK: no regression above {threshold_pct}% threshold")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("baseline", type=Path,
                   help="Google Benchmark JSON from the reference run")
    p.add_argument("current", type=Path,
                   help="Google Benchmark JSON from the candidate run")
    p.add_argument("--threshold-pct", type=float, default=5.0,
                   help="Regression threshold (percent slowdown). Default 5.")
    args = p.parse_args()

    if not args.baseline.exists():
        print(f"baseline file not found: {args.baseline}", file=sys.stderr)
        return 2
    if not args.current.exists():
        print(f"current file not found: {args.current}", file=sys.stderr)
        return 2

    baseline = load_samples(args.baseline)
    current = load_samples(args.current)
    return compare(baseline, current, args.threshold_pct)


if __name__ == "__main__":
    sys.exit(main())
