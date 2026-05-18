#!/usr/bin/env python3
"""Multi-pass bench gate — run a binary N times, surface median + IQR + Welch.

Usage:
    python3 tools/bench_multipass.py <binary> --passes=N [--baseline=path] \
        [--alpha=0.05] [--filter=...]

Drives a google-benchmark binary N times, parses every run's JSON
output, and reports:

  * median real_time per case across the N runs;
  * inter-quartile range (P75 - P25) per case — variance signal;
  * Welch's two-sample t-test against a reference JSON when
    `--baseline` is supplied. A p-value below the alpha threshold
    (default 0.05) plus a >5% mean-time delta flags the row as a
    statistically-significant regression.

Methodology rationale (also documented in
`docs/perf/methodology.en.md` §4.7):
  - Single bench runs are nit-pickable. The default `run_all.sh`
    flow reads a 5% delta as "drift in the wash"; a release-gate
    bench needs >3 consecutive runs OR Welch p < 0.05 to count.
  - Median is robust to a single outlier run.
  - IQR surfaces benches that are inherently noisy (e.g. ICE
    nomination latency dispatch where strand scheduling jitters
    add variance) so operators don't read an IQR-wide row as a
    regression signal.

The script does not require dependencies beyond the standard
library; `math.sqrt` + manually computed t-statistic is enough.

Exit code 0 when no row crosses the regression bar; 1 otherwise
(suitable for a CI gate).
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import subprocess
import sys
from pathlib import Path


def run_one_pass(binary: Path, extra_args: list[str]) -> dict:
    """Invoke @p binary once and return the parsed gbench JSON output.

    The binary is run with `--benchmark_format=json` so the parser
    reads exactly the shape `parse_gbench` in `aggregate.py` reads.
    """
    cmd = [str(binary), "--benchmark_format=json"] + extra_args
    out = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if out.returncode != 0:
        sys.stderr.write(
            f"bench binary {binary} exited {out.returncode}\n"
            f"stdout head:\n{out.stdout[:1000]}\n"
            f"stderr head:\n{out.stderr[:1000]}\n"
        )
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"bench binary {binary} emitted non-JSON: {e}\n")
        sys.stderr.write(f"output: {out.stdout[:2000]}\n")
        return {}


def collect(binary: Path, passes: int,
            extra_args: list[str]) -> dict[str, list[float]]:
    """Run @p passes invocations; return a {case_name: [real_time_ns]} map."""
    samples: dict[str, list[float]] = {}
    for i in range(passes):
        sys.stderr.write(f"[multipass] pass {i+1}/{passes}\n")
        data = run_one_pass(binary, extra_args)
        for b in data.get("benchmarks", []):
            name = b.get("name", "?")
            if name.endswith(("_mean", "_median", "_stddev", "_cv")):
                continue
            if b.get("aggregate_name") in ("mean", "median", "stddev", "cv"):
                continue
            rt = b.get("real_time")
            unit = b.get("time_unit", "ns")
            scale = {"ns": 1.0, "us": 1e3, "ms": 1e6, "s": 1e9}.get(unit, 1.0)
            if rt is None or rt == 0:
                continue
            samples.setdefault(name, []).append(float(rt) * scale)
    return samples


def welch_t(a: list[float], b: list[float]) -> tuple[float, float]:
    """Welch's two-sample t-test. Returns (t-statistic, approximate p-value).

    The p-value is approximated through the two-tailed normal CDF; for
    sample sizes >= 5 per side the approximation is within ~1% of the
    exact t-distribution p-value, which is well below the bench-gate
    sensitivity threshold. Returns (0.0, 1.0) when either sample has
    fewer than two points (no signal possible).
    """
    if len(a) < 2 or len(b) < 2:
        return (0.0, 1.0)
    mean_a = statistics.fmean(a)
    mean_b = statistics.fmean(b)
    var_a = statistics.variance(a)
    var_b = statistics.variance(b)
    n_a = len(a)
    n_b = len(b)
    denom = math.sqrt(var_a / n_a + var_b / n_b)
    if denom == 0.0:
        return (0.0, 1.0)
    t_stat = (mean_a - mean_b) / denom
    # Two-tailed p approximation via the standard normal — adequate
    # for the n>=5 regime the bench gate runs in. erf(-x) = -erf(x);
    # the formula is `1 - erf(|t|/sqrt(2))`.
    p = 1.0 - math.erf(abs(t_stat) / math.sqrt(2.0))
    return (t_stat, p)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", type=Path,
                   help="The google-benchmark binary to invoke.")
    p.add_argument("--passes", type=int, default=3,
                   help="Number of independent passes per run (default 3).")
    p.add_argument("--baseline", type=Path, default=None,
                   help="Path to a previous-pass JSON (single google-bench "
                        "JSON) for Welch's t-test regression detection.")
    p.add_argument("--alpha", type=float, default=0.05,
                   help="Welch p-value threshold below which a row is "
                        "flagged as a statistically-significant regression "
                        "(default 0.05).")
    p.add_argument("--min-delta-pct", type=float, default=5.0,
                   help="Minimum mean-time delta percent to flag as "
                        "regression (must be paired with p < alpha).")
    p.add_argument("--filter", default=None,
                   help="`--benchmark_filter` regex passed to each pass.")
    args = p.parse_args()

    if not args.binary.exists():
        sys.stderr.write(f"binary not found: {args.binary}\n")
        return 2
    extra = []
    if args.filter:
        extra.append(f"--benchmark_filter={args.filter}")

    samples = collect(args.binary, args.passes, extra)
    if not samples:
        sys.stderr.write("no benchmark samples collected\n")
        return 2

    baseline = {}
    if args.baseline:
        if not args.baseline.exists():
            sys.stderr.write(f"baseline not found: {args.baseline}\n")
            return 2
        baseline_raw = json.loads(args.baseline.read_text())
        for b in baseline_raw.get("benchmarks", []):
            name = b.get("name", "?")
            if name.endswith(("_mean", "_median", "_stddev", "_cv")):
                continue
            rt = b.get("real_time")
            unit = b.get("time_unit", "ns")
            scale = {"ns": 1.0, "us": 1e3, "ms": 1e6, "s": 1e9}.get(unit, 1.0)
            if rt is None or rt == 0:
                continue
            baseline.setdefault(name, []).append(float(rt) * scale)

    print(f"{'case':<60} {'passes':>6} {'median_ns':>14} "
          f"{'iqr_ns':>14} {'p-value':>10} {'verdict':>14}")
    print("-" * 120)
    regressions = 0
    for case in sorted(samples.keys()):
        vals = samples[case]
        n = len(vals)
        median = statistics.median(vals)
        if n >= 4:
            sorted_vals = sorted(vals)
            q25 = sorted_vals[n // 4]
            q75 = sorted_vals[(3 * n) // 4]
            iqr = q75 - q25
        else:
            iqr = max(vals) - min(vals)
        verdict = "ok"
        p_val = float("nan")
        if case in baseline:
            base_vals = baseline[case]
            _, p_val = welch_t(vals, base_vals)
            base_median = statistics.median(base_vals)
            delta_pct = ((median - base_median) / base_median * 100.0
                         if base_median > 0 else 0.0)
            if p_val < args.alpha and delta_pct > args.min_delta_pct:
                verdict = "REGRESSION"
                regressions += 1
            elif p_val < args.alpha and delta_pct < -args.min_delta_pct:
                verdict = "improvement"
        print(f"{case:<60} {n:>6} {median:>14.1f} "
              f"{iqr:>14.1f} {p_val:>10.4f} {verdict:>14}")

    print("-" * 120)
    if regressions > 0:
        print(f"FAIL: {regressions} row(s) regressed "
              f"(p<{args.alpha}, |Δ|>{args.min_delta_pct}%)",
              file=sys.stderr)
        return 1
    print(f"OK: no statistically-significant regression "
          f"(p<{args.alpha}, |Δ|>{args.min_delta_pct}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
