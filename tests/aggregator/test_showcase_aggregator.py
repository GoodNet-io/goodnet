"""Smoke test for `bench/comparison/reports/showcase_aggregate.py`.

Builds a minimal in-memory bench JSON + CSV, runs the aggregator
against it, and asserts the report contains the expected section
headings + acceptance verdicts. NOT an exhaustive coverage —
checks the shape of the output so a refactor that breaks
section emission surfaces in CI before the manual `nix run
.#bench-showcase` round-trip.

Run via pytest from the GoodNet repo root:
    python3 -m pytest tests/aggregator/test_showcase_aggregator.py -v
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
AGG  = REPO / "bench" / "comparison" / "reports" / "showcase_aggregate.py"


def _make_bench_json(path, cases):
    """Write a minimal google-benchmark JSON containing @p cases.

    Each case is a (name, counters_dict) tuple."""
    bench_records = []
    for name, counters in cases:
        rec = {
            "name":            name,
            "real_time":       counters.pop("real_time", 1000.0),
            "cpu_time":        counters.pop("cpu_time", 1000.0),
            "time_unit":       "ns",
            "iterations":      counters.pop("iters", 1),
            "bytes_per_second": counters.pop("throughput", 0),
            **counters,
        }
        bench_records.append(rec)
    with open(path, "w") as f:
        json.dump({"benchmarks": bench_records,
                   "context": {"date": "test"}}, f)


def _make_csv(path, rows):
    """Write a CsvSeries-compatible CSV. `rows` = [(iter, col, val)]."""
    with open(path, "w") as f:
        f.write("iter,column,value\n")
        for it, col, val in rows:
            f.write(f"{it},{col},{val}\n")


def _run_agg(bench_json, csvs, out_md):
    """Invoke the aggregator script as a subprocess and return the
    written markdown. Subprocess so we exercise the CLI surface
    operators actually use."""
    cmd = [sys.executable, str(AGG), "test-sha", out_md, bench_json, *csvs]
    subprocess.run(cmd, check=True,
                   capture_output=True, text=True)
    return Path(out_md).read_text()


def test_b1_pass_when_three_conns():
    with tempfile.TemporaryDirectory() as td:
        bench = os.path.join(td, "b.json")
        _make_bench_json(bench, [
            ("MultiConnFixture/FallbackThroughput/1024/real_time", {
                "alice_conns":    3,
                "alice_sessions": 3,
                "lat_p50_ns":     20000,
                "throughput":     1024 * 1024,
            }),
        ])
        md = _run_agg(bench, [], os.path.join(td, "out.md"))
    assert "## B.1 — Multi-connect" in md
    assert "**PASS**" in md  # acceptance row should be PASS
    assert "observed 3" in md


def test_b2_passes_when_picker_selects_ipc():
    with tempfile.TemporaryDirectory() as td:
        bench = os.path.join(td, "b.json")
        _make_bench_json(bench, [
            ("StrategyFixture/PickerSelectsIpc/1024/real_time", {
                "picks_ipc":   1000,
                "picks_other": 0,
            }),
        ])
        md = _run_agg(bench, [], os.path.join(td, "out.md"))
    assert "## B.2 — Strategy" in md
    assert "**PASS**" in md


def test_b3_incomplete_when_no_handoff_data():
    """B.3 marks acceptance INCOMPLETE when post-handoff numbers
    are zero — the bench wasn't actually run, the aggregator
    shouldn't claim PASS."""
    with tempfile.TemporaryDirectory() as td:
        bench = os.path.join(td, "b.json")
        _make_bench_json(bench, [
            ("HandoffFixture/NoiseSteady/1024/real_time", {
                "lat_p50_ns": 18000,
                "lat_p95_ns": 25000,
                "lat_p99_ns": 30000,
            }),
        ])
        md = _run_agg(bench, [], os.path.join(td, "out.md"))
    assert "## B.3 — Provider handoff" in md
    assert "INCOMPLETE" in md


def test_csv_spark_renders_when_provided():
    """When a CSV side-channel is passed in, the aggregator should
    render an ASCII spark in the corresponding section."""
    with tempfile.TemporaryDirectory() as td:
        bench = os.path.join(td, "b.json")
        _make_bench_json(bench, [
            ("StrategyFixture/FlipOnRttDegradation/200/real_time", {
                "total_iters": 200,
                "flip_iter":   140,
            }),
        ])
        csv_path = os.path.join(td, "showcase-b2-flip-9999.csv")
        _make_csv(csv_path, [
            (i, "chosen_conn", 0xC30 if i < 100 else 0xC10)
            for i in range(200)
        ])
        md = _run_agg(bench, [csv_path], os.path.join(td, "out.md"))
    assert "**Chosen-conn time-series.**" in md
    # The spark uses block characters U+2581..U+2588.
    assert any(c in md for c in "▁▂▃▄▅▆▇█")
