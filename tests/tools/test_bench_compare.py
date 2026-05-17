"""Smoke tests for `tools/bench_compare.py`.

The bench regression gate ships as a CI driver that reads two
Google Benchmark JSON outputs and exits non-zero when any
benchmark's cpu_time regressed past a threshold. These tests
pin the regression detection — easy to ship a broken comparator
that silently passes every commit otherwise.
"""

from __future__ import annotations

import json
from pathlib import Path

import bench_compare  # noqa: E402 — module is on pythonpath via pytest.ini


def _benchmark_json(name: str, cpu_time_ns: float) -> dict:
    """One Google Benchmark output row shaped like `--benchmark_format=json`."""
    return {
        "name": name,
        "cpu_time": cpu_time_ns,
        "real_time": cpu_time_ns,
        "time_unit": "ns",
    }


def _write_bench_json(tmp_path: Path, name: str, samples: list) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"benchmarks": samples}))
    return path


def test_load_samples_converts_ns_to_us(tmp_path: Path) -> None:
    """`time_unit: ns` rows convert to microseconds for delta math."""
    path = _write_bench_json(
        tmp_path, "x.json",
        [_benchmark_json("BM_ping", 5000.0)],
    )
    out = bench_compare.load_samples(path)
    assert "BM_ping" in out
    assert out["BM_ping"].cpu_time_us == 5.0


def test_load_samples_skips_aggregate_rows(tmp_path: Path) -> None:
    """`*_mean` / `*_median` aggregate rows must not double-count."""
    raw = {
        "benchmarks": [
            _benchmark_json("BM_ping", 5000.0),
            {
                **_benchmark_json("BM_ping_mean", 5000.0),
                "aggregate_name": "mean",
            },
        ],
    }
    path = tmp_path / "x.json"
    path.write_text(json.dumps(raw))
    out = bench_compare.load_samples(path)
    assert set(out) == {"BM_ping"}, "aggregate row leaked into samples"


def test_compare_returns_zero_when_steady(capsys) -> None:
    """Two identical sample sets — no regression, exit code 0."""
    base = {"BM_x": bench_compare.Sample("BM_x", 100.0, 100.0)}
    cur  = {"BM_x": bench_compare.Sample("BM_x", 102.0, 102.0)}
    rc = bench_compare.compare(base, cur, threshold_pct=5.0)
    assert rc == 0


def test_compare_detects_regression(capsys) -> None:
    """One benchmark drifts past the threshold — exit code 1."""
    base = {"BM_x": bench_compare.Sample("BM_x", 100.0, 100.0)}
    cur  = {"BM_x": bench_compare.Sample("BM_x", 110.0, 110.0)}
    rc = bench_compare.compare(base, cur, threshold_pct=5.0)
    assert rc == 1, "10% slowdown vs 5% threshold must regress"
    out = capsys.readouterr().out
    assert "REGRESSION" in out


def test_compare_marks_improvement_without_failing(capsys) -> None:
    """Speedups annotate the row but never fail the gate."""
    base = {"BM_x": bench_compare.Sample("BM_x", 100.0, 100.0)}
    cur  = {"BM_x": bench_compare.Sample("BM_x", 70.0, 70.0)}
    rc = bench_compare.compare(base, cur, threshold_pct=5.0)
    assert rc == 0
    out = capsys.readouterr().out
    assert "improvement" in out


def test_compare_handles_new_benchmark(capsys) -> None:
    """A benchmark present only in `current` is annotated `(new)`."""
    base: dict = {}
    cur  = {"BM_new": bench_compare.Sample("BM_new", 42.0, 42.0)}
    rc = bench_compare.compare(base, cur, threshold_pct=5.0)
    assert rc == 0
    assert "(new)" in capsys.readouterr().out


def test_compare_handles_removed_benchmark(capsys) -> None:
    """A benchmark present only in `baseline` is annotated `(gone)`."""
    base = {"BM_gone": bench_compare.Sample("BM_gone", 50.0, 50.0)}
    cur: dict = {}
    rc = bench_compare.compare(base, cur, threshold_pct=5.0)
    assert rc == 0
    assert "(gone)" in capsys.readouterr().out


def test_compare_skips_percent_for_zero_baseline(capsys) -> None:
    """Sub-tick baseline (cpu_time == 0) — absolute-delta path runs;
    no percent calculation, so no false-positive regression."""
    base = {"BM_x": bench_compare.Sample("BM_x", 0.0, 0.0)}
    cur  = {"BM_x": bench_compare.Sample("BM_x", 12.34, 12.34)}
    rc = bench_compare.compare(base, cur, threshold_pct=5.0)
    assert rc == 0
    out = capsys.readouterr().out
    assert "+12.34us" in out, "absolute-delta fallback must print the swing"


def test_main_returns_2_on_missing_baseline(tmp_path, monkeypatch, capsys) -> None:
    """`main()` exits 2 (not 1) when the baseline file is missing —
    the CI driver distinguishes "comparator error" from "benchmark
    regressed". A nonzero exit that wasn't a regression is the
    only way the gate can fail safe."""
    cur = tmp_path / "current.json"
    cur.write_text('{"benchmarks": []}')
    monkeypatch.setattr("sys.argv",
                        ["bench_compare", str(tmp_path / "missing.json"),
                         str(cur)])
    rc = bench_compare.main()
    assert rc == 2
    err = capsys.readouterr().err
    assert "not found" in err


def test_main_returns_2_on_missing_current(tmp_path, monkeypatch, capsys) -> None:
    """Same as above but the candidate side."""
    base = tmp_path / "baseline.json"
    base.write_text('{"benchmarks": []}')
    monkeypatch.setattr("sys.argv",
                        ["bench_compare", str(base),
                         str(tmp_path / "missing.json")])
    rc = bench_compare.main()
    assert rc == 2
    err = capsys.readouterr().err
    assert "not found" in err
