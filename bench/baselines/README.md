# Bench baselines for the `bench-smoke` CI gate

JSON outputs from a known-good `bench_*` Release build, used by the
`bench-smoke` workflow job in `.github/workflows/ci.yml` to gate
performance regressions on push to `main` (and on PRs carrying the
`bench` label).

## Layout

One file per bench binary, named `<binary>.json` (e.g.,
`bench_real_e2e.json`). When the CI job sees a baseline file it
runs `tools/bench_compare.py current.json baseline.json
--threshold-pct 15` and fails the job if any benchmark's
`cpu_time` regressed by more than 15 %.

Absent baseline → smoke mode: numbers logged, no gate. New bench
binaries inherit smoke mode until a baseline is committed.

## Ratchet workflow

When you intentionally improve performance and want the new
numbers locked in, refresh the baseline:

```sh
nix run .#build -- release
./build-release/bench/<binary> \
    --benchmark_min_time=0.3s \
    --benchmark_format=json \
  > bench/baselines/<binary>.json
git add bench/baselines/<binary>.json
git commit -m "bench: ratchet <binary> baseline after <description>"
```

The 15 % threshold is loose enough to absorb GitHub-hosted runner
host variance; if a benchmark is too noisy at that threshold,
either tighten with `--threshold-pct 25` per-binary in the
workflow, or split the bench case so the noisy fixture sits
outside the gate.

## Why baselines aren't auto-rolled

A perf regression should be either:

- Intentional (refactor that trades perf for clarity / safety) —
  reviewer signs off, baseline ratchets in the same commit.
- Unintentional (bug) — fix it, don't move the goalpost.

Auto-ratcheting masks the second case. The manual ratchet is the
review gate. Three flavours of bench binary suffice for a v1.x
scope: `bench_real_e2e` (end-to-end echo), `bench_tcp` (TCP
throughput), `bench_udp` (UDP throughput). Adding more bench
binaries means deciding whether they belong in the regression
gate; default is yes once a stable baseline lands.
