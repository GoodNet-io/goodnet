#!/usr/bin/env python3
"""Aggregate google-benchmark JSON + comparison-harness JSON into a
single markdown report.

Usage:
    python3 aggregate.py <commit-sha> <output.md> <inputs...>

Inputs can be either:
  * google-benchmark JSON (--benchmark_format=json output)
  * comparison-harness JSON (handshake_ns / dx_loc_hello_world_echo /
    tcp_throughput / ...).
"""

import argparse
import json
import re
import sys
from pathlib import Path


def fmt_bytes_per_sec(n):
    units = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"]
    f = float(n)
    i = 0
    while f >= 1024 and i + 1 < len(units):
        f /= 1024
        i += 1
    return f"{f:.2f} {units[i]}"


def fmt_ns(n):
    if n is None:
        return "—"
    if n < 1e3:
        return f"{n:.0f} ns"
    if n < 1e6:
        return f"{n/1e3:.1f} μs"
    if n < 1e9:
        return f"{n/1e6:.1f} ms"
    return f"{n/1e9:.2f} s"


# Bench `case` names that came from the in-process kernel + real
# security/protocol stack are tagged with the `RealFixture` prefix.
# Google-benchmark fixture-class names live to the left of the first
# `/`, so the case strings look like `RealFixtureTcp/TcpEcho/64/...`
# (one-way A.2) or `RealFixtureTcpEcho/TcpEchoRoundtrip/64/...`
# (track-А round-trip, sibling fixture) — both start with
# `RealFixture` but neither has `RealFixture/` literally. Drop the
# trailing `/` so the prefix recognises every sibling class.
_REAL_PREFIX = "RealFixture"


def is_real_row(row):
    return row.get("case", "").startswith(_REAL_PREFIX)


def parse_gbench(j, out):
    for b in j.get("benchmarks", []):
        name = b.get("name", "?")
        # Aggregate rows (suffix _mean / _median / _stddev / _cv)
        # double-count individual iterations. Skip them; the
        # iteration rows already carry the numbers we want.
        if name.endswith(("_mean", "_median", "_stddev", "_cv")):
            continue
        if b.get("aggregate_name") in ("mean", "median", "stddev", "cv"):
            continue
        bps  = b.get("bytes_per_second")
        time = b.get("real_time")
        unit = b.get("time_unit", "ns")
        scale = {"ns": 1, "us": 1e3, "ms": 1e6, "s": 1e9}.get(unit, 1)
        # `UseManualTime()` benchmarks write `real_time` from the
        # user's `SetIterationTime`; if the body never reached that
        # call (early SkipWithError exit) the field stays 0.0. Treat
        # that as "no data" rather than a 0-ns measurement.
        if time is not None and float(time) == 0.0:
            time = None
        time_ns = float(time) * scale if time else None
        error_msg = b.get("error_message") if b.get("error_occurred") else None
        cpu_user = b.get("cpu_user_us")
        cpu_sys  = b.get("cpu_sys_us")
        cpu_total_us = (b.get("cpu_total_us")
                        or ((cpu_user or 0) + (cpu_sys or 0)) or None)
        iters = b.get("iterations")
        # Derive ns of CPU time spent per byte of throughput. Useful
        # for cross-payload comparisons because the absolute Gbps
        # number scales with both link speed AND payload size; cpu/B
        # isolates the per-byte cost the code path imposes.
        #
        # `cpu_total_us` is a delta from `getrusage(RUSAGE_SELF)`
        # snapshots wrapping the WHOLE bench body (every iteration);
        # `bytes_per_second` is normalised per-iteration time. So to
        # match the units we need total bytes, which is
        # `iterations × bytes_per_second × real_time_per_iter`. With
        # `SetBytesProcessed(iterations × payload)` in the bench
        # bodies this collapses to `iterations × payload`.
        cpu_ns_per_byte = None
        if cpu_total_us and bps and time_ns and iters:
            total_bytes = float(bps) * float(time_ns) / 1e9 * float(iters)
            if total_bytes > 0:
                cpu_ns_per_byte = float(cpu_total_us) * 1e3 / total_bytes
        # `mode` discriminator — every gbench row carries it so the
        # downstream pivot tables can refuse to mix parody and real
        # rows in the same column. `RealFixture` cases boot the full
        # kernel + Noise + gnet stack (production-shape, comparable
        # to libp2p / iroh); every other case is the parody matrix
        # (`<Plug>Fixture/...`, link plugin wired directly to
        # LinkStub, no security, no protocol layer — comparable to
        # iperf3 / socat). The two number sets answer different
        # questions; mixing them in one column would lie by ~5-10×
        # in either direction depending on which row a reader
        # latches onto first. See `docs/perf/methodology.en.md` §1.3.
        mode = "real" if name.startswith(_REAL_PREFIX) else "parody"
        row = {
            "stack": "goodnet",
            "case":  name,
            "mode":  mode,
            "time_ns": time_ns,
            "throughput_bps": bps,
            "error":  error_msg,
            "p50_ns":   b.get("lat_p50_ns"),
            "p95_ns":   b.get("lat_p95_ns"),
            "p99_ns":   b.get("lat_p99_ns"),
            "p999_ns":  b.get("lat_p999_ns"),
            "p9999_ns": b.get("lat_p9999_ns"),
            "lat_samples": b.get("lat_samples"),
            "rss_kb_delta":      b.get("rss_kb_delta"),
            "rss_peak_kb_delta": b.get("rss_peak_kb_delta"),
            "vsz_peak_kb_delta": b.get("vsz_peak_kb_delta"),
            "sock_mem_kb_delta": b.get("sock_mem_kb_delta"),
            "minor_faults":      b.get("minor_faults"),
            "major_faults":      b.get("major_faults"),
            "vol_ctx_sw":        b.get("vol_ctx_sw"),
            "inv_ctx_sw":        b.get("inv_ctx_sw"),
            "cpu_user_us":       cpu_user,
            "cpu_sys_us":        cpu_sys,
            "cpu_total_us":      cpu_total_us,
            "cpu_ns_per_byte":   cpu_ns_per_byte,
        }
        out.setdefault("perf", []).append(row)


def fmt_kb(v):
    """Render a KiB-valued counter; cope with None and zero deltas."""
    if v is None:
        return "—"
    try:
        n = int(v)
    except (TypeError, ValueError):
        return "—"
    if n == 0:
        return "0"
    if abs(n) >= 1024:
        return f"{n/1024:+.1f} MiB" if n else "0"
    return f"{n:+d} KiB"


# Classify a comparison-harness `metric` string into one of the two
# bench shapes. `real` = transport + AEAD + framing/mux (libp2p,
# iroh, planned GoodNet RealFixture rows); `parody` = raw socket
# baseline with no security and no framing (iperf3, socat).
# `openssl` handshake is a record-layer measurement only and lands
# in `single_stack` next to other handshake numbers — left
# `parody` for cell-mixing purposes because the handshake number
# itself sits in a separate section. Returns `None` for metrics
# that aren't carried in a comparable pivot table (binary sizes,
# DX LOC counts, etc.); the caller skips mode tagging for those.
_REAL_METRIC_TOKENS = ("libp2p", "iroh")


def _classify_metric_mode(metric):
    if not isinstance(metric, str):
        return None
    m = metric.lower()
    if any(tok in m for tok in _REAL_METRIC_TOKENS):
        return "real"
    if "iperf3" in m or "socat" in m or "raw" in m:
        return "parody"
    return None


def parse_comparison(j, out):
    if j.get("metric") == "binary_sizes":
        out["binary_sizes"] = j
        return
    if j.get("metric") == "comparison_weights":
        out["comparison_weights"] = j
        return
    if j.get("metric") == "env_facts":
        out["env_facts"] = j
        return
    if "rows" in j:
        # Tag the table itself so per-payload pivot validators can
        # compare across tables sharing a column. `metric` carries
        # the per-stack name (`libp2p_echo_throughput`,
        # `iroh_echo_throughput`); both classify to `real`.
        if "mode" not in j:
            mode = _classify_metric_mode(j.get("metric"))
            if mode is not None:
                j["mode"] = mode
        out.setdefault("tables", []).append(j)
        return
    if "metric" in j and "p50" in j:
        if "mode" not in j:
            mode = _classify_metric_mode(j.get("metric"))
            if mode is not None:
                j["mode"] = mode
        out.setdefault("single_stack", []).append(j)
        return
    if "metric" in j and "bytes_per_sec" in j:
        if "mode" not in j:
            # `throughput_stack` is the iperf3 / planned-libp2p
            # bucket. Tag by metric so the cross-impl table can
            # surface mismatches if a future runner accidentally
            # emits a `real`-shape row through this slot.
            mode = _classify_metric_mode(j.get("metric"))
            if mode is not None:
                j["mode"] = mode
            else:
                # Fall back to `stack` field — iperf3 lists itself
                # as `iperf3 (raw TCP)`, so a `parody` classification
                # is the conservative default for unknown raw-socket
                # entries.
                stack = (j.get("stack") or "").lower()
                if any(tok in stack for tok in _REAL_METRIC_TOKENS):
                    j["mode"] = "real"
                elif "iperf3" in stack or "socat" in stack:
                    j["mode"] = "parody"
        out.setdefault("throughput_stack", []).append(j)


class ModeMismatchError(RuntimeError):
    """Pivot table tried to land cells from different bench shapes in
    one column. The aggregator refuses to render such a mix because a
    reader scanning the column would compare numbers that paid
    different costs (parody = raw socket; real = transport + AEAD +
    framing/mux). Raise instead of silently emitting the mixed row
    so the runner fails fast — `docs/perf/methodology.en.md` §1.3
    pairing rule states why this is a methodology error, not a
    formatting one."""


def _validate_pivot_modes(cells, section_label):
    """Assert every cell in @p cells carries the same `mode` tag.

    @p cells is a sequence of `(column_name, mode)` tuples — the
    aggregator collects them as it walks a pivot table's rows. The
    function ignores cells where `mode is None` (no shape was
    classifiable), so future runners that emit untagged rows fail
    open rather than blocking the report. A non-None mismatch
    aborts the run via `ModeMismatchError`."""
    seen = {}
    for col, mode in cells:
        if mode is None:
            continue
        prev = seen.setdefault(mode, col)
        if prev is not col and not (prev == col):
            # Same column appearing twice with same mode is fine;
            # the key insight is that we want to find the FIRST
            # column per distinct mode.
            pass
    if len(seen) <= 1:
        return
    pairs = ", ".join(f"{col!r}={mode}" for mode, col in seen.items())
    raise ModeMismatchError(
        f"section {section_label!r} mixes bench shapes in one pivot "
        f"table: {pairs}. Refusing to emit — see "
        f"`docs/perf/methodology.en.md` §1.3 (pairing rule). Move "
        f"the mismatched cell into a separate section, or correct "
        f"its `mode` tag in the source runner.")


def fmt_size_bytes(n):
    """KiB / MiB-aware size formatter for binary-size table."""
    if n is None:
        return "—"
    try:
        b = int(n)
    except (TypeError, ValueError):
        return "—"
    if b < 1024:
        return f"{b} B"
    if b < 1024 * 1024:
        return f"{b/1024:.1f} KiB"
    return f"{b/1024/1024:.2f} MiB"


def fmt_size_kib(n):
    if n is None:
        return "—"
    try:
        kib = int(n)
    except (TypeError, ValueError):
        return "—"
    if kib < 1024:
        return f"{kib} KiB"
    return f"{kib/1024:.1f} MiB"


def fmt_per_byte(n):
    """Render a `ns of CPU per byte sent` rate. Sub-1ns values
    print with one decimal so the reader can still distinguish the
    raw-socket plugin (~0.4 ns/B) from a Noise-encrypted carrier
    (~3-5 ns/B) at a glance."""
    if n is None:
        return "—"
    try:
        v = float(n)
    except (TypeError, ValueError):
        return "—"
    if v <= 0:
        return "—"
    if v < 10:
        return f"{v:.2f} ns/B"
    if v < 1000:
        return f"{v:.1f} ns/B"
    return f"{v/1000:.2f} μs/B"


def _baseline_index_from_report(path):
    """Parse a previous markdown bench report and extract the perf
    rows that have a comparable throughput / time value. Returns a
    `{case_name: {'time_ns': float|None, 'throughput_bps': float|None}}`
    map. The Δ-baseline column joins on `case_name`; rows present in
    the current run but absent from the baseline render as `(new)`,
    and vice-versa as `(gone)`.

    The aggregator emits one row per case under `## Parody — GoodNet
    plugin matrix` (and `## Real — ...`) — the regex below picks up
    the `| <case> | <Time> | <Throughput> | ...` shape. Numbers are
    parsed by `_parse_time_ns_from_md` and `_parse_throughput_bps_from_md`
    which mirror `fmt_ns` / `fmt_bytes_per_sec` inverses."""
    out = {}
    try:
        text = Path(path).read_text()
    except (OSError, FileNotFoundError):
        return out
    row_re = re.compile(
        r"^\| ([A-Za-z][A-Za-z0-9_/:.\-]+(?:/[A-Za-z0-9_]+)*)"
        r" \| ([^|]+?) \| ([^|]+?) \| ")
    for line in text.splitlines():
        m = row_re.match(line)
        if not m:
            continue
        case  = m.group(1).strip()
        if case == "Case":
            continue
        t_str = m.group(2).strip()
        bp_str = m.group(3).strip()
        out[case] = {
            "time_ns":         _parse_time_ns_from_md(t_str),
            "throughput_bps":  _parse_throughput_bps_from_md(bp_str),
        }
    return out


def _parse_time_ns_from_md(s):
    """Inverse of `fmt_ns` — accepts `5.1 ms` / `42 ns` / `1.2 μs` etc.
    Returns None for `—` or unparseable strings."""
    if not s or s == "—" or s == "-":
        return None
    try:
        n = float(s.split()[0])
    except (ValueError, IndexError):
        return None
    if "ms" in s:
        return n * 1e6
    if "μs" in s or "us" in s:
        return n * 1e3
    if " s" in s:
        return n * 1e9
    return n  # ns


def _parse_throughput_bps_from_md(s):
    """Inverse of `fmt_bytes_per_sec`. Accepts `2.03 GiB/s` etc."""
    if not s or s == "—" or s == "-":
        return None
    try:
        n = float(s.split()[0])
    except (ValueError, IndexError):
        return None
    if "GiB" in s:
        return n * 1024 * 1024 * 1024
    if "MiB" in s:
        return n * 1024 * 1024
    if "KiB" in s:
        return n * 1024
    if "TiB" in s:
        return n * 1024 * 1024 * 1024 * 1024
    return n


def _baseline_delta(current, baseline_entry, is_latency):
    """Compute the regression marker + percent delta. `current` is
    the active row's throughput_bps (or time_ns when `is_latency`);
    `baseline_entry` is the matched dict from `_baseline_index_from_report`.
    Returns a markdown-safe string (`+12.3% [REGRESSION]` /
    `-4.1% improvement` / `—` when no baseline)."""
    if baseline_entry is None:
        return "—"
    if is_latency:
        base = baseline_entry.get("time_ns")
        cur  = current
    else:
        base = baseline_entry.get("throughput_bps")
        cur  = current
    if base is None or cur is None or base <= 0:
        return "—"
    delta_pct = (cur - base) / base * 100.0
    # Latency regression: current LARGER than baseline by >15% — bad.
    # Throughput regression: current SMALLER than baseline by >10% — bad.
    # The marker text is `[REGRESSION]` because emoji are banned and
    # bench reports need a plain-text scannable marker.
    if is_latency:
        if delta_pct > 15.0:
            return f"+{delta_pct:.1f}% [REGRESSION]"
        if delta_pct < -15.0:
            return f"{delta_pct:.1f}% improvement"
    else:
        if delta_pct < -10.0:
            return f"{delta_pct:.1f}% [REGRESSION]"
        if delta_pct > 10.0:
            return f"+{delta_pct:.1f}% improvement"
    return f"{delta_pct:+.1f}%"


def main(argv):
    p = argparse.ArgumentParser()
    p.add_argument("commit_sha")
    p.add_argument("output")
    p.add_argument("inputs", nargs="+")
    p.add_argument("--baseline", default=None,
                   help="Path to a previous bench report markdown for "
                        "delta-vs-baseline column. Disabled when absent.")
    args = p.parse_args(argv)

    baseline_idx = (_baseline_index_from_report(args.baseline)
                    if args.baseline else {})

    aggregated = {}
    skipped_inputs = []
    for path in args.inputs:
        try:
            with open(path) as f:
                content = f.read().strip()
            if not content:
                skipped_inputs.append((path, "empty file"))
                continue
            j = json.loads(content)
        except (json.JSONDecodeError, OSError) as e:
            print(f"warn: skipping {path}: {e}", file=sys.stderr)
            # An empty / truncated JSON usually means the binary
            # crashed mid-run. Track those so the report's `## Known
            # crashes` section can call out the missing rows by name
            # rather than letting them silently vanish from the matrix.
            skipped_inputs.append((path, str(e)))
            continue
        if "benchmarks" in j:
            parse_gbench(j, aggregated)
        else:
            parse_comparison(j, aggregated)
    if skipped_inputs:
        aggregated["skipped_inputs"] = skipped_inputs

    out = [f"# Benchmark report — {args.commit_sha}", ""]
    if args.baseline:
        out.append(f"_Baseline: `{args.baseline}` — Δ-vs-baseline "
                   f"column in `## Parody` / `## Real` tables flags "
                   f"regressions (`[REGRESSION]` marker on >15% latency "
                   f"slowdown or >10% throughput drop)._")
        out.append("")
    # ── Environment header ────────────────────────────────────────
    #
    # Bench numbers shift across CPU governors, turbo state, SMT
    # config, ASLR setting — the canonical answer to "why is this row
    # 30% slower than last week" is the env. Document it inline so a
    # reader picking up the report a quarter later can see the
    # mismatch at a glance.
    if env := aggregated.get("env_facts"):
        out.append("## Environment")
        out.append("")
        out.append("| Fact | Value |")
        out.append("|---|---|")
        out.append(f"| CPU | {env.get('cpu_model', '?')} "
                   f"({env.get('cpu_cores', '?')} cores) |")
        out.append(f"| RAM | {env.get('ram', '?')} |")
        out.append(f"| Kernel | {env.get('kernel', '?')} |")
        gov = env.get('governor', '?')
        gov_str = (f"`{gov}` (run `cpupower frequency-set -g performance` "
                   f"for production-grade numbers — see "
                   f"`docs/perf/methodology.en.md` §Environmental controls)"
                   if gov not in ("performance", "?")
                   else f"`{gov}`")
        out.append(f"| CPU governor | {gov_str} |")
        out.append(f"| Turbo | {env.get('turbo', '?')} |")
        out.append(f"| SMT | {env.get('smt', '?')} |")
        out.append(f"| ASLR | {env.get('aslr', '?')} (0=off, 1=stack, 2=full) |")
        out.append(f"| NUMA nodes | {env.get('numa_nodes', '?')} |")
        out.append("")

    # ── TL;DR cross-stack throughput at the canonical payload ────────
    #
    # One row per stack at 1024 B — the size every comparison runner
    # measures and where libp2p / iroh tend to publish their own
    # headline numbers. The reader who only wants the top-line
    # "is GoodNet competitive?" answer gets it without scrolling
    # through the per-stack matrices below.
    #
    # Rows assembled from THREE sources:
    #   * gbench `*EchoRoundtrip/1024/...`  — GoodNet parody RTT
    #   * gbench `*Throughput/1024/...`     — GoodNet parody one-way
    #   * `tables` rows where `payload == 1024` — libp2p / iroh
    #   * `throughput_stack` entries        — iperf3 baselines (no
    #     payload axis; folded in as "≥ 1 KiB" since iperf3 picks its
    #     own MTU-sized chunks)
    canon_payload = 1024
    tldr_rows: list[dict] = []
    plug_re = re.compile(
        r"^(?P<plug>Udp|Ws|Tcp|Ipc|Quic|Tls)Fixture/"
        r"(?P<kind>EchoRoundtrip|Throughput)/(?P<sz>\d+)/")
    # Real-mode round-trip lives in sibling fixture classes named
    # `RealFixtureTcpEcho`, `RealFixtureUdpEcho`, `RealFixtureIpcEcho`.
    # The case payload is `RealFixture<Plug>Echo/<Plug>EchoRoundtrip/<sz>/`.
    real_rt_re = re.compile(
        r"^RealFixture(?P<plug>Tcp|Udp|Ipc)Echo/"
        r"(?:Tcp|Udp|Ipc)EchoRoundtrip/(?P<sz>\d+)/")
    # Real-mode one-way A.2 cases — sibling fixture `RealFixtureTcp`
    # (no `Echo` suffix on the class name). Case shape:
    # `RealFixture<Plug>/<Plug>Echo/<sz>/`.
    real_oneway_re = re.compile(
        r"^RealFixture(?P<plug>Tcp|Udp|Ipc)/"
        r"(?:Tcp|Udp|Ipc)Echo/(?P<sz>\d+)/")
    for r in aggregated.get("perf", []):
        case = r.get("case", "")
        if not r.get("throughput_bps"):
            continue
        m_rt = real_rt_re.match(case)
        m_ow = real_oneway_re.match(case)
        m_par = plug_re.match(case)
        if m_rt and int(m_rt.group("sz")) == canon_payload:
            tldr_rows.append({
                "stack":       f"GoodNet {m_rt.group('plug').upper()}+Noise+gnet",
                "shape":       "real",
                "kind":        "echo-RTT",
                "throughput":  r["throughput_bps"],
                "p50_ns":      r.get("p50_ns"),
                "p99_ns":      r.get("p99_ns"),
            })
            continue
        if m_ow and int(m_ow.group("sz")) == canon_payload:
            tldr_rows.append({
                "stack":       f"GoodNet {m_ow.group('plug').upper()}+Noise+gnet",
                "shape":       "real",
                "kind":        "echo-one-way",
                "throughput":  r["throughput_bps"],
                "p50_ns":      r.get("p50_ns"),
                "p99_ns":      r.get("p99_ns"),
            })
            continue
        if m_par and int(m_par.group("sz")) == canon_payload:
            kind = ("echo-RTT" if m_par.group("kind") == "EchoRoundtrip"
                    else "send-only")
            tldr_rows.append({
                "stack":       f"GoodNet {m_par.group('plug').upper()}",
                "shape":       "parody",
                "kind":        kind,
                "throughput":  r["throughput_bps"],
                "p50_ns":      r.get("p50_ns"),
                "p99_ns":      r.get("p99_ns"),
            })
    for tbl in aggregated.get("tables", []):
        if tbl.get("metric") not in (
                "libp2p_echo_throughput", "iroh_echo_throughput"):
            continue
        for row in tbl.get("rows", []):
            if int(row.get("payload", 0)) != canon_payload:
                continue
            bps = row.get("bytes_per_sec", 0)
            if not bps:
                continue
            tldr_rows.append({
                "stack":      row.get("stack", "?"),
                "shape":      "real",  # libp2p/iroh measure full stack
                "kind":       "echo-RTT",
                "throughput": float(bps),
                "p50_ns":     None,
                "p99_ns":     None,
            })
    for t in aggregated.get("throughput_stack", []):
        bps = t.get("bytes_per_sec", 0)
        if not bps:
            continue
        # iperf3 is a raw-socket baseline — same shape as parody.
        tldr_rows.append({
            "stack":      t.get("stack", "?"),
            "shape":      "parody",
            "kind":       t.get("metric", "throughput"),
            "throughput": float(bps),
            "p50_ns":     None,
            "p99_ns":     None,
        })
    if tldr_rows:
        # Sort: real first, then parody; within each, by throughput
        # descending. Reader sees the production-shape numbers at
        # the top of the table, with the upper-bound parody rows
        # below for context.
        tldr_rows.sort(
            key=lambda r: (r["shape"] != "real", -r["throughput"]))
        out.append(f"## TL;DR — {canon_payload} B payload, all stacks")
        out.append("")
        out.append(f"_Headline throughput across every stack the bench "
                   f"runner observed at the canonical {canon_payload}-byte "
                   f"payload. `shape` = `real` for production-equivalent "
                   f"stacks (libp2p TCP+Noise+Yamux, iroh TLS1.3+QUIC, "
                   f"GoodNet `RealFixture/...`) and `parody` for raw-"
                   f"transport baselines (iperf3, GoodNet plugin matrix "
                   f"without security/protocol). Compare same-shape rows "
                   f"only — a `real` vs `parody` delta IS the cost of "
                   f"running the production stack, not a stack quality "
                   f"signal._")
        out.append("")
        out.append("| Stack | Shape | Kind | Throughput | P50 RTT | P99 RTT |")
        out.append("|---|---|---|---|---|---|")
        for r in tldr_rows:
            out.append(
                f"| {r['stack']} | `{r['shape']}` | {r['kind']} | "
                f"{fmt_bytes_per_sec(r['throughput'])} | "
                f"{fmt_ns(r['p50_ns'])} | {fmt_ns(r['p99_ns'])} |")
        out.append("")

    # ── А. Comparable echo round-trip — production stack ────────────
    #
    # Pivots Real-mode echo round-trip gbench rows (TCP/IPC; UDP is
    # neither libp2p nor iroh's primary transport so the column is
    # dropped) against the libp2p / iroh runner outputs. Same stack
    # shape on every row: transport + AEAD + framing/mux.
    #   * GoodNet TCP+Noise+gnet  ↔  libp2p (TCP+Noise+Yamux)
    #   * GoodNet QUIC+TLS+gnet   ↔  iroh   (QUIC+TLS 1.3)   [pending]
    # iperf3 / socat parody rows live in `## Cross-implementation
    # throughput` and are NOT directly comparable to this section.
    # See `docs/perf/methodology.en.md` §1.3 (pairing rule).
    echo_re = re.compile(
        r"^RealFixture(?P<plug>Tcp|Ipc|Quic)Echo/"
        r"(?:Tcp|Ipc|Quic)EchoRoundtrip/(?P<sz>\d+)/")
    by_payload: dict[int, dict[str, float]] = {}
    # Track which `mode` tag each cell landed with so the pivot can
    # fail fast if a parody row sneaks in via a future runner
    # mis-labelling its metric. See `_validate_pivot_modes` for the
    # rationale: same section = same shape, always.
    cell_modes: list[tuple[str, str]] = []
    for r in aggregated.get("perf", []):
        m = echo_re.match(r.get("case", ""))
        if not m or not r.get("throughput_bps"):
            continue
        sz = int(m.group("sz"))
        col = f"GoodNet {m.group('plug').upper()}+Noise+gnet"
        by_payload.setdefault(sz, {})[col] = float(r["throughput_bps"])
        cell_modes.append((col, r.get("mode", "real")))
    for tbl in aggregated.get("tables", []):
        if tbl.get("metric") not in (
                "libp2p_echo_throughput", "iroh_echo_throughput"):
            continue
        tbl_mode = tbl.get("mode", "real")
        for row in tbl.get("rows", []):
            sz = row.get("payload")
            bps = row.get("bytes_per_sec", 0)
            if not isinstance(sz, (int, float)) or not bps:
                continue
            col = row.get("stack", "?")
            by_payload.setdefault(int(sz), {})[col] = float(bps)
            cell_modes.append((col, tbl_mode))
    _validate_pivot_modes(cell_modes,
                          "А. Comparable echo round-trip")
    if by_payload:
        stacks = ["GoodNet TCP+Noise+gnet", "GoodNet IPC+Noise+gnet",
                  "GoodNet QUIC+Noise+gnet",
                  "libp2p (TCP+Noise+Yamux)", "iroh (QUIC+TLS1.3)"]
        out.append("## А. Comparable echo round-trip — "
                   "production stack vs libp2p / iroh")
        out.append("")
        out.append("_Same conceptual stack on every row: transport "
                   "+ AEAD + framing/mux. GoodNet rows are "
                   "`RealFixture<plug>Echo` cases (kernel + Noise XX "
                   "+ gnet protocol). libp2p uses Noise XX + Yamux; "
                   "iroh uses TLS 1.3 + QUIC streams. Compare "
                   "directly within this section. iperf3 / socat "
                   "parody rows live in `## Cross-implementation "
                   "throughput` and are NOT directly comparable — see "
                   "`docs/perf/methodology.en.md` §1.3 (pairing rule). "
                   "Real-QUIC fixture is not wired; the QuicLink "
                   "carrier-bring-up path needs a LinkCarrier + "
                   "`composer_listen` / `composer_connect` fixture "
                   "before the iroh row can land here._")
        out.append("")
        out.append("| Payload | " + " | ".join(stacks) + " |")
        out.append("|---|" + "---|" * len(stacks))
        for sz in sorted(by_payload):
            cells = [f"{sz} B"]
            for col in stacks:
                v = by_payload[sz].get(col)
                cells.append(fmt_bytes_per_sec(v) if v else "—")
            out.append("| " + " | ".join(cells) + " |")
        out.append("")

    # ── Handshake cost summary ─────────────────────────────────────
    #
    # Pivot every `*HandshakeTime/...` case across plugins (TCP,
    # TLS, QUIC, DTLS today; future Noise / Wireguard would land
    # here too). Connection setup latency is a separate cost
    # dimension from steady-state throughput — operators with
    # connection-churn workloads (Lambda-style, mobile reconnects)
    # care about it more than they care about per-byte rate.
    #
    # `lat_p50_ns` / `lat_p99_ns` are populated by the per-plugin
    # fixtures that drive a fresh listener + connect for every
    # iteration. The raw `time_ns` falls back to the gbench
    # `real_time` when the fixture didn't pin a P50 explicitly.
    hs_re = re.compile(
        r"^(?P<plug>[A-Z][a-z]+)Fixture/(?:Handshake|HandshakeTime)(?:/|$)")
    hs_rows = []
    for r in aggregated.get("perf", []):
        m = hs_re.match(r.get("case", ""))
        if not m:
            continue
        plug = m.group("plug").upper()
        hs_rows.append({
            "stack":   f"GoodNet {plug}",
            "time_ns": r.get("p50_ns") or r.get("time_ns"),
            "p99_ns":  r.get("p99_ns"),
            "case":    r["case"],
        })
    # Pick up cross-impl handshake numbers too — openssl s_client
    # baseline emits one row through `single_stack`.
    for s in aggregated.get("single_stack", []):
        if "handshake" not in s.get("metric", "").lower():
            continue
        hs_rows.append({
            "stack":   s.get("stack", "?"),
            "time_ns": s.get("p50") or s.get("mean"),
            "p99_ns":  s.get("p99"),
            "case":    s.get("metric", "?"),
        })
    if hs_rows:
        hs_rows.sort(key=lambda r: (r["time_ns"] or float("inf")))
        out.append("## Handshake cost — fresh connection setup time")
        out.append("")
        out.append("_The connect → first-handler-byte round trip "
                   "for each transport. TCP is the bare three-way "
                   "(SYN / SYN-ACK / ACK); TLS adds the 1-RTT "
                   "handshake on top; QUIC bakes the crypto into the "
                   "first flight; DTLS is the UDP variant of TLS. "
                   "Operators serving connection-churn workloads "
                   "(short-lived RPC, mobile reconnect storms) "
                   "weight this column heavier than steady-state "
                   "throughput. Sorted ascending by P50._")
        out.append("")
        out.append("| Stack | Case | P50 | P99 |")
        out.append("|---|---|---|---|")
        for r in hs_rows:
            out.append(
                f"| {r['stack']} | `{r['case']}` | "
                f"{fmt_ns(r['time_ns'])} | "
                f"{fmt_ns(r['p99_ns'])} |")
        out.append("")

    def emit_perf_table(rows, shape_label):
        # Δ-baseline column only emitted when --baseline is set.
        delta_col = " Δ vs baseline |" if baseline_idx else ""
        delta_sep = "---|" if baseline_idx else ""
        out.append("| Case | Status | Time | Throughput |" + delta_col +
                   " CPU/B | P50 lat | P99 lat | RSS Δ | RSS Peak Δ | "
                   "VSZ Peak Δ | Sock Mem Δ | Minor Faults | "
                   "Ctx Sw (vol/inv) |")
        out.append("|---|---|---|---|" + delta_sep +
                   "---|---|---|---|---|---|---|---|---|")
        for r in rows:
            tput = (fmt_bytes_per_sec(r["throughput_bps"])
                    if r["throughput_bps"] else "-")
            mf = r.get("minor_faults")
            mf_str = f"{int(mf):,}" if mf is not None and mf > 0 else "—"
            vol = r.get("vol_ctx_sw")
            inv = r.get("inv_ctx_sw")
            if vol is None and inv is None:
                cs_str = "—"
            else:
                cs_str = (f"{int(vol or 0):,} / {int(inv or 0):,}")
            case = r["case"]
            if shape_label == "real" and case.startswith(_REAL_PREFIX):
                case = case[len(_REAL_PREFIX):]
            # Status column makes SkipWithError visible. `error` is
            # the bench fixture's diagnostic ("send failed mid-loop",
            # "handshake timeout") propagated from
            # google-benchmark's `error_message`. Rows that ran
            # cleanly show `ok` — operators scanning for the SKIP /
            # CRASH cells get them at a glance instead of having to
            # cross-reference the JSON.
            if r.get("error"):
                status = f"SKIP: {r['error']}"
            elif r.get("throughput_bps") or r.get("time_ns"):
                status = "ok"
            else:
                status = "no data"
            # Δ vs baseline column. Throughput-bearing rows compare
            # `throughput_bps`; latency-bearing rows (no throughput)
            # compare `time_ns`. Rows where the current bench reports
            # no number get `—`. Rows absent from baseline get `(new)`.
            if baseline_idx:
                bl = baseline_idx.get(case)
                if bl is None:
                    delta_cell = "(new)"
                elif r.get("throughput_bps"):
                    delta_cell = _baseline_delta(
                        float(r["throughput_bps"]), bl, is_latency=False)
                elif r.get("time_ns"):
                    delta_cell = _baseline_delta(
                        float(r["time_ns"]), bl, is_latency=True)
                else:
                    delta_cell = "—"
                delta_col_str = f" {delta_cell} |"
            else:
                delta_col_str = ""
            out.append(
                f"| {case} | {status} | {fmt_ns(r['time_ns'])} | {tput} |"
                + delta_col_str +
                f" {fmt_per_byte(r.get('cpu_ns_per_byte'))} | "
                f"{fmt_ns(r['p50_ns'])} | {fmt_ns(r['p99_ns'])} | "
                f"{fmt_kb(r.get('rss_kb_delta'))} | "
                f"{fmt_kb(r.get('rss_peak_kb_delta'))} | "
                f"{fmt_kb(r.get('vsz_peak_kb_delta'))} | "
                f"{fmt_kb(r.get('sock_mem_kb_delta'))} | "
                f"{mf_str} | {cs_str} |")
        out.append("")

    if perf := aggregated.get("perf"):
        parody_rows = [r for r in perf if not is_real_row(r)]
        real_rows   = [r for r in perf if is_real_row(r)]

        if parody_rows:
            out.append("## Parody — GoodNet plugin matrix (raw transport, "
                       "no security, no protocol layer)")
            out.append("")
            out.append("_**Shape**: bench fixtures wire the link plugin to "
                       "a test stub `host_api` — no security provider is "
                       "registered, no protocol layer frames the bytes. "
                       "Numbers are the upper-bound the plugin can deliver "
                       "to a downstream that drains as fast as the link "
                       "writes. Compare against `iperf3` rows below (also "
                       "no security, no framing) for a fair stack-by-stack "
                       "delta. For production-shape numbers compare to the "
                       "`## Real` section (`RealFixture/...` cases) — "
                       "the delta IS the cost of the production stack._")
            out.append("")
            out.append("_`CPU/B` = CPU-nanoseconds per byte sent, derived "
                       "from getrusage user+sys time and effective "
                       "throughput. Compare across rows at the same "
                       "payload size: per-byte cost is the dimension that "
                       "stays meaningful when the absolute Gbps number "
                       "moves with link speed or packet size._")
            out.append("")
            out.append("_Memory deltas: `RSS Δ` = `VmRSS_end − VmRSS_start` "
                       "(current; allocator `madvise(MADV_DONTNEED)` masks "
                       "bursts that returned). `RSS Peak Δ` = `VmHWM_end − "
                       "VmHWM_start` (high-water-mark; catches bursts). "
                       "`VSZ Peak Δ` = same for VmPeak (virtual address "
                       "space, includes mmap'd-but-untouched). "
                       "`Sock Mem Δ` = kernel TCP+UDP+FRAG buffers from "
                       "`/proc/net/sockstat` (system-wide; bench "
                       "attribution via window-delta — every other socket "
                       "on a quiet test machine stays at steady state)._")
            out.append("")
            emit_perf_table(parody_rows, "parody")

        # ── Latency tail ladder ─────────────────────────────────────
        #
        # Every fixture that records `lat_pNN_ns` lands here as one row
        # showing P50 → P95 → P99 → P99.9. Tail behaviour is the more
        # discriminating signal between p2p stacks: average / P50 hides
        # the worst-case path; P99.9 surfaces it. RoundTripMeter
        # interpolates between adjacent samples (linear), so a fixture
        # with N=1 returns the same value at every percentile — those
        # show up flat across the row, which is the honest answer.
        lat_rows = [
            r for r in perf
            if any(r.get(k) for k in ("p50_ns", "p95_ns",
                                       "p99_ns", "p999_ns",
                                       "p9999_ns"))
        ]
        if lat_rows:
            out.append("## Latency tail — P50 → P99.99 ladder")
            out.append("")
            out.append("_Tail latency is the dimension that distinguishes "
                       "an evenly-paced p2p stack from one that pauses on "
                       "GC / strand-hop / allocator slow paths. A widening "
                       "gap between P99 and P99.9 across rows is the "
                       "signal — flat rows mean the bench body is "
                       "uniformly fast. Cases with fewer than 10 000 "
                       "samples report P99.99 == P99.9 by linear "
                       "interpolation; the `samples` column makes the "
                       "underlying N visible so operators can tell which "
                       "rows have enough mass for the deepest tail. See "
                       "`docs/perf/methodology.en.md` §4.4 for the "
                       "fixture-by-fixture interpretation guide._")
            out.append("")
            out.append("| Case | Samples | P50 | P95 | P99 | P99.9 | P99.99 |")
            out.append("|---|---|---|---|---|---|---|")
            for r in lat_rows:
                case = r["case"]
                if case.startswith(_REAL_PREFIX):
                    case = "real:" + case[len(_REAL_PREFIX):]
                n = r.get("lat_samples")
                n_str = f"{int(n):,}" if n is not None and n > 0 else "—"
                out.append(
                    f"| {case} | {n_str} | "
                    f"{fmt_ns(r.get('p50_ns'))} | "
                    f"{fmt_ns(r.get('p95_ns'))} | "
                    f"{fmt_ns(r.get('p99_ns'))} | "
                    f"{fmt_ns(r.get('p999_ns'))} | "
                    f"{fmt_ns(r.get('p9999_ns'))} |")
            out.append("")

        if real_rows:
            out.append("## Real — production-shape echo "
                       "(kernel + security + protocol)")
            out.append("")
            out.append("_**Shape**: bench fixtures boot a real kernel, "
                       "load the matching security provider "
                       "(`gn.security.noise` for peer trust, "
                       "`gn.security.null` for loopback per StackRegistry), "
                       "and frame bytes through `gn.protocol.gnet`. Numbers "
                       "match the cost an operator-facing `send()` actually "
                       "incurs in production — compare against "
                       "`rust-libp2p` (Noise XX + Yamux) and `iroh` "
                       "(TLS 1.3 + QUIC) rows in `## Cross-implementation "
                       "throughput` below for a fair real-vs-real "
                       "stack-quality signal._")
            out.append("")
            out.append("_Per-byte cost in this section reflects the full "
                       "send path: protocol framing + AEAD encrypt + "
                       "link write. Subtract the same-payload row from "
                       "`## Parody` above to isolate the security + "
                       "protocol overhead._")
            out.append("")
            emit_perf_table(real_rows, "real")

            # ── Cost decomposition: parody → real overhead ──────────
            #
            # For every plugin family present in BOTH shapes, pair
            # the rows at the canonical payload and surface the
            # delta as a percentage. Hides the rest of the matrix
            # noise — the reader gets one row per plugin showing
            # the cost of switching from raw-transport to the full
            # production stack.
            #
            # Pair heuristic: case name's plugin prefix (everything
            # up to the first `/`). RealFixture/TcpEcho/1024 pairs
            # against TcpFixture/EchoRoundtrip/1024 (or .../Throughput).
            # We pick the FASTEST parody row at the canonical
            # payload so the overhead reflects "production cost vs
            # plugin's headline number," not "production cost vs an
            # echo path that already paid a round-trip tax."
            def _plugin_family(case: str) -> str:
                """Extract `TCP` / `UDP` / `WS` etc. from the case name.
                Parody cases use `TcpFixture/.../...`; real-mode cases
                use `RealFixture/TcpEcho/...`. Both reduce to the same
                family by taking the leading camelcase word (e.g. `Tcp`)
                of the first path segment that follows the optional
                `RealFixture/` prefix."""
                stripped = case[len(_REAL_PREFIX):] \
                    if case.startswith(_REAL_PREFIX) else case
                head = stripped.split("/", 1)[0]
                # Strip the `Fixture` / `Bench` suffix gbench bodies use.
                for suffix in ("Fixture", "Bench"):
                    if head.endswith(suffix):
                        head = head[: -len(suffix)]
                # Real-mode case names append the workload after the
                # plugin name (`TcpEcho`, `UdpSend`). Trim everything
                # after the first secondary capital letter so the
                # parody `Tcp` and real `TcpEcho` both reduce to `TCP`.
                if head:
                    first = head[0]
                    cut = len(head)
                    for i in range(1, len(head)):
                        if head[i].isupper():
                            cut = i
                            break
                    head = (first + head[1:cut]).rstrip()
                return head.upper()

            def _payload_size(case: str):
                """Pull the `/<size>/` integer out of the case name."""
                parts = case.split("/")
                for p in parts:
                    if p.isdigit():
                        n = int(p)
                        if 32 <= n <= 1024 * 1024:
                            return n
                return None

            parody_at = {}
            for r in parody_rows:
                if not r["throughput_bps"]:
                    continue
                fam = _plugin_family(r["case"])
                sz = _payload_size(r["case"])
                if sz != canon_payload:
                    continue
                cur = parody_at.get(fam)
                if cur is None or r["throughput_bps"] > cur["throughput_bps"]:
                    parody_at[fam] = r

            decomp_rows = []
            for r in real_rows:
                if not r["throughput_bps"]:
                    continue
                if _payload_size(r["case"]) != canon_payload:
                    continue
                fam = _plugin_family(r["case"])
                p = parody_at.get(fam)
                if p is None:
                    continue
                pthru = float(p["throughput_bps"])
                rthru = float(r["throughput_bps"])
                if pthru <= 0:
                    continue
                overhead_pct = (rthru - pthru) / pthru * 100.0
                pcpu = p.get("cpu_ns_per_byte")
                rcpu = r.get("cpu_ns_per_byte")
                cpu_delta = None
                if pcpu is not None and rcpu is not None:
                    cpu_delta = rcpu - pcpu
                decomp_rows.append({
                    "family":   fam,
                    "parody":   pthru,
                    "real":     rthru,
                    "overhead": overhead_pct,
                    "cpu_p":    pcpu,
                    "cpu_r":    rcpu,
                    "cpu_d":    cpu_delta,
                })
            if decomp_rows:
                out.append(f"## Cost decomposition — production overhead at "
                           f"{canon_payload} B payload")
                out.append("")
                out.append("_For each plugin family present in both shapes, "
                           "the row pairs the FASTEST parody measurement at "
                           "this payload against the matching real-mode row "
                           "and surfaces the cost of running through the "
                           "production stack (security + protocol + "
                           "kernel dispatch). `Overhead` is signed — "
                           "negative means real-mode is slower than parody "
                           "by that percentage, which is the expected "
                           "direction. `Δ CPU/B` is the per-byte CPU cost "
                           "the production layers add on top of raw "
                           "transport._")
                out.append("")
                out.append("| Plugin | Parody | Real | Overhead | CPU/B parody | CPU/B real | Δ CPU/B |")
                out.append("|---|---|---|---|---|---|---|")
                for d in decomp_rows:
                    sign = "+" if d["overhead"] >= 0 else ""
                    out.append(
                        f"| {d['family']} | "
                        f"{fmt_bytes_per_sec(d['parody'])} | "
                        f"{fmt_bytes_per_sec(d['real'])} | "
                        f"{sign}{d['overhead']:.1f}% | "
                        f"{fmt_per_byte(d['cpu_p'])} | "
                        f"{fmt_per_byte(d['cpu_r'])} | "
                        f"{fmt_per_byte(d['cpu_d']) if d['cpu_d'] else '—'} |")
                out.append("")

    if singles := aggregated.get("single_stack"):
        out.append("## Cross-implementation latency / handshake")
        out.append("")
        out.append("| Stack | Metric | Mean | P50 | P99 |")
        out.append("|---|---|---|---|---|")
        for s in singles:
            out.append(f"| {s.get('stack','?')} | {s.get('metric','?')} | "
                       f"{fmt_ns(s.get('mean'))} | {fmt_ns(s.get('p50'))} | "
                       f"{fmt_ns(s.get('p99'))} |")
        out.append("")

    if tputs := aggregated.get("throughput_stack"):
        out.append("## Cross-implementation throughput")
        out.append("")
        out.append("_**Stack shapes** for the row that follows so the "
                   "numbers aren't apples-to-oranges:_")
        out.append("")
        out.append("| Stack | What's measured |")
        out.append("|---|---|")
        out.append("| `iperf3 TCP/UDP` | raw socket throughput, no "
                   "security, no framing |")
        out.append("| `rust-libp2p` | Noise XX + Yamux + libp2p-stream "
                   "(full mesh stack) |")
        out.append("| `iroh` | TLS 1.3 + QUIC + RPC open_bi per round |")
        out.append("| `GoodNet parody` | TcpLink/UdpLink/WsLink "
                   "through a stub host_api — no security, no framing, "
                   "matches `iperf3` shape |")
        out.append("| `GoodNet real` (planned) | full kernel: TcpLink + "
                   "Noise + gnet protocol — matches `libp2p` shape |")
        out.append("")
        out.append("| Stack | Metric | Throughput | Detail |")
        out.append("|---|---|---|---|")
        for t in tputs:
            bps = t.get("bytes_per_sec", 0)
            detail_parts = []
            if "duration_s" in t:
                detail_parts.append(f"{t['duration_s']} s")
            if "lost_percent" in t:
                detail_parts.append(f"{t['lost_percent']}% lost")
            if "retransmits" in t:
                detail_parts.append(f"{t['retransmits']} retr")
            if "payload_size" in t:
                detail_parts.append(f"{t['payload_size']}B × {t.get('iterations','?')}")
            detail = ", ".join(detail_parts) if detail_parts else "—"
            out.append(f"| {t.get('stack','?')} | {t.get('metric','?')} | "
                       f"{fmt_bytes_per_sec(bps)} | {detail} |")
        out.append("")

    if sizes := aggregated.get("binary_sizes"):
        out.append("## Binary sizes & deployment closure")
        out.append("")
        out.append("_Release + LTO + mold. `Dynamic shipping` is "
                   "what an operator copies to a host: the kernel "
                   "binary plus N plugin `.so` files. `Static` is "
                   "`make build-static` — every plugin's `.text` "
                   "linked into the kernel binary. `Nix closure` is "
                   "the worst-case `nix profile install` cost "
                   "(transitive dependency tree, de-dup'd on real "
                   "deployments via store sharing). `Docker image` "
                   "uses `debian:bookworm-slim` as the glibc base "
                   "(see `dist/Dockerfile.static`); a `scratch`-"
                   "based musl build would land near ~5 MiB but "
                   "needs a separate musl plugin port._")
        out.append("")
        out.append("| Artifact | Size |")
        out.append("|---|---|")
        if sizes.get("kernel_dynamic_bytes") is not None:
            out.append(f"| Dynamic kernel binary | "
                       f"{fmt_size_bytes(sizes['kernel_dynamic_bytes'])} |")
        if sizes.get("plugins_sum_bytes"):
            out.append(f"| Plugin `.so` files "
                       f"(sum, {sizes.get('plugin_count', '?')} files) | "
                       f"{fmt_size_bytes(sizes['plugins_sum_bytes'])} |")
        if sizes.get("kernel_dynamic_bytes") is not None \
                and sizes.get("plugins_sum_bytes"):
            total = (sizes["kernel_dynamic_bytes"]
                     + sizes["plugins_sum_bytes"])
            out.append(f"| **Dynamic shipping total** | "
                       f"**{fmt_size_bytes(total)}** |")
        if sizes.get("kernel_static_bytes") is not None:
            out.append(f"| **Static single binary** | "
                       f"**{fmt_size_bytes(sizes['kernel_static_bytes'])}** |")
        if sizes.get("kernel_static_stripped_bytes") is not None:
            out.append(f"| Static, stripped | "
                       f"{fmt_size_bytes(sizes['kernel_static_stripped_bytes'])} |")
        if sizes.get("nix_closure_kb") is not None:
            out.append(f"| Nix closure (`.#goodnet-core` + deps) | "
                       f"{fmt_size_kib(sizes['nix_closure_kb'])} |")
        if sizes.get("docker_image_kb") is not None:
            out.append(f"| Docker image (debian-slim + static binary) | "
                       f"{fmt_size_kib(sizes['docker_image_kb'])} |")
        out.append("")

    if weights := aggregated.get("comparison_weights"):
        out.append("## Comparison stack weights")
        out.append("")
        out.append("_Same axes as `## Binary sizes`, applied to "
                   "every external stack the bench compares "
                   "against. `Binary` is the executable on disk; "
                   "`Lib closure` is the sum of every distinct `.so` "
                   "the binary maps at runtime (from `ldd`, "
                   "excluding `linux-vdso`). Rust stacks "
                   "static-link their crates so `Binary` is the "
                   "meaningful number and `Lib closure` is just "
                   "glibc + libgcc_s + libm. C tools take the "
                   "opposite shape — small binary, large library "
                   "closure._")
        out.append("")
        out.append("| Stack | Binary | Lib closure | Total |")
        out.append("|---|---|---|---|")
        label_map = {
            "libp2p_rust": "rust-libp2p 0.55 (`libp2p-echo`)",
            "iroh_rust":   "iroh 0.32 (`iroh-echo`)",
            "iperf3":      "iperf3 (TCP/UDP throughput baseline)",
            "socat":       "socat (AF_UNIX echo baseline)",
            "openssl":     "openssl CLI (handshake baseline)",
        }
        for name in ("libp2p_rust", "iroh_rust", "iperf3", "socat",
                     "openssl"):
            s = weights.get("stacks", {}).get(name)
            if not s:
                continue
            out.append(
                f"| {label_map.get(name, name)} | "
                f"{fmt_size_bytes(s['binary_bytes'])} | "
                f"{fmt_size_bytes(s['libs_sum_bytes'])} | "
                f"**{fmt_size_bytes(s['total_bytes'])}** |")
        # Reference row from the GoodNet build itself so readers
        # don't have to scroll between sections to compare.
        if (bs := aggregated.get("binary_sizes")) is not None:
            if bs.get("kernel_dynamic_bytes") is not None \
                    and bs.get("plugins_sum_bytes"):
                gn_total = (bs["kernel_dynamic_bytes"]
                            + bs["plugins_sum_bytes"])
                out.append(
                    f"| **GoodNet dynamic** (kernel + 11 plugins) | "
                    f"{fmt_size_bytes(bs['kernel_dynamic_bytes'])} | "
                    f"{fmt_size_bytes(bs['plugins_sum_bytes'])} | "
                    f"**{fmt_size_bytes(gn_total)}** |")
            if bs.get("kernel_static_bytes") is not None:
                out.append(
                    f"| **GoodNet static** (single binary, all "
                    f"plugins linked in) | "
                    f"{fmt_size_bytes(bs['kernel_static_bytes'])} | "
                    f"— | "
                    f"**{fmt_size_bytes(bs['kernel_static_bytes'])}** |")
        out.append("")

    # ── Known crashes ─────────────────────────────────────────────
    #
    # A bench binary that crashed during the run produced either no
    # output, an empty file, or a truncated JSON. The runner forwards
    # those paths; the aggregator surfaces them as a named section so
    # the matrix below isn't quietly missing rows. See
    # `docs/perf/methodology.en.md` §4.3 for the operator's
    # "honest fixture failures" contract.
    if skipped := aggregated.get("skipped_inputs"):
        # Surface only crashes that *match* a known bench binary name —
        # otherwise empty / unparseable comparison-runner outputs leak
        # in here. The runner's filename convention is
        # `bench_<plugin>.json` for gbench inputs and arbitrary names
        # for comparison-harness JSON; matching on the prefix keeps
        # the section focused on the bench plugin crashes that
        # operators care about.
        bench_crashes = [
            (Path(p).stem, reason) for p, reason in skipped
            if Path(p).stem.startswith("bench_")
        ]
        if bench_crashes:
            out.append("## Known crashes — bench binaries that "
                       "produced no output")
            out.append("")
            out.append("_These bench binaries either exited before "
                       "writing their JSON header (segfault / heap "
                       "corruption) or wrote partial JSON the parser "
                       "could not decode. The matrix above is missing "
                       "every row from these binaries — by design, "
                       "since a `—` row would lie about whether the "
                       "fixture ran. Operators reproduce by running "
                       "the binary directly._")
            out.append("")
            out.append("| Binary | Parse failure |")
            out.append("|---|---|")
            for name, reason in bench_crashes:
                out.append(f"| `{name}` | `{reason}` |")
            out.append("")

    if tables := aggregated.get("tables"):
        for tbl in tables:
            out.append(f"## {tbl.get('metric', 'table')}")
            out.append("")
            if note := tbl.get("note"):
                out.append(f"_{note}_")
                out.append("")
            rows = tbl.get("rows", [])
            if rows:
                cols = list(rows[0].keys())
                out.append("| " + " | ".join(cols) + " |")
                out.append("|" + "---|" * len(cols))
                for r in rows:
                    cells = []
                    for c in cols:
                        v = r.get(c, "")
                        if c == "bytes_per_sec" and isinstance(v, (int, float)) and v > 0:
                            cells.append(fmt_bytes_per_sec(v))
                        elif c == "handshake_ms" and isinstance(v, (int, float)) and v > 0:
                            cells.append(f"{v:.2f} ms")
                        elif c == "payload" and isinstance(v, (int, float)):
                            cells.append(f"{int(v)} B")
                        else:
                            cells.append(str(v))
                    out.append("| " + " | ".join(cells) + " |")
            out.append("")

    Path(args.output).write_text("\n".join(out))
    print(f"wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
