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


def parse_gbench(j, out):
    for b in j.get("benchmarks", []):
        name = b.get("name", "?")
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
        row = {
            "stack": "goodnet",
            "case":  name,
            "time_ns": time_ns,
            "throughput_bps": bps,
            "error":  error_msg,
            "p50_ns":  b.get("lat_p50_ns"),
            "p95_ns":  b.get("lat_p95_ns"),
            "p99_ns":  b.get("lat_p99_ns"),
            "p999_ns": b.get("lat_p999_ns"),
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


def parse_comparison(j, out):
    if j.get("metric") == "binary_sizes":
        out["binary_sizes"] = j
        return
    if j.get("metric") == "comparison_weights":
        out["comparison_weights"] = j
        return
    if "rows" in j:
        out.setdefault("tables", []).append(j)
        return
    if "metric" in j and "p50" in j:
        out.setdefault("single_stack", []).append(j)
        return
    if "metric" in j and "bytes_per_sec" in j:
        out.setdefault("throughput_stack", []).append(j)


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


# Bench `case` names that came from the in-process kernel + real
# security/protocol stack are tagged with the `RealFixture/` prefix
# (see `bench/plugins/bench_real_e2e.cpp`, plan §A.2). Anything
# else is parody — link plugin + LinkStub, no security, no framing.
_REAL_PREFIX = "RealFixture/"


def is_real_row(row):
    return row.get("case", "").startswith(_REAL_PREFIX)


def main(argv):
    p = argparse.ArgumentParser()
    p.add_argument("commit_sha")
    p.add_argument("output")
    p.add_argument("inputs", nargs="+")
    args = p.parse_args(argv)

    aggregated = {}
    for path in args.inputs:
        try:
            with open(path) as f:
                content = f.read().strip()
            if not content:
                continue
            j = json.loads(content)
        except (json.JSONDecodeError, OSError) as e:
            print(f"warn: skipping {path}: {e}", file=sys.stderr)
            continue
        if "benchmarks" in j:
            parse_gbench(j, aggregated)
        else:
            parse_comparison(j, aggregated)

    out = [f"# Benchmark report — {args.commit_sha}", ""]

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
    for r in aggregated.get("perf", []):
        m = plug_re.match(r.get("case", ""))
        if not m or int(m.group("sz")) != canon_payload:
            continue
        if not r.get("throughput_bps"):
            continue
        kind = "echo-RTT" if m.group("kind") == "EchoRoundtrip" else "send-only"
        shape = "real" if is_real_row(r) else "parody"
        tldr_rows.append({
            "stack":       f"GoodNet {m.group('plug').upper()}",
            "shape":       shape,
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

    # ── Side-by-side echo round-trip ─────────────────────────────────
    #
    # Pivots `*Fixture/EchoRoundtrip/<payload>` gbench rows AND
    # libp2p / iroh runner tables into a single matrix where rows
    # are payload sizes and columns are stacks. Lets the reader see
    # GoodNet vs libp2p vs iroh at the same payload without scrolling
    # between per-stack sections below.
    echo_re = re.compile(
        r"^(?P<plug>Udp|Ws)Fixture/EchoRoundtrip/(?P<sz>\d+)/")
    by_payload: dict[int, dict[str, float]] = {}
    for r in aggregated.get("perf", []):
        m = echo_re.match(r.get("case", ""))
        if not m or not r.get("throughput_bps"):
            continue
        sz = int(m.group("sz"))
        col = f"GoodNet {m.group('plug').upper()}"
        by_payload.setdefault(sz, {})[col] = float(r["throughput_bps"])
    for tbl in aggregated.get("tables", []):
        if tbl.get("metric") not in (
                "libp2p_echo_throughput", "iroh_echo_throughput"):
            continue
        for row in tbl.get("rows", []):
            sz = row.get("payload")
            bps = row.get("bytes_per_sec", 0)
            if not isinstance(sz, (int, float)) or not bps:
                continue
            col = row.get("stack", "?")
            by_payload.setdefault(int(sz), {})[col] = float(bps)
    if by_payload:
        stacks = ["GoodNet UDP", "GoodNet WS", "libp2p", "iroh"]
        out.append("## Echo round-trip — side-by-side (parody shape)")
        out.append("")
        out.append("_loopback, round-trip bytes/sec at the application_")
        out.append("_layer; one-way send-only numbers live in "
                   "`## Parody — GoodNet plugin matrix` (`Throughput`) "
                   "and `## Cross-implementation throughput` (iperf3)._")
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

    def emit_perf_table(rows, shape_label):
        out.append("| Case | Time | Throughput | CPU/B | P50 lat | "
                   "P99 lat | RSS Δ | RSS Peak Δ | VSZ Peak Δ | "
                   "Sock Mem Δ | Minor Faults | Ctx Sw (vol/inv) |")
        out.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
        for r in rows:
            tput = (fmt_bytes_per_sec(r["throughput_bps"])
                    if r["throughput_bps"] else "-")
            mf = r.get("minor_faults")
            mf_str = f"{int(mf):,}" if mf is not None and mf > 0 else "—"
            # Voluntary / involuntary context switches as a pair.
            # Voluntary = thread gave up the slice (mutex / condvar /
            # io_context post / sleep) — high count means lots of
            # synchronisation. Involuntary = preempted (slice
            # expired / higher-priority task arrived) — high count
            # means saturated CPU. Both reveal whether a throughput
            # number was bottlenecked by sync vs CPU.
            vol = r.get("vol_ctx_sw")
            inv = r.get("inv_ctx_sw")
            if vol is None and inv is None:
                cs_str = "—"
            else:
                cs_str = (f"{int(vol or 0):,} / {int(inv or 0):,}")
            # Strip the `RealFixture/` prefix from the case name in
            # the Real table so a reader scanning the column gets
            # `TcpEcho/1024` not `RealFixture/TcpEcho/1024` repeated.
            case = r["case"]
            if shape_label == "real" and case.startswith(_REAL_PREFIX):
                case = case[len(_REAL_PREFIX):]
            out.append(
                f"| {case} | {fmt_ns(r['time_ns'])} | {tput} | "
                f"{fmt_per_byte(r.get('cpu_ns_per_byte'))} | "
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
                                       "p99_ns", "p999_ns"))
        ]
        if lat_rows:
            out.append("## Latency tail — P50 → P99.9 ladder")
            out.append("")
            out.append("_Tail latency is the dimension that distinguishes "
                       "an evenly-paced p2p stack from one that pauses on "
                       "GC / strand-hop / allocator slow paths. A widening "
                       "gap between P99 and P99.9 across rows is the "
                       "signal — flat rows mean the bench body is "
                       "uniformly fast. Cases with a single iteration "
                       "(handshake fixtures) report the same number at "
                       "every percentile by definition._")
            out.append("")
            out.append("| Case | P50 | P95 | P99 | P99.9 |")
            out.append("|---|---|---|---|---|")
            for r in lat_rows:
                case = r["case"]
                if case.startswith(_REAL_PREFIX):
                    case = "real:" + case[len(_REAL_PREFIX):]
                out.append(
                    f"| {case} | "
                    f"{fmt_ns(r.get('p50_ns'))} | "
                    f"{fmt_ns(r.get('p95_ns'))} | "
                    f"{fmt_ns(r.get('p99_ns'))} | "
                    f"{fmt_ns(r.get('p999_ns'))} |")
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
