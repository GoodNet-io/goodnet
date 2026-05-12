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
        time_ns = float(time) * scale if time else None
        row = {
            "stack": "goodnet",
            "case":  name,
            "time_ns": time_ns,
            "throughput_bps": bps,
            "p50_ns": b.get("lat_p50_ns"),
            "p95_ns": b.get("lat_p95_ns"),
            "p99_ns": b.get("lat_p99_ns"),
            "rss_kb_delta": b.get("rss_kb_delta"),
            "cpu_user_us": b.get("cpu_user_us"),
            "cpu_sys_us":  b.get("cpu_sys_us"),
        }
        out.setdefault("perf", []).append(row)


def parse_comparison(j, out):
    if "rows" in j:
        out.setdefault("tables", []).append(j)
        return
    if "metric" in j and "p50" in j:
        out.setdefault("single_stack", []).append(j)
        return
    if "metric" in j and "bytes_per_sec" in j:
        out.setdefault("throughput_stack", []).append(j)


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

    if perf := aggregated.get("perf"):
        out.append("## GoodNet plugin matrix")
        out.append("")
        out.append("| Case | Time | Throughput | P50 lat | P99 lat | RSS Delta |")
        out.append("|---|---|---|---|---|---|")
        for r in perf:
            tput = fmt_bytes_per_sec(r["throughput_bps"]) if r["throughput_bps"] else "-"
            out.append(f"| {r['case']} | {fmt_ns(r['time_ns'])} | {tput} | "
                       f"{fmt_ns(r['p50_ns'])} | {fmt_ns(r['p99_ns'])} | "
                       f"{r['rss_kb_delta'] or '-'} KB |")
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
