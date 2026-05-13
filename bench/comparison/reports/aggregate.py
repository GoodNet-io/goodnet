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
        row = {
            "stack": "goodnet",
            "case":  name,
            "time_ns": time_ns,
            "throughput_bps": bps,
            "error":  error_msg,
            "p50_ns": b.get("lat_p50_ns"),
            "p95_ns": b.get("lat_p95_ns"),
            "p99_ns": b.get("lat_p99_ns"),
            "rss_kb_delta":      b.get("rss_kb_delta"),
            "rss_peak_kb_delta": b.get("rss_peak_kb_delta"),
            "vsz_peak_kb_delta": b.get("vsz_peak_kb_delta"),
            "sock_mem_kb_delta": b.get("sock_mem_kb_delta"),
            "minor_faults":      b.get("minor_faults"),
            "cpu_user_us":       b.get("cpu_user_us"),
            "cpu_sys_us":        b.get("cpu_sys_us"),
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

    if perf := aggregated.get("perf"):
        out.append("## Parody — GoodNet plugin matrix (raw transport, "
                   "no security, no protocol layer)")
        out.append("")
        out.append("_**Shape**: bench fixtures wire the link plugin to a "
                   "test stub `host_api` — no security provider is "
                   "registered, no protocol layer frames the bytes. "
                   "Numbers are the upper-bound the plugin can deliver "
                   "to a downstream that drains as fast as the link "
                   "writes. Compare against `iperf3` rows below (also "
                   "no security, no framing) for a fair stack-by-stack "
                   "delta. For the production-shape numbers see the "
                   "`## Real` section once `bench_real_e2e` lands (plan "
                   "§A.2)._")
        out.append("")
        out.append("_Memory deltas: `RSS Δ` = `VmRSS_end − VmRSS_start` "
                   "(current; allocator `madvise(MADV_DONTNEED)` masks "
                   "bursts that returned). `RSS Peak Δ` = `VmHWM_end − "
                   "VmHWM_start` (high-water-mark; catches bursts). "
                   "`VSZ Peak Δ` = same for VmPeak (virtual address "
                   "space, includes mmap'd-but-untouched). `Sock Mem Δ` = "
                   "kernel TCP+UDP+FRAG buffers from "
                   "`/proc/net/sockstat` (system-wide; bench attribution "
                   "via window-delta — every other socket on a quiet "
                   "test machine stays at steady state)._")
        out.append("")
        out.append("| Case | Time | Throughput | P50 lat | P99 lat | "
                   "RSS Δ | RSS Peak Δ | VSZ Peak Δ | Sock Mem Δ | "
                   "Minor Faults |")
        out.append("|---|---|---|---|---|---|---|---|---|---|")
        for r in perf:
            tput = fmt_bytes_per_sec(r["throughput_bps"]) if r["throughput_bps"] else "-"
            mf = r.get("minor_faults")
            mf_str = f"{int(mf):,}" if mf is not None and mf > 0 else "—"
            out.append(f"| {r['case']} | {fmt_ns(r['time_ns'])} | {tput} | "
                       f"{fmt_ns(r['p50_ns'])} | {fmt_ns(r['p99_ns'])} | "
                       f"{fmt_kb(r.get('rss_kb_delta'))} | "
                       f"{fmt_kb(r.get('rss_peak_kb_delta'))} | "
                       f"{fmt_kb(r.get('vsz_peak_kb_delta'))} | "
                       f"{fmt_kb(r.get('sock_mem_kb_delta'))} | "
                       f"{mf_str} |")
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
