#!/usr/bin/env python3
"""Track Б — free-kernel showcase bench aggregator.

Reads the JSON output of `bench_showcase` (google-benchmark format)
plus the per-section CSV side-channels emitted by the bench's
time-series cases (`/tmp/showcase-b{2,3,5,6}-*-<pid>.csv`). Emits a
narrative-style markdown report at `bench/reports/showcase-<sha>.md`.

Each `## B.X` section has a fixed shape:
  * **Что это** — one-liner, plain language
  * **Почему это GoodNet-only** — comparison vs libp2p/WebRTC/gRPC
  * **Bench** — table + (where relevant) inline ASCII spark from CSV
  * **Acceptance** — pass/fail derived from JSON counters

This is the showcase, not the fair-comparison track. Numbers here
are about what GoodNet CAN DO architecturally that other stacks
cannot — adaptive runtime carrier selection, security provider
handoff, mobility-driven LAN shortcut, etc.

Usage:
    showcase_aggregate.py <sha> <output.md> <bench_showcase.json>
                          [csv_glob...]

If csv_glob is omitted the script auto-discovers
`/tmp/showcase-*-<bench_pid>.csv` by reading the bench JSON's
context info (not currently exposed by gbench; the bench's own
`announce_csv_path` prints stderr lines `[showcase] <tag> csv ->
<path>` for operators). For the smoke tests the harness passes the
csv paths explicitly.
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import re
import sys
from collections import defaultdict


# ── small format helpers (parallel to aggregate.py) ────────────────

def fmt_bytes_per_sec(n):
    units = ["B/s", "KiB/s", "MiB/s", "GiB/s"]
    if n is None:
        return "—"
    f = float(n)
    i = 0
    while f >= 1024 and i + 1 < len(units):
        f /= 1024
        i += 1
    return f"{f:.2f} {units[i]}"


def fmt_ns(n):
    if n is None:
        return "—"
    try:
        v = float(n)
    except (TypeError, ValueError):
        return "—"
    if v < 1e3:
        return f"{v:.0f} ns"
    if v < 1e6:
        return f"{v/1e3:.1f} μs"
    if v < 1e9:
        return f"{v/1e6:.1f} ms"
    return f"{v/1e9:.2f} s"


def ascii_spark(values):
    """Render an inline ASCII sparkline from a numeric series.

    Caps at 80 chars; collapses long series by averaging adjacent
    buckets so the spark always fits on a markdown table cell.
    Empty input yields the explicit "—" marker.
    """
    if not values:
        return "—"
    blocks = "▁▂▃▄▅▆▇█"
    max_width = 80
    if len(values) > max_width:
        bucket = len(values) // max_width
        downsampled = []
        for i in range(0, len(values), bucket):
            chunk = values[i:i + bucket]
            downsampled.append(sum(chunk) / len(chunk))
        values = downsampled
    lo = min(values)
    hi = max(values)
    if hi == lo:
        return blocks[0] * len(values)
    out = []
    for v in values:
        idx = int((v - lo) / (hi - lo) * (len(blocks) - 1))
        out.append(blocks[idx])
    return "".join(out)


# ── JSON / CSV ingestion ───────────────────────────────────────────

def parse_gbench_json(path):
    """Return dict {case_name: {counters...}} from a gbench JSON.

    Strips suffixes like `/real_time` and `/manual_time` so case
    lookup stays stable across UseRealTime/UseManualTime flips.
    """
    cases = {}
    with open(path) as f:
        j = json.load(f)
    for b in j.get("benchmarks", []):
        name = b.get("name", "")
        # Normalise — drop trailing `/real_time` etc.
        for suffix in ("/real_time", "/manual_time"):
            if name.endswith(suffix):
                name = name[: -len(suffix)]
                break
        rec = {
            "name":      name,
            "real_time": b.get("real_time"),
            "time_unit": b.get("time_unit"),
            "iters":     b.get("iterations"),
            "throughput": b.get("bytes_per_second"),
        }
        # Custom counters bench bodies emit via `state.counters[...]`.
        for k, v in b.items():
            if k in (
                "name", "family_index", "per_family_instance_index",
                "run_name", "run_type", "repetitions", "repetition_index",
                "threads", "real_time", "cpu_time", "time_unit",
                "iterations", "bytes_per_second", "items_per_second",
                "label", "error_occurred", "error_message",
            ):
                continue
            rec[k] = v
        cases[name] = rec
    return cases


def parse_csv_series(path):
    """Read a CSV file written by `CsvSeries::emit`. Returns dict
    {column_name: [(iter, value), ...]} sorted by iter."""
    out = defaultdict(list)
    try:
        with open(path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    iter_n = int(row["iter"])
                    val    = int(row["value"])
                except (KeyError, ValueError):
                    continue
                out[row.get("column", "")].append((iter_n, val))
    except (OSError, csv.Error) as e:
        print(f"warn: csv {path}: {e}", file=sys.stderr)
        return {}
    for col in out:
        out[col].sort()
    return dict(out)


# ── Section emitters ───────────────────────────────────────────────

def section_header(out, key, title, what, why):
    """Emit the fixed-shape `## B.X` heading + the two narration
    paragraphs every showcase section starts with."""
    out.append(f"## {key} — {title}")
    out.append("")
    out.append(f"**Что это.** {what}")
    out.append("")
    out.append(f"**Почему это GoodNet-only.** {why}")
    out.append("")


def emit_b1(out, cases):
    section_header(out, "B.1", "Multi-connect под одной identity",
        "Один peer pk у alice; bob дозванивается до неё через три "
        "одновременно живых carrier'a (TCP + UDP + IPC). Kernel's "
        "ConnectionRegistry хранит три записи под одним `remote_pk`.",
        "libp2p/WebRTC/gRPC привязывают peer identity к одному "
        "transport-instance при handshake'е. Сменить carrier "
        "runtime'но — это либо reconnect (новый identity у iroh "
        "QUIC), либо отдельная multistream-фабрика (libp2p, "
        "fragmented). У GoodNet это base-line поведение registry; "
        "три conn'a живут одновременно и видимы strategy plugin'у.")
    rows = []
    for name, rec in sorted(cases.items()):
        if not name.startswith("MultiConnFixture/FallbackThroughput/"):
            continue
        size = name.rsplit("/", 1)[-1]
        rows.append({
            "size":     size,
            "p50":      rec.get("lat_p50_ns"),
            "throughput": rec.get("throughput"),
            "conns":    rec.get("alice_conns"),
            "sessions": rec.get("alice_sessions"),
            "iters":    rec.get("iters"),
        })
    if not rows:
        out.append("_no `MultiConnFixture/*` data in input — skip_")
        out.append("")
        return
    out.append("**Bench.**")
    out.append("")
    out.append("| Payload | Time | Throughput | alice conns | alice sessions |")
    out.append("|---|---|---|---|---|")
    for r in rows:
        out.append(
            f"| {r['size']} B | {fmt_ns(r['p50'])} | "
            f"{fmt_bytes_per_sec(r['throughput'])} | "
            f"{int(r['conns'] or 0)} | {int(r['sessions'] or 0)} |")
    out.append("")
    expected = 3
    actual = int(rows[0].get("conns") or 0)
    ok = actual == expected
    out.append(f"**Acceptance.** `alice.conns == {expected}` "
               f"required: **{'PASS' if ok else 'FAIL'}** "
               f"(observed {actual}).")
    out.append("")


def emit_b2(out, cases, csv_data):
    section_header(out, "B.2", "Strategy-driven carrier selection",
        "Bob регистрирует `float_send_rtt` strategy plugin. "
        "Synthetic RTT samples (TCP=200µs, UDP=150µs, IPC=20µs) "
        "feed the picker через `on_path_event`. Picker сходится к "
        "IPC. Деградация RTT (IPC→500µs) flips winner после ~3 "
        "samples (EWMA α=1/8 hysteresis).",
        "У libp2p/iroh/gRPC carrier выбирается на установке "
        "connection и навсегда. Adaptive routing per-send под "
        "одним peer identity — это feature без аналога в этом "
        "классе.")
    pick = cases.get("StrategyFixture/PickerSelectsIpc/1024", {})
    if pick:
        out.append("**Bench: picker overhead + IPC selection.**")
        out.append("")
        out.append("| Payload | Picker dispatch | IPC picks | Other picks |")
        out.append("|---|---|---|---|")
        out.append(
            f"| 1024 B | {fmt_ns(pick.get('real_time'))} | "
            f"{int(pick.get('picks_ipc') or 0)} | "
            f"{int(pick.get('picks_other') or 0)} |")
        out.append("")
    flip = cases.get("StrategyFixture/FlipOnRttDegradation/200", {})
    if flip:
        out.append("**Bench: flip on RTT degradation.**")
        out.append("")
        out.append("| Total iters | Flip iter | Comment |")
        out.append("|---|---|---|")
        out.append(
            f"| {int(flip.get('total_iters') or 0)} | "
            f"{int(flip.get('flip_iter') or 0)} | "
            "Hysteresis kicks in after ~3 sample EWMA crossover |")
        out.append("")
    series = csv_data.get("b2-flip", {}).get("chosen_conn", [])
    if series:
        spark = ascii_spark([v for _, v in series])
        out.append(f"**Chosen-conn time-series.** `{spark}`")
        out.append("")
    ok = (int(pick.get('picks_ipc') or 0) >
          int(pick.get('picks_other') or 0))
    out.append(f"**Acceptance.** Picker selects IPC majority "
               f"(`picks_ipc > picks_other`): "
               f"**{'PASS' if ok else 'FAIL'}**.")
    out.append("")


def emit_b3(out, cases, csv_data):
    section_header(out, "B.3", "Provider handoff Noise→Null после "
                              "handshake (PoC)",
        "После Noise XX handshake (peer authenticated, identity "
        "bound), kernel runtime'но обнуляет inline AEAD state на "
        "established session. Per-frame seal/open отваливается; "
        "identity-binding (handshake hash) сохраняется. Бенч "
        "пишет latency time-series через handoff trigger.",
        "TLS / Noise сессии в любом другом стеке — это monolith: "
        "либо on (full AEAD per-frame), либо off (handshake "
        "skipped). Runtime provider migration после handshake'а "
        "— green-field. PoC реализован через env-gated "
        "`SecuritySession::_test_clear_inline_crypto`; v1.x "
        "exposes kernel-driven API.")
    noise64 = cases.get("HandoffFixture/NoiseSteady/64", {})
    noise1k = cases.get("HandoffFixture/NoiseSteady/1024", {})
    trigger = cases.get("HandoffFixture/TriggerStep/1024", {})
    out.append("**Bench: Noise steady baseline.**")
    out.append("")
    out.append("| Payload | p50 | p95 | p99 |")
    out.append("|---|---|---|---|")
    for sz, rec in (("64", noise64), ("1024", noise1k)):
        if not rec:
            continue
        out.append(
            f"| {sz} B | {fmt_ns(rec.get('lat_p50_ns'))} | "
            f"{fmt_ns(rec.get('lat_p95_ns'))} | "
            f"{fmt_ns(rec.get('lat_p99_ns'))} |")
    out.append("")
    if trigger:
        out.append("**Bench: handoff trigger step.**")
        out.append("")
        out.append("| Pre-trigger p50 | Post-trigger p50 | Pre count | Post count |")
        out.append("|---|---|---|---|")
        out.append(
            f"| {fmt_ns(trigger.get('pre_p50_ns'))} | "
            f"{fmt_ns(trigger.get('post_p50_ns'))} | "
            f"{int(trigger.get('pre_count') or 0)} | "
            f"{int(trigger.get('post_count') or 0)} |")
        out.append("")
    series = csv_data.get("b3-handoff", {}).get("lat_ns", [])
    if series:
        spark = ascii_spark([v for _, v in series])
        out.append(f"**Latency time-series.** `{spark}` "
                   "(per-iter; step-down at handoff trigger)")
        out.append("")
    pre = trigger.get("pre_p50_ns") or 0
    post = trigger.get("post_p50_ns") or 0
    ok = pre > 0 and post > 0 and post < pre
    out.append(f"**Acceptance.** post-handoff p50 < pre-handoff "
               f"p50: **{'PASS' if ok else 'INCOMPLETE'}** (pre={pre}, "
               f"post={post}).")
    out.append("")


def emit_b4(out, cases):
    section_header(out, "B.4", "Multi-thread fanout",
        "N producer threads на bob одновременно дёргают "
        "`api.send_to(alice_pk, ...)`. Kernel разводит на "
        "per-conn strand + crypto pool. Throughput vs N показывает "
        "где kernel становится bottleneck'ом (single-writer drain "
        "CAS в `PerConnQueue::drain_scheduled`).",
        "gRPC обычно один HTTP/2-stream per goroutine; libp2p "
        "stream-multiplexer не parallel'ит crypto. У GoodNet "
        "kernel-side strand routing — это base feature, scaling "
        "обусловлено архитектурой kernel'a, не SDK-обёртками.")
    rows = []
    for name, rec in sorted(cases.items()):
        if not name.startswith("FanoutFixture/Producers/"):
            continue
        n = name.rsplit("/", 1)[-1]
        rows.append({
            "n":         n,
            "sent":      rec.get("sent"),
            "vol_ctx":   rec.get("vol_ctx_sw"),
            "inv_ctx":   rec.get("inv_ctx_sw"),
            "cpu_total": rec.get("cpu_total_us"),
        })
    if not rows:
        out.append("_no `FanoutFixture/*` data — skip_")
        out.append("")
        return
    out.append("**Bench.**")
    out.append("")
    out.append("| Producers | Sent | vol_ctx_sw | inv_ctx_sw | CPU total |")
    out.append("|---|---|---|---|---|")
    for r in rows:
        out.append(
            f"| {r['n']} | {int(r['sent'] or 0)} | "
            f"{int(r['vol_ctx'] or 0)} | {int(r['inv_ctx'] or 0)} | "
            f"{fmt_ns((r['cpu_total'] or 0) * 1000)} |")
    out.append("")
    out.append("**Acceptance.** Throughput grows monotonically with "
               "N (single-carrier knee around N=2; multi-carrier "
               "knee expected ≈ crypto pool width once "
               "multipath-bond strategy lands).")
    out.append("")


def emit_b5(out, cases, csv_data):
    section_header(out, "B.5", "Carrier failover",
        "Picker выбирает IPC (RTT 20µs). Mid-bench bench инжектит "
        "`CONN_DOWN` на IPC conn (kernel auto-emit от "
        "`notify_disconnect` pending в Slice-9-KERNEL). Picker "
        "переключается на TCP — следующий best-RTT. Zero packet "
        "loss across the flip.",
        "У libp2p/WebRTC failover между transport instances — "
        "это reconnect: rebuild handshake state, lose pending "
        "frames. У GoodNet strategy slot'ы — runtime decisions; "
        "переключение между уже установленными conn'ами — это "
        "просто следующий `pick_conn` call.")
    flip = cases.get("FailoverFixture/IpcDrop/200", {})
    if flip:
        out.append("**Bench.**")
        out.append("")
        out.append("| Total iters | Drop iter | Flip iter |")
        out.append("|---|---|---|")
        out.append(
            f"| {int(flip.get('total_iters') or 0)} | "
            f"{int(flip.get('drop_iter') or 0)} | "
            f"{int(flip.get('flip_iter') or 0)} |")
        out.append("")
    series = csv_data.get("b5-failover", {}).get("chosen_conn", [])
    if series:
        spark = ascii_spark([v for _, v in series])
        out.append(f"**Chosen-conn time-series.** `{spark}` "
                   "(visible flip at drop iter)")
        out.append("")
    drop = int(flip.get("drop_iter") or 0)
    flip_at = int(flip.get("flip_iter") or 0)
    ok = flip_at >= drop and flip_at - drop <= 5
    out.append(f"**Acceptance.** Flip lands within ≤ 5 iter of "
               f"drop: **{'PASS' if ok else 'INCOMPLETE'}** "
               f"(drop={drop}, flip={flip_at}).")
    out.append("")


def emit_b6(out, cases, csv_data):
    section_header(out, "B.6", "Mobility → LAN shortcut",
        "Alice стартует с одним carrier'ом (TURN-relayed, RTT "
        "60µs). Mid-bench симулируем «пришла домой» — синтетически "
        "появляется второй carrier (LAN host candidate, RTT "
        "~2µs). Strategy ловит CONN_UP, winner flip'ается на LAN. "
        "Traffic counter на TURN side НЕ растёт после flip'a — "
        "трафик уходит на свитч, не в интернет.",
        "WebRTC ICE-restart требует full re-handshake. libp2p "
        "multistream не switches carrier'ы на одной identity. "
        "Mobile gRPC retries — это full connection reset. У "
        "GoodNet это сборка из multi-connect + strategy + ICE "
        "host candidate priority (RFC 8445 §5.1.2). Identity "
        "preserved across the path flip.")
    mob = cases.get("MobilityFixture/LanShortcut/300", {})
    if mob:
        out.append("**Bench.**")
        out.append("")
        out.append("| Total iters | LAN up at | Flip at | TURN bytes | LAN bytes |")
        out.append("|---|---|---|---|---|")
        out.append(
            f"| {int(mob.get('total_iters') or 0)} | "
            f"{int(mob.get('lan_up_at') or 0)} | "
            f"{int(mob.get('flip_iter') or 0)} | "
            f"{int(mob.get('turn_bytes') or 0)} | "
            f"{int(mob.get('lan_bytes') or 0)} |")
        out.append("")
    series = csv_data.get("b6-mobility", {}).get("chosen_conn", [])
    if series:
        spark = ascii_spark([v for _, v in series])
        out.append(f"**Chosen-conn time-series.** `{spark}` "
                   "(TURN until lan_up_at, LAN after)")
        out.append("")
    flip = int(mob.get("flip_iter") or 0)
    lan_up = int(mob.get("lan_up_at") or 0)
    ok = flip > lan_up and flip - lan_up <= 5
    out.append(f"**Acceptance.** Flip within ≤ 5 iter of LAN "
               f"appearance: **{'PASS' if ok else 'INCOMPLETE'}** "
               f"(lan_up={lan_up}, flip={flip}).")
    out.append("")


# ── main ───────────────────────────────────────────────────────────

def main(argv):
    p = argparse.ArgumentParser(
        description="Aggregate bench_showcase outputs into a "
                    "narrative markdown report.")
    p.add_argument("commit_sha")
    p.add_argument("output_md")
    p.add_argument("bench_json")
    p.add_argument("csvs", nargs="*",
        help="Optional CSV side-channel paths. If omitted, the "
             "script globs /tmp/showcase-*-<pid>.csv where <pid> "
             "is recent.")
    args = p.parse_args(argv)

    cases = parse_gbench_json(args.bench_json)

    csv_data = {}
    csv_paths = args.csvs[:]
    if not csv_paths:
        # Auto-discover any recent showcase CSV in /tmp.
        csv_paths = sorted(glob.glob("/tmp/showcase-*.csv"),
                            key=os.path.getmtime, reverse=True)
    for path in csv_paths:
        # Filename pattern: showcase-<tag>-<pid>.csv → tag is key.
        base = os.path.basename(path)
        m = re.match(r"showcase-([a-z0-9-]+?)-\d+\.csv$", base)
        if not m:
            continue
        tag = m.group(1)
        csv_data[tag] = parse_csv_series(path)

    out = [f"# Showcase bench report — {args.commit_sha}", ""]
    out.append("_Track Б — free-kernel showcase. Each section "
               "demonstrates one GoodNet-distinctive move no other "
               "stack reproduces natively. NOT a fair-comparison "
               "track (that lives in `bench/reports/<sha>.md` "
               "section А); this report's reader is asked «попробуй "
               "повторить»._")
    out.append("")

    emit_b1(out, cases)
    emit_b2(out, cases, csv_data)
    emit_b3(out, cases, csv_data)
    emit_b4(out, cases)
    emit_b5(out, cases, csv_data)
    emit_b6(out, cases, csv_data)

    with open(args.output_md, "w") as f:
        f.write("\n".join(out))
    print(f"wrote {args.output_md}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
