# Bench methodology — parody vs real, and how to read the report

Status: living document.
Last verified: 2026-05-13.
Owner: `bench/` + `bench/comparison/reports/aggregate.py`.

This page is the single answer to "why does the bench report
quote two different GoodNet numbers and which one should I
believe." Read it before pasting a row out of
`bench/reports/<sha>.md` into a slide deck.

---

## 1. The two shapes a bench can have

The aggregator splits every GoodNet row into one of two **shapes**.
Same `host_api->send` entry point on the operator side; different
amount of plumbing underneath.

### 1.1 Parody — raw transport, no security, no protocol layer

The fixture wires the link plugin (`gn.link.tcp`, `gn.link.udp`,
`gn.link.ws`, ...) directly to a `LinkStub` test `host_api`. The
stub registers no security provider, no protocol layer, no
strategy plugin. Bytes flow:

```
caller → link plugin → loopback socket → link plugin (peer) → LinkStub
```

This is the **upper bound** of what the plugin can deliver to a
downstream that drains as fast as the link can write. It is
**directly comparable** to `iperf3 TCP/UDP` and `socat
AF_UNIX` — those tools are also a raw socket / pipe with no
crypto, no framing. If GoodNet parody is slower than iperf3 the
plugin has a bug; if it is comparable the link layer is
healthy.

What parody is **not** comparable to: `rust-libp2p`, `iroh`,
real production GoodNet. Those carry Noise / TLS / framing /
multiplexing. Comparing them to parody would flatter GoodNet by
~10×; doing so is the bench methodology error this
document exists to prevent.

### 1.2 Real — production-shape echo

The fixture boots a full `gn::core::Kernel`, registers
`gn.security.noise` for peer trust, frames bytes through
`gn.protocol.gnet`, and connects the link plugin through the
real `host_api` (not the stub). Bytes flow:

```
caller → host_api → protocol layer (frame) → security (AEAD) →
       link plugin → loopback socket → link plugin (peer) →
       security (verify+decrypt) → protocol layer (deframe) →
       handler dispatch
```

This is what an operator-facing `send()` actually pays. It is
**directly comparable** to `rust-libp2p` (TCP + Noise XX + Yamux
+ libp2p-stream) and `iroh` (TLS 1.3 + QUIC + RPC). When the
report quotes a "GoodNet real" row next to libp2p / iroh, the
two are running through the same conceptual stack: secured,
multiplexed, framed.

What real-mode is **not** comparable to: `iperf3` numbers. Doing
so would pessimise GoodNet by ~5-10× because iperf3 doesn't pay
for crypto.

Case names with the `RealFixture/` prefix carry this shape.
Currently (slice A.2 — `3d58cf3`) the bodies are
`SkipWithError`-stubbed; numbers materialise once the
kernel-boot helper lands. See the §A.2 entry in the master plan
for the path to real numbers.

---

## 2. How to read a row

Pick the column you actually care about; the aggregator emits
the rest for context.

### 2.1 Throughput / payload

Pick at the **canonical 1 KB payload** for cross-stack apples-to-
apples. Smaller (64 B) shows per-syscall overhead; larger
(64 KiB) shows pure I/O. Every reference stack
(libp2p / iroh / iperf3) is bench'd at 1 KB so that's where
the TL;DR table lives.

### 2.2 CPU/B

CPU ns per byte sent, derived from `getrusage` user + sys time
and effective throughput. This is the **most portable** number
in the report — it doesn't change with link speed, payload
size or socket buffer tuning. Two CPU/B numbers across the same
payload are directly comparable; two raw `MiB/s` numbers at
different payloads are not.

Typical values (synthetic; real numbers in
`bench/reports/<sha>.md`):
- iperf3 TCP loopback: ~0.05 ns/B (basically nothing)
- GoodNet parody TCP: ~0.1 ns/B (link plugin overhead)
- GoodNet real TCP: ~3-5 ns/B (Noise AEAD + gnet framing)
- libp2p TCP: ~5-8 ns/B (Noise XX + Yamux per-frame
  bookkeeping)

The `## Cost decomposition` section in the report pivots
parody → real for the same payload and surfaces the Δ CPU/B
directly. That delta IS the production-stack cost: zero out
parody, you get raw Noise + gnet per-byte ns.

### 2.3 Tail latency

`## Latency tail` ladders P50 → P95 → P99 → P99.9 for every
fixture that recorded percentiles. Tail behaviour is the
discriminator between a uniformly-paced stack and one that
stalls on allocator / strand-hop / GC slow paths. P99 alone
doesn't reveal a stall; the P99.9 → P99 ratio does.

Operators picking a stack for latency-sensitive RPC weight
P99.9 over throughput.

### 2.4 Ctx switches (vol / inv)

Voluntary = thread gave up the slice waiting on a mutex /
condvar / sleep — high count means sync-bound.
Involuntary = preempted by the scheduler — high count means
CPU-saturated. The pair distinguishes the two failure modes a
flat-looking throughput number can hide. A row with `vol:0 /
inv:0` is running idle; a row with `vol:1000 / inv:0` is
hammering a mutex; `vol:50 / inv:5000` is CPU-bound.

### 2.5 Handshake cost

Connection setup latency for the four transports with a
fresh-listener fixture (TCP / TLS / QUIC / DTLS) plus the
openssl `s_client` baseline. Operators serving connection-
churn workloads (short-lived RPC, mobile reconnect storms)
weight this over steady-state throughput.

Sorted ascending by P50 in the report so the cheapest setup
is at the top.

---

## 3. What the report is NOT trying to say

- "GoodNet is faster than libp2p" — not unless you compare
  same-shape rows. Parody vs libp2p is unfair to libp2p; real
  vs libp2p is the honest comparison.
- "GoodNet beats iperf3" — never the goal. iperf3 is the
  upper-bound ceiling for raw TCP / UDP throughput on the box;
  parody reaches it ⇒ link plugin is fine.
- "Production GoodNet is N% faster" — that depends on the
  axis. Throughput at 64 B and at 64 KiB measure different
  things. The TL;DR locks the comparison to 1 KB; other
  payloads are in the per-plugin matrices below.
- "Memory cost per connection is X KiB" — the bench bodies
  open ~1-10 conns (or a single conn) and report RSS Δ.
  Per-conn extrapolation requires `bench_tcp_scale` which
  iterates conn counts and the aggregator's not yet rendering
  that as a curve (followup).

---

## 4. Running the bench

```bash
nix develop --command bash -c "
  cmake -B build -DGOODNET_BUILD_BENCH=ON &&
  cmake --build build -j8
"

bench/comparison/runners/run_all.sh
# → bench/reports/<sha>.md
```

The runner orchestrates every `bench_<plugin>` binary + the
external baselines (iperf3 / socat / openssl s_client /
rust-libp2p / iroh) and feeds the JSON into the aggregator.
The 1 KB row of every stack lands in the TL;DR; the rest
spreads across the report sections.

---

## 5. Cross-references

- The bench harness: [`bench/bench_harness.hpp`](../../bench/bench_harness.hpp)
- The aggregator: [`bench/comparison/reports/aggregate.py`](../../bench/comparison/reports/aggregate.py)
- Stack analysis (long-form numbers + commentary):
  [`docs/perf/analysis.md`](analysis.en.md)
- Throughput baselines methodology (cross-impl runner shells):
  [`bench/comparison/README.md`](../../bench/comparison/README.md)
