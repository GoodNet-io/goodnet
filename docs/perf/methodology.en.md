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

Case names starting with the `RealFixture` prefix carry this
shape. Two sibling fixture families:

* `RealFixture<Plug>` (`RealFixtureTcp`, `RealFixtureUdp`,
  `RealFixtureIpc`) — **one-way** send→receive measurement.
  Case shape `RealFixture<Plug>/<Plug>Echo/<sz>/`. Useful as
  the cost-decomposition baseline against parody.
* `RealFixture<Plug>Echo` (`RealFixtureTcpEcho`,
  `RealFixtureUdpEcho`, `RealFixtureIpcEcho`) — **echo
  round-trip** measurement; alice echoes bob's payload back so
  bob measures wall-clock RTT. Case shape
  `RealFixture<Plug>Echo/<Plug>EchoRoundtrip/<sz>/`. This is the
  shape that lines up with libp2p / iroh runners (read → write
  → read), reported in `## А. Comparable echo round-trip`.

### 1.3 Comparable stacks — pairing rule

Section `## А. Comparable echo round-trip` is the **only** part
of the report that quotes GoodNet next to libp2p / iroh. Same
stack shape per row: transport + AEAD + framing/mux.

| GoodNet column | Reference column | Same shape because |
|---|---|---|
| `RealFixtureTcpEcho` (TCP + Noise XX + gnet) | `libp2p-echo` (TCP + Noise XX + Yamux) | both pay TCP + Noise AEAD + frame mux per send |
| `RealFixtureQuicEcho` (QUIC + TLS 1.3 + gnet) [pending] | `iroh-echo` (QUIC + TLS 1.3 + streams) | both pay QUIC + TLS 1.3 record + per-stream framing |
| `RealFixtureIpcEcho` (AF_UNIX + Noise + gnet) | (no upstream peer) | included for the IPC lower-bound baseline; not a fair-comparison row |

`yamux ≠ gnet` but both are application-layer mux/framing
layers running on top of a Noise-encrypted stream — same
per-frame bookkeeping cost class, so the pairing is honest.

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

### 2.6 Send vs recv asymmetry

Real-mode rows report a single throughput number per row but
the underlying send path and recv path are NOT structurally
symmetric, and the number lands closer to whichever side is
the bottleneck. The asymmetry is a property of the current
data-plane layout, not a measurement artefact.

**Send path** fans out:
```
host_api->send →
   protocol layer framing →
   per-conn send queue →
   CryptoWorkerPool::run_batch — encrypt jobs across N workers →
   coalesced wire bytes →
   link plugin write
```
`InlineCrypto::reserve_send_nonces(k)` pre-allocates `k` nonces
so workers can encrypt independently; the AEAD seal cost
parallelises across the pool's worker count
(`core/crypto/crypto_worker_pool.cpp`).

**Recv path** mirrors the send-side fan-out:
```
link plugin notify_inbound_bytes →
   SecuritySession::decrypt_batch_transport_stream — splits
       inbound frames across CryptoWorkerPool workers →
   protocol layer deframe →
   HandlerRegistry dispatch
```
`InlineCrypto::reserve_recv_nonces(k)` pre-allocates `k`
nonces so workers can decrypt independently; the AEAD open
cost parallelises across the pool's worker count
(`core/crypto/crypto_worker_pool.cpp`). A `batch-of-one`
fast path in `decrypt_batch_transport_stream` falls through
to the scalar `InlineCrypto::decrypt` so a single inbound
frame does not pay the latch / cv handshake.

The send and recv paths share the `CryptoWorkerPool`
instance, so a recv batch and a send batch in flight at the
same time both pull workers from the same pool. The visible
shape in bench rows:

- `<Plug>EchoRoundtrip` (full RTT — both directions, both
  peers encrypt+decrypt) reflects steady-state symmetric
  load on the pool.
- `<Plug>Echo` one-way send→receive splits work across
  encrypt jobs on the sender side and decrypt jobs on the
  receiver side; same pool layout on both ends.
- Same payload, both peers identically configured: the
  reported number is dominated by whichever pool side has
  fewer workers idle when the bench window samples.

`bench_real_e2e.cpp` measures both sides through one fixture;
a recv-only row that feeds a pre-recorded ciphertext stream
into `notify_inbound_bytes` and isolates the decrypt half is
the shape needed to surface recv-only as its own number.

---

## 3. What the report is NOT trying to say

- "GoodNet is faster than libp2p" — not unless the rows live
  in `## А. Comparable echo round-trip`. That section is the
  only place where stack shape is matched (transport + AEAD +
  framing/mux), per §1.3 pairing rule. Quoting numbers from
  `## Cross-implementation throughput` (iperf3 / socat) or
  `## Parody — GoodNet plugin matrix` next to libp2p / iroh
  is a methodology error.
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
  iterates conn counts; the aggregator does not yet render that
  as a curve.

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

### 4.1 Environmental controls — mandatory before bench

Bench rows from a `powersave` / `schedutil` governor are NOT
valid for cross-commit comparison. The CPU scales its frequency
under load against the OS schedule, which means a 64-byte
throughput row's "ns per send" depends on what the rest of the
machine was doing during the bench window. Production-grade
numbers require:

```bash
sudo cpupower frequency-set -g performance
# Confirm: cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
# → performance
```

Other levers, in roughly decreasing impact order:

- **Turbo / boost**: leave ENABLED for realistic numbers
  (production servers run with boost on). DISABLE if you need
  reproducibility across batches — `echo 1 | sudo tee
  /sys/devices/system/cpu/intel_pstate/no_turbo` (or
  `echo 0 > /sys/devices/system/cpu/cpufreq/boost` on AMD).
- **SMT / hyperthreading**: noise sink. Disable for tail-latency
  benches; leave on for throughput benches (matches production).
- **ASLR**: leave at `2` (the kernel default). Reproducibility
  across runs comes from the bench using statistical aggregation
  over many iterations, not from process-layout determinism.
- **Background load**: kill `firefox`, `cargo build`, etc.
  before the bench. `loadavg < 0.5` is the sanity check.

The aggregator reads `/sys/devices/system/cpu/cpu0/cpufreq/
scaling_governor` and emits the result in the report's
`## Environment` header. A row scanning `schedutil` should be
treated as advisory only, not a regression-gate input.

### 4.2 Statistical confidence — repetitions + aggregate

Single-iteration bench rows are nit-pickable: a 5% delta vs
baseline could be real or could be that one warm-up iteration
hit a cold L2 line. The runner addresses this by:

1. Each `bench_<plugin>` binary runs with
   `--benchmark_min_time=0.3s` — google-benchmark auto-scales
   iteration count to fill the window, so the per-iteration
   number is the average over hundreds of thousands of calls
   even on the cheapest fixtures.
2. The aggregator drops gbench's `_mean / _median / _stddev /
   _cv` aggregate rows (suffix-based skip in `parse_gbench`) to
   avoid double-counting; the iteration row already carries the
   convergence-checked number.
3. The `Δ vs baseline` column in the parody / real tables (when
   `--baseline=<path-to-prev-report.md>` is supplied) flags any
   row that drifted >15% in latency or >10% in throughput
   against the prior bench report. A `[REGRESSION]` marker
   appears inline so the row is visible without an external
   diff tool.

For tighter convergence (`bench-CI`-style gates, not the
day-to-day `run_all.sh` flow), invoke each binary directly
with `--benchmark_repetitions=5
--benchmark_report_aggregates_only=true` so each row reports
`{mean, median, stddev}`. The aggregator does NOT currently
render the stddev column; the convention is to feed both the
baseline and the candidate JSON to `tools/bench_compare.py`,
which exits non-zero on >5% regression. Hooks into the
release process live in `bench/CHANGELOG.md`.

### 4.3 Honest fixture failures

A row that hit `SkipWithError("inbound timeout")` is not the
same as a row that ran to completion — collapsing both into
`—` lies. The aggregator surfaces the SkipWithError message in
a `Status` column on every perf-table row:

- `ok` — the fixture ran the loop body and reported a number.
- `SKIP: <reason>` — the bench fixture caught a failure and
  stopped (loopback setup race, handshake timeout, send
  rejection). The cause is visible inline; nothing for the
  reader to dig out of the JSON.
- `no data` — google-benchmark emitted a benchmark row but it
  carried neither time nor throughput. Should be rare — usually
  a sign that the fixture's `SetIterationTime` (manual-time
  benches) never fired before the loop exited.

Crashing fixtures (e.g. `bench_udp` hits glibc
`malloc.c:2610` with a heap-arena assertion in current `HEAD`)
fail outside the benchmark loop, so no row reaches the
aggregator. The runner reports those by their absence; the
report's `## Known crashes` section, when present, lists them
with the diagnostic the operator should reproduce locally.

### 4.4 Latency-tail interpretation

The `## Latency tail` section ladders P50 → P95 → P99 → P99.9
→ P99.99. The two ends of the ladder answer different questions
and the per-fixture interpretation differs:

| Fixture | Tail-sensitive? | Why |
|---|---|---|
| `TcpFixture/LatencyRoundtrip` | yes | round-trip RTT is the operator-visible latency; P99.9 is what the slowest 0.1% of RPCs paid |
| `TcpFixture/Throughput` | no | throughput is steady-state; tail is the noise floor of the loopback socket buffer |
| `IpcFixture/Throughput` | no | same |
| `WsFixture/EchoRoundtrip` | yes | echo round-trip carries an extra strand-hop; tail surfaces strand jitter |
| `*Fixture/HandshakeTime` | no (sample size too small) | handshake fixtures run one-shot; P99.9 collapses to the same number as P50 by linear interpolation |
| `IceFixture/NominationMetricsLookup` | yes | strategy plugins poll this on the hot path; tail = lock contention |
| `SubprocessLinkFixture/HostCallRoundtrip` | yes | wire-proxy round trip carries scheduler hops; tail surfaces scheduler-class jitter |

P99.99 (1-in-10k sample) is meaningful only when `lat_samples`
column reads ≥ 10 000. Below that count, linear interpolation
between the last two recorded samples collapses P99.99 onto
P99.9; reporting P99.99 with N=200 is mathematically the same as
P99.9 (the interpolation reaches into the same neighbouring
points) and operators should read the two columns as equal.
The aggregator emits both columns regardless so the reader
can verify the convergence from the `Samples` column.

A widening P99.9 / P99 ratio across rows is the long-tail
signal: row whose P99 is 10× the median has a fundamentally
different behaviour than one whose P99 is 1.2× the median.
P99.9 / P99 amplifies this — a row reading `P99: 20μs, P99.9:
50μs` (ratio 2.5×) has GC / strand-hop / allocator-slow-path
pauses; a row reading `20μs / 25μs` (ratio 1.25×) is uniformly
fast. Operators picking a stack for latency-sensitive RPC
weight P99.9 over throughput.

### 4.5 Expected-range table per host class

The bench's absolute numbers depend on the host class. A row
reading "WAN GoodNet TCP @ 1024B = 1.68 GiB/s" is a SIGNAL
mismatch — production WAN deployments cannot reach that. The
table below documents the bench's expected ranges so an
operator can tell whether their environment matches the
methodology's assumptions:

| Metric @ 1024 B payload | Loopback dev box | 1 GbE LAN | Typical WAN | Mobile cellular |
|---|---|---|---|---|
| TCP parody throughput | 1.5-2.5 GiB/s | 110-118 MiB/s | 5-30 MiB/s | 1-5 MiB/s |
| TCP real-mode throughput | 200-400 MiB/s | 80-100 MiB/s | 5-25 MiB/s | 1-3 MiB/s |
| UDP echo RTT (P50) | 30-80 μs | 200-500 μs | 20-80 ms | 50-200 ms |
| ICE establishment (P50) | <50 ms | 100-500 ms | 1-3 s | 2-10 s |
| Noise XX handshake | 250-500 μs | 1-2 ms | 30-100 ms | 100-300 ms |

The bench harness assumes loopback; `bench/comparison/runners/`
emits a `Note` row in the report when the runner detects a
non-loopback test. Numbers outside these ranges by >2× are
likely an environmental misconfiguration (governor on
schedutil, NUMA-cross traffic, antivirus scan) rather than a
kernel regression. Bisecting a kernel-level regression on a
box matching its host class's expected range is straightforward;
bisecting on a misconfigured box wastes everyone's time.

### 4.6 Sanitizer-build bench expectations

ASan + TSan instrumentation imposes a per-instruction tax. A
sanitizer-build bench is a correctness gate, NOT a perf gate.
The methodology forbids comparing sanitizer numbers to vanilla
baseline.

Expected slowdown per sanitizer:

| Sanitizer | Throughput | Latency | Why |
|---|---|---|---|
| ASan | 2-4× slower | 2-5× higher | shadow-memory load on every heap access |
| TSan | 5-15× slower | 5-15× higher | happens-before tracking per memory op |
| UBSan | 1.1-1.3× slower | similar | mostly cheap integer-overflow / shift-bounds checks |
| MSan | 3-5× slower | similar | uninitialised-memory shadow propagation |

The aggregator does not currently tag rows with their sanitizer
build (the bench JSON output does not carry it). Convention:
sanitizer-build report files go in
`bench/reports/sanitizer/<sha>-<sanitizer>.md` rather than the
top-level `bench/reports/<sha>.md` so the baseline-delta column
NEVER auto-pairs a sanitizer row against a vanilla one. A
sanitizer-build that crashed where vanilla didn't IS a real
signal; sanitizer-build "+250% latency vs vanilla" is just the
instrumentation tax.

### 4.7 Multi-run statistical significance

A single bench run is unreliable for regression detection. The
day-to-day `run_all.sh` flow is for fast iteration; a
release-gate signal requires a stronger statistical argument:

  * Per-row Δ flagged at >15% latency / >10% throughput is the
    `aggregate.py --baseline=` default. A single noisy run can
    cross this threshold without being a real regression.
  * **Three consecutive runs showing the same delta** is the
    operational "is this a regression" signal. The Δ-vs-baseline
    column persists across `bench/reports/<sha>.md` files; if
    three consecutive commits show the same row flag, the
    regression is real.
  * **Welch's two-sample t-test** is the release-gate gate.
    `tools/bench_multipass.py --passes=N --baseline=<ref>.json`
    runs the binary N times, computes the t-statistic + p-value
    against the baseline, and exits non-zero when both p < 0.05
    AND |Δ| > 5% hold. Suitable for a CI release gate; the
    n-fold cost is N× longer bench wall time but the gate
    answers a question single-run benches cannot.
  * **Median + IQR** is the noise-floor signal. A row whose IQR
    is wider than the mean delta is inherently noisy
    (ICE `NominationMetricsLookup` is a representative example —
    the lock-acquire jitter is the IQR-wide signal, not a
    regression). The multipass tool surfaces median and IQR
    columns so the reader can rule out IQR-wide rows.

### 4.8 Shape-mismatch explicit forbid

A row claiming "GoodNet TCP is 2.03 GiB/s" without saying the
shape is meaningless. The bench runs two shapes — parody and
real — and the aggregator enforces the separation by raising
`ModeMismatchError` when a pivot table mixes the two. The
methodology states it explicitly:

  * Reporting `GoodNet parody 2 GiB/s` next to `libp2p 200 MiB/s`
    on the same axis is **lying with statistics**. The shapes
    pay different costs — parody is a raw socket, libp2p carries
    Noise + Yamux. A reader compares the numbers as if they
    answered the same question; they do not.
  * The aggregator's `ModeMismatchError` is the enforcement
    mechanism. A future runner that emits an untagged metric
    (`stack: "GoodNet"` without `mode`) lands in the
    `_classify_metric_mode` fallback; an unclassifiable metric
    keeps the row out of the pivot table rather than letting
    it land somewhere wrong.
  * The methodology lives at the top of this document
    (§1.1-1.3). The shape distinction belongs in the rationale
    of every chart that touches GoodNet numbers — the report
    layout, the slide deck, the README, every screenshot of a
    bench row.

The single-section rule:

> Within ONE pivot column, the shapes match. Across columns,
> the document calls out the shape via prose. NEVER mix
> shapes silently.

### 4.9 Ratchet workflow

`bench/baselines/` holds CI-pinned baseline JSONs. The ratchet
question is "when does the baseline move forward?" Two cases:

**When to ratchet (move baseline to current numbers):**

  * A legitimate perf improvement landed.
  * **AND** three consecutive runs show the same improvement
    (filters out a single noisy run that happened to be
    fast).
  * **AND** Welch p < 0.05 against the previous baseline
    (`tools/bench_multipass.py --baseline=<prev>.json`).
  * **AND** sign-off from the perf reviewer.

**When NOT to ratchet:**

  * A single fast run.
  * A run on a different host class (the baseline lives in a
    host-class-specific directory; cross-class moves are
    NEVER auto-ratcheted).
  * A run with non-default environment knobs (`schedutil`
    governor, ASLR off, debug build).
  * Sanitizer-build numbers are NEVER ratcheted against
    vanilla baselines.

**Bisecting a regression to a commit:**

  1. `git bisect start <bad-sha> <good-sha>`
  2. Per bisect step: `nix develop --command bash -c 'cd
     build-release && ninja bench_<plugin>'`
  3. Run the candidate against the baseline:
     `python3 tools/bench_compare.py
     bench/baselines/<host>/<plugin>.json
     build-release/bench/bench_<plugin>_json`
  4. `git bisect good` / `git bisect bad` on the exit code.
  5. The `git bisect run` driver script lives in
     `tools/bench_bisect.sh` (planned).

A bisect spanning >100 commits is the wrong direction; the
right shape is to narrow to <20 commits first using the
`bench/reports/` directory (every commit that ran the bench
left a report; binary-search them for the first regression).

### 4.10 Common anti-patterns observed in audit reports

Stale or mis-read bench rows surface the same handful of mistakes
across audits. Each row in this section is a concrete artefact
that has appeared in a real `bench/reports/<sha>.md` file — kept
here so future operators read a row in context instead of quoting
the literal number.

**1. TCP loopback handshake reading 5.1 ms (poll-tick artefact).**
The `gn::sdk::test::wait_for` helper polls a predicate with a 5 ms
sleep between evaluations. A latency-critical fixture like
`TcpFixture/HandshakeTime` or `TcpFixture/LatencyRoundtrip` whose
true wait is sub-millisecond reads `5.1 ms` because the first poll
fires after the 5 ms tick — the number is the poll resolution, NOT
the round-trip time. Sibling helper `wait_for_fast` yields between
evaluations and resolves at the OS scheduler quantum (~1-50 μs).
Verify before quoting any handshake row under ~10 ms: the fixture
should use `wait_for_fast`, not `wait_for`. Every
`TcpFixture/HandshakeTime` row in reports prior to 9700a9c quotes
the 5.1 ms artefact.

**2. RTT-dominated small-payload reading (UDP/WS EchoRoundtrip
@ 64 B).** A round-trip echo row at 64 B looks slow relative to the
8 KiB row — `UdpFixture/EchoRoundtrip/64` at ~25 MiB/s vs
`UdpFixture/EchoRoundtrip/8192` at ~1.2 GiB/s. The bottleneck on
small payloads is the round-trip wall time, not the per-byte cost:
1 RTT × small-payload = throughput is dominated by RTT. A row
reading "WS echo 25 MiB/s @ 64 B" is NOT a WS throughput limit —
it is the RTT cost amortised over 64 bytes. Compare the latency
column (P50 RTT), not the throughput column, when reasoning about
small-payload echo behaviour. The `## Latency tail` section is
where the small-payload signal lives.

**3. `—` cell vs. structural zero (broken fixture vs. real zero).**
The aggregator renders `—` when a fixture produced no value (parse
failure, fixture crash, manual-time row without throughput) and
`0` when the fixture ran but the metric is structurally zero
(steady-state `RSS Δ` after warmup, ctx switches on a CPU-bound
loop, etc.). `—` is NOT zero — it is missing data. A row whose
throughput column reads `—` while sibling rows at neighbouring
payloads carry valid numbers indicates a fixture bug or a missing
runner, NOT that the plugin has zero throughput at that payload.
The `## Known crashes` section names the binaries whose `—` rows
came from crashes; everything else is fixture-level.

**4. Sanitizer-build numbers compared to vanilla baseline.**
A `bench/reports/sanitizer/<sha>-asan.md` row at "+250% latency
vs vanilla baseline" is the instrumentation tax (see §4.6), NOT a
regression. The aggregator's `--baseline=` flag does not currently
tag rows with their sanitizer build, so the operator is responsible
for never pointing a sanitizer report at a vanilla baseline (and
vice versa). A sanitizer-build that crashed where vanilla did not
IS a real signal — runtime correctness gates trip even when
absolute numbers do not.

**5. Single-run regression detection.**
A row that crossed the 15% latency / 10% throughput Δ threshold in
ONE report is the start of an investigation, not the conclusion of
one. The `bench/reports/<sha>.md` regression flag exists for fast
iteration; release-grade signals require three consecutive runs
showing the same direction (§4.7) and/or a Welch t-test under
`tools/bench_multipass.py`. A single 17% latency Δ from a sample
size of 50 iterations can be pure environmental noise — schedutil
governor, antivirus scan, kernel TLB flush from a neighbour
process. Acting on a single-run flag risks bisecting noise.

**6. Mixing parody and real-mode rows in one mental comparison.**
`UdpFixture/Throughput/1200 @ 1.57 GiB/s` (parody — raw transport,
no security, no protocol) and `libp2p-echo @ 1024 B` (real — Noise
XX + Yamux + libp2p-stream) on the same axis is the apples-to-
oranges shape §4.8 forbids. The shapes pay different per-byte
costs. Parody rows pair against `iperf3` / `socat`; real rows pair
against `libp2p` / `iroh`. The aggregator raises
`ModeMismatchError` on a pivot that mixes shapes — the manual
discipline is to never quote two shapes side-by-side in prose
either.

---

## 5. Cross-references

- The bench harness: [`bench/bench_harness.hpp`](../../bench/bench_harness.hpp)
- The aggregator: [`bench/comparison/reports/aggregate.py`](../../bench/comparison/reports/aggregate.py)
- Stack analysis (long-form numbers + commentary):
  [`docs/perf/analysis.en.md`](analysis.en.md)
- Throughput baselines methodology (cross-impl runner shells):
  [`bench/comparison/README.md`](../../bench/comparison/README.md)
