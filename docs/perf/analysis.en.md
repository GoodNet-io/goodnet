# GoodNet stack analysis — measurements vs analogs

Status: living document. Numbers come from `bench/reports/`,
methodology from `bench/README.md`.

This article exists so any reader — operator, plugin author,
funder, downstream integrator — gets a concrete answer to three
questions:

  1. **How fast is each layer of GoodNet?** Per-plugin, per-axis,
     with the matching resource footprint (CPU, memory, page
     faults, context switches) so the number is attributable, not
     just stated.
  2. **How does it compare to mature analogs?** iperf3 for raw
     TCP/UDP, OpenSSL `s_client` for TLS handshake, libuv echo,
     libssh examples — the same workload through each.
  3. **What does the composition cost?** Stack depth (TCP →
     TLS → WS → WSS = depth 3) and per-layer overhead
     contribution.

Every number below is reproducible — see [§ How to reproduce](#how-to-reproduce).

## Reference hardware

i5-1235U laptop, 12 logical CPUs at 4.4 GHz, 32 GiB RAM, NixOS
26.05 kernel. CPU frequency scaling enabled — bench reports flag
this in the header. **All numbers are loopback** unless explicitly
labelled inter-host. A real 10 Gbps NIC shifts the comparison;
this document does not yet pretend to have those numbers.

### Build configuration

**Bench binaries are built in Release mode** (`-DCMAKE_BUILD_TYPE=Release`).
The default `nix run .#build` produces Debug — the test suite uses
that flavour to keep the inner loop fast on iteration. Debug runs
through the same syscalls so throughput benches (syscall-bound,
not compute-bound) come within ±5 % of Release; crypto-heavy
benches (Noise handshake / AEAD) slow by 5–10 % in Debug. The
[reproduce](#how-to-reproduce) section below builds Release
explicitly so the numbers are comparable against `iperf3` (Release)
and other published baselines.

### Run-to-run variability

CPU frequency scaling + ambient system load mean a single bench
run swings ±10–15 % on this hardware. The numbers below are taken
from the most recent aggregated report under `bench/reports/`; for
a release announcement we run the suite three times and quote the
median.

## Methodology

Eight measurement axes (full table in
[`bench/README.md`](../../bench/README.md)):

| Axis | What it varies |
|---|---|
| **Payload size** | 64 / 1024 / 8192 / 32768 bytes |
| **Connection count** | 1 / 10 / 100 / 1000 parallel conns |
| **Concurrency** | 1 / 2 / 4 / 8 worker threads |
| **Plugin** | TCP / UDP / IPC / TLS / WS / DTLS / QUIC / ICE |
| **Composition depth** | TLS/TCP (2), WSS/TLS/TCP (3), Noise/QUIC/UDP (3) |
| **Strategy** | min-RTT picker over N candidates |
| **Real-mode end-to-end** | kernel + Noise XX + gnet through TCP / UDP / IPC; one-way `<Plug>Echo` + round-trip `<Plug>EchoRoundtrip` |
| **Free-kernel showcase** | multi-connect, strategy carrier pick, Noise→Null handoff PoC, multi-thread fanout, carrier failover, mobility LAN shortcut |

Plus a **topology** dimension (intra-process loopback /
inter-process xprocess / inter-host LAN) and a **cross-impl**
dimension that drives the same payload matrix through external
baselines. The cross-impl dimension is split into two report
tracks — see [§ Two report tracks](#two-report-tracks) below.

## Two report tracks

The aggregator emits two markdown documents per run, on purpose:

* **`bench/reports/<sha>.md`** — fair-comparison aggregate.
  Section `## А. Comparable echo round-trip — production stack vs
  libp2p / iroh` is the only place the report quotes GoodNet next
  to libp2p / iroh — both sides match in stack shape (transport +
  AEAD + framing/mux). Driven by `bench_real_e2e` (sibling
  fixtures `RealFixture<Plug>Echo/<Plug>EchoRoundtrip`) +
  `aggregate.py` + runners under `bench/comparison/`. See
  [`methodology.en.md`](methodology.en.md) §1.3 for the pairing
  rule.
* **`bench/reports/showcase-<sha>.md`** — free-kernel showcase.
  Six narrative sections, each demonstrating a capability where
  libp2p / WebRTC / gRPC have no architectural equivalent:
  multi-connect under one identity, strategy-driven carrier
  selection, post-handshake Noise→Null security provider
  migration (PoC), multi-thread fanout, carrier failover,
  mobility-driven LAN shortcut. NOT a fair-comparison surface.
  Driven by the `bench_showcase` binary +
  `showcase_aggregate.py`. See
  [`../../bench/showcase/README.md`](../../bench/showcase/README.md)
  for the per-section breakdown and the B.3 PoC disclaimer.

### Measurement shape: send-only vs echo vs handshake vs showcase

Each bench fixture is one of four shapes. Mixing them in a single
table — "GoodNet 1.6 GiB/s vs libp2p 250 MiB/s" — is the apples-
to-oranges trap this section exists to flag.

| Shape | Hot-loop body | Reads | Compares with |
|---|---|---|---|
| `Throughput` | `client.send(payload)` only | Send-side syscall + plugin overhead, no response | iperf3 raw send |
| `EchoRoundtrip` (parody) | `client.send → server.send_back → client.read` through `LinkStub` (no security, no protocol) | Plugin overhead both directions, no AEAD or framing | iperf3 round-trip, but NOT libp2p / iroh |
| `<Plug>EchoRoundtrip` (real) | same shape but through real kernel + Noise XX + gnet protocol on both peers | Full production-stack overhead both directions + 1 RTT | rust-libp2p, iroh, browser data-channel — **the libp2p-comparable shape** |
| `HandshakeTime` | Set up fresh connection, no traffic | Crypto + control-plane cost only | OpenSSL `s_client` handshake |
| `Showcase*` | One capability per fixture (multi-connect, strategy, handoff, fanout, failover, mobility) | Architectural feature reachability | nothing — these capabilities have no architectural analogue in libp2p / WebRTC / gRPC |

Rust P2P stacks expose echo + handshake; iperf3 exposes
send-only. GoodNet exposes all four (`Throughput`,
`<Plug>EchoRoundtrip`, `HandshakeTime`, and `Showcase*`). The
aggregator never crosses shapes in a single table — see
**`## А. Comparable echo round-trip`** for the round-trip
cross-impl matrix and `bench/reports/showcase-<sha>.md` for the
showcase narrative.

Resource counters surfaced per bench:

```
cpu_user_us / cpu_sys_us / cpu_total_us   # getrusage
rss_kb_delta                              # VmRSS  (current; madvise masks bursts)
rss_peak_kb_delta                         # VmHWM  (high-water-mark; catches bursts)
vsz_kb_delta / vsz_peak_kb_delta          # VmSize / VmPeak (virtual address space)
sock_mem_kb_delta                         # /proc/net/sockstat TCP+UDP+FRAG aggregate
minor_faults / major_faults               # allocator + disk-back
vol_ctx_sw / inv_ctx_sw                   # sync + preemption
block_io_in / block_io_out                # disk
```

Memory deltas come paired on purpose. `rss_kb_delta` is `VmRSS`
right at `snapshot_end` — an allocator that grew to 1 GiB and
then released pages via `madvise(MADV_DONTNEED)` reads 0 here.
`rss_peak_kb_delta` is `VmHWM`, the high-water-mark the kernel
accumulates across the window — that same bench reads
`+~1 GiB`. Compare the two columns to distinguish flat-real from
burst-and-released allocation. `sock_mem_kb_delta` captures
kernel TCP/UDP send-receive buffers that are NOT in `VmRSS` —
~2 MiB per socket × N sockets can be invisible in the process's
memory map. See
[`bench/README.md` §"Memory measurement caveats"](../../bench/README.md#memory-measurement-caveats)
for the four blind spots and which column disambiguates each.

## Results

Numbers below are illustrative — copy the actual values from the
latest `bench/reports/<sha>.md` for an operator-grade quote. The
shapes (which plugin maps to which column, which fixture lives in
which section) stay stable across runs even when absolute numbers
move with host class.

### Per-plugin throughput

| Plugin | @ 64B | @ 512–1200B | @ 8192B |
|---|---|---|---|
| TCP   | ~190 MiB/s | ~1.6 GiB/s (1024 B) | ~2.9 GiB/s |
| IPC   | ~160 MiB/s | ~1.3 GiB/s (1024 B) | ~2.5 GiB/s |
| UDP   | ~170 MiB/s | ~1.0 GiB/s (512 B) / ~1.6 GiB/s (1200 B PMTU) | error (MTU cap) |
| WS    | ~130 MiB/s | ~730 MiB/s | ~1.2 GiB/s |
| Noise transport (AEAD) | ~115 MiB/s | ~225 MiB/s | ~250 MiB/s |

Peak send-only on this host class is UDP at the 1200 B PMTU
ceiling, around 1.5 GiB/s ≈ 13 Gb/s. The VmHWM column in the
report row catches the allocator burst that `VmRSS` masks after
`madvise(MADV_DONTNEED)` returns pages.

### Handshake time

| Stack | Typical loopback median |
|---|---|
| `TcpFixture/HandshakeTime` (TCP listen + connect) | ~50–60 μs |
| Noise XX (3 messages, no socket) | ~240 μs |
| Noise IK (2 messages + pre-message hash) | ~320 μs |
| ICE `composer_connect` dispatch | ~75 ns |
| `TlsFixture/HandshakeTime` | ~3–4 ms |

IK appears slightly slower than XX on loopback because both share
4 DH operations but IK does 2 extra pre-message hashes. IK wins in
real networks where it saves one RTT — the loopback bench captures
crypto-only cost, not the round-trip differential.

The TCP handshake row reads tens of microseconds; earlier reports
quoted 5.1 ms there, which was a `wait_for` poll-tick artefact
(see [`methodology.en.md`](methodology.en.md) §4.10 anti-pattern
#1). The fixture switched to `wait_for_fast` and now resolves
sub-millisecond timings honestly.

### Cross-implementation throughput

Two flavours of "throughput", measured separately. **Don't mix them
in a single mental comparison** — that's the one mistake this section
exists to prevent.

**Send-only (one-way).** Application produces bytes as fast as the
transport accepts them; no acknowledgements at the application layer.
This is what `iperf3` and GoodNet `*Fixture/Throughput` measure.

| Stack | Metric | Throughput |
|---|---|---|
| **iperf3 raw TCP** | TCP single-stream | **7.81 GiB/s ≈ 67 Gb/s** |
| iperf3 raw UDP | UDP, capped via `-b 1000M` | 119 MiB/s |
| **GoodNet UDP @ 1200 B** | UDP composer | **1.57 GiB/s ≈ 13.5 Gb/s** |
| GoodNet WS @ 8192 B | WS-over-TCP | 1.23 GiB/s ≈ 10.6 Gb/s |

iperf3 is **kernel TCP in a tight loop, no plugin overhead**. The
gap to GoodNet UDP (≈ 5×) is the composition + asio-strand +
allocator budget — see § "Where the cost goes" below.

**Round-trip echo (two-way).** Client sends, server reflects, client
waits for the echo, repeat. Includes plugin-stack overhead in **both**
directions plus one full RTT per byte returned. This is what the
mature Rust P2P stacks (libp2p, iroh) measure, and what GoodNet
**`RealFixture<Plug>Echo/<Plug>EchoRoundtrip`** measures for fair
compare — kernel + Noise XX + gnet protocol on both peers. Pre-track-
А `*Fixture/EchoRoundtrip` parody rows still exist in the report but
must NOT be quoted next to libp2p / iroh — see
[`methodology.en.md`](methodology.en.md) §1.3 (pairing rule).

| Stack | Fixture | Stack shape |
|---|---|---|
| **GoodNet TCP+Noise+gnet** | `RealFixtureTcpEcho/TcpEchoRoundtrip` | TCP + Noise XX + gnet protocol on both peers |
| GoodNet IPC+Noise+gnet | `RealFixtureIpcEcho/IpcEchoRoundtrip` | AF_UNIX + Noise XX + gnet — IPC trails TCP on AF_UNIX strand layout cost |
| GoodNet UDP+Noise+gnet | `RealFixtureUdpEcho/UdpEchoRoundtrip` | UDP + Noise XX + gnet — capped by PMTU on the upper payloads |
| rust-libp2p (`libp2p_rs.sh` runner) | TCP + Noise XX + Yamux + libp2p-stream | comparable column for TCP+Noise rows |
| iroh (`iroh.sh` runner) | QUIC + TLS 1.3 | comparable column once `RealFixtureQuicEcho` lands (`QuicLink::listen/connect` returns `GN_ERR_NOT_IMPLEMENTED` at the time of writing) |

The aggregator renders the side-by-side pivot under
**`## А. Comparable echo round-trip — production stack vs libp2p /
iroh`** when `bench_real_e2e` ran in the same cycle as the
`libp2p_rs.sh` / `iroh.sh` runners; the section is omitted from
reports where one side is missing rather than fabricated. Release
builds run 5–10 % faster than Debug on crypto-heavy sections; the
canonical report quotes Release.

### Free-kernel showcase — capabilities no other stack has

The `bench_showcase` binary wraps six fixtures, each
demonstrating one capability that requires the kernel-driven
architecture. The report lives at `bench/reports/showcase-<sha>.md`
through `showcase_aggregate.py` — separate from the
fair-comparison aggregate above by design. Each section is
**not** a number to beat; it's an acceptance condition to verify.

| # | Section | What it demonstrates | Acceptance condition |
|---|---|---|---|
| B.1 | `MultiConnFixture/FallbackThroughput` | One peer pk holds three live conn records (TCP + UDP + IPC); registry returns all three on `for_each` | `alice.kernel->connections().size() == 3` |
| B.2 | `StrategyFixture/PickerSelectsIpc` + `FlipOnRttDegradation` | `goodnet_float_send_rtt` strategy plugin selects the lowest-RTT carrier per send; EWMA-α=1/8 hysteresis at 0.75× threshold prevents thrash | `picks_ipc > picks_other` under preset RTT; flip lands within 1–2 samples after EWMA crosses |
| B.3 | `HandoffFixture/NoiseSteady` + `TriggerStep` + `NullSteady` | Post-handshake Noise→Null security provider migration: identity-binding survives Noise handshake, per-frame AEAD drops off on a kernel-driven trigger | T0 (Noise inline) p50 ~20 μs → T2 (post-handoff) p50 ~12 μs; zero decryption errors across the trigger. PoC reaches through compile-gated `_test_clear_inline_crypto` (`GOODNET_BENCH_SHOWCASE`) — production-shape `SessionRegistry::downgrade_*` API not yet wired |
| B.4 | `FanoutFixture/Producers` | N producer threads spam `api.send_to(peer_pk)` in parallel; kernel strand-per-conn + crypto worker pool absorb the load | Throughput grows monotonically with N until single-writer drain CAS plateaus (single-carrier knee ≈ N=2) |
| B.5 | `FailoverFixture/IpcDrop` | Picker drives between three carriers; `CONN_DOWN` injected mid-bench evicts the winner; next pick re-routes to the next-best RTT | Flip lands within ≤ 5 iters of drop; zero packet loss. Kernel auto-emit from `notify_disconnect` is wired (`core/kernel/host_api/notifications.cpp`); the bench injects `CONN_DOWN` for deterministic timing |
| B.6 | `MobilityFixture/LanShortcut` | Synthetic LAN host candidate appears mid-bench (RTT 2 μs vs TURN-relayed 60 μs); picker flips; peer identity preserved; `turn_bytes` delta after flip = 0 | Flip within ≤ 5 iters of LAN appearance; identity unchanged. Production auto-emit goes through `plugins/links/ice/interface_watcher` re-gather on `RTM_NEWLINK`/`RTM_DELLINK`; the bench injects directly for deterministic timing |

Time-series cases (B.2 flip, B.3 trigger, B.5 failover, B.6
mobility) emit CSV side-channels to
`/tmp/showcase-<tag>-<pid>.csv` that the aggregator renders as
inline ASCII sparklines (`▁▂▃▄▅▆▇█`) in the report.

The showcase exists to make these architectural moves
**observable**, not asserted. Each acceptance row is a single
boolean derived from counters in the JSON output — pass / fail,
not aggregated latency. The full read happens in
[`bench/showcase/README.md`](../../bench/showcase/README.md),
including the B.3 PoC disclaimer (`GOODNET_BENCH_SHOWCASE`
compile-time gate + unit test
[`tests/unit/security/test_inline_downgrade_gate.cpp`](../../tests/unit/security/test_inline_downgrade_gate.cpp)
that pins the in-bench phase-guard contract).

### DX LOC — hello-world echo

| Stack | Client + Server LOC | Ratio vs GoodNet |
|---|---|---|
| **GoodNet** | **43** (24 + 19) | 1 × |
| iroh (single-file echo) | 71 | 1.7 × |
| rust-libp2p (single-file echo) | 107 | 2.5 × |
| libuv (raw TCP echo) | 121 (50 + 71) | 2.8 × |
| OpenSSL `sslecho` (TLS) | 648 (single TU, both halves) | 15 × |
| libssh examples | 658 (server side; client demo absent) | 15 × |

Numbers are raw source lines with comments + blank lines stripped.
GoodNet and the C stacks count from each upstream's canonical
"hello echo" example (committed as symlinks in
`~/.cache/goodnet-bench-refs/`). The Rust P2P numbers count the
in-tree echo benches at `bench/comparison/p2p/{libp2p,iroh}-echo/
src/main.rs` — full round-trip echo, same shape as
[`examples/hello-echo/`](../../examples/hello-echo/). Upstream
rust-libp2p doesn't ship a canonical echo example (the closest is
`examples/ping/`, ~34 LOC — but it's not an echo).

### Deployment weight — binary + dependency closure

The bench harness sizes every stack on the same axes (`Binary` on
disk + `Lib closure` from `ldd`), so a reader can compare "what an
operator copies onto a fresh host" side-by-side with the throughput
/ latency rows.

| Stack | Binary | Lib closure | **Total** |
|---|---|---|---|
| **GoodNet static** (single binary, 11 plugins linked in) | 1.36 MiB | — | **1.36 MiB** |
| **GoodNet dynamic** (kernel + 11 plugin `.so`) | 759 KiB | 3.08 MiB | **3.82 MiB** |
| rust-libp2p 0.55 (`libp2p-echo`) | 4.69 MiB | 3.60 MiB | **8.29 MiB** |
| iperf3 | 16 KiB | 12.16 MiB | **12.17 MiB** |
| socat | 565 KiB | 11.13 MiB | **11.69 MiB** |
| openssl CLI | 1.25 MiB | 11.10 MiB | **12.35 MiB** |
| iroh 0.32 (`iroh-echo`) | 16.97 MiB | 3.60 MiB | **20.58 MiB** |

Two observations the table makes load-bearing:

1. **GoodNet static is the smallest single-binary networking
   stack in the comparison set.** 1.36 MiB carries the kernel
   plus every bundled plugin's `.text` — TCP, UDP, TLS, WS,
   ICE, QUIC, IPC, Noise, heartbeat, float-send-rtt, null
   security — in one shippable artefact. The next-closest
   single-binary is rust-libp2p at 8.29 MiB (one transport +
   one security layer only).
2. **Dynamic shipping vs. static breakdown** mirrors how the
   plugin model trades flexibility for footprint. Dynamic
   builds let an operator drop plugins they don't use (a TCP-
   only deployment ships kernel + `libgoodnet_link_tcp.so` =
   ~1.3 MiB); static builds give the embedded operator a
   single-binary deploy where nothing can be selectively
   omitted.

The same report row tracks the Nix dependency closure (around
100 MiB worst case before store de-duplication) and a
`debian:bookworm-slim`-based Docker image (~70 MiB; a musl /
scratch base would drop to ~5 MiB but needs a separate musl plugin
port). Latest absolute numbers live in
`bench/reports/<sha>.md` § "Binary sizes & deployment closure".

### Memory burst vs. released (VmHWM column)

The harness reads `VmHWM` (peak RSS) alongside `VmRSS` (current)
on every bench. Two patterns the side-by-side makes visible:

| Bench | `RSS Δ` (current) | `RSS Peak Δ` (VmHWM) | Reading |
|---|---|---|---|
| UDP/Throughput/1200 B | +1320 MiB | +691 MiB | bench peaked at +691 MiB, then allocator returned ~630 MiB via `madvise(MADV_DONTNEED)` — but current RSS still shows +1320 MiB at `snapshot_end` because retention happened on a different thread |
| WS/Throughput/8192 B | +590 MiB | +237 MiB | similar: ~350 MiB released |
| WS/EchoRoundtrip/65536 B | +81 MiB | +13 MiB | allocator was very active: ~68 MiB returned of an 81 MiB current |
| UDP/EchoRoundtrip/* | +28–36 KiB | 0 | flat-real: tiny per-call growth, no burst |
| TCP/Backpressure/8 producers | +3.8 GiB | +3.8 GiB | runaway queue: no `pending_queue_bytes_hard` configured in the BenchKernel stub, so the queue grew unbounded — a real kernel with limits set would plateau |

The backpressure fixture is intentional — it proves the queue
depth is the alarming variable a steady-state echo bench hides.
With a real kernel `limits()` table wired, the same fixture
would show `back_pressure_hits > 0` and a bounded `RSS Peak Δ`.

### Kernel socket buffers (sock_mem column)

`sock_mem_kb_delta` reads aggregate TCP + UDP + FRAG memory
from `/proc/net/sockstat` — kernel-side buffers that don't show
up in any `VmRSS`-derived counter. Loopback benches usually
register tiny deltas (`+22 MiB` in the backpressure stress is
the largest single-bench delta in this run); inter-host or
N-thousand-connection workloads make this number dominant. The
column is the system-wide signal; per-process attribution
needs `ss -tm` or `/proc/<pid>/net/sockstat` and is left to
operator tooling.

## Where the cost goes

Resource counters from `UdpLink @ 1200B, 1.29 GiB/s`:

| Counter | Value | Reading |
|---|---|---|
| `cpu_total_us / wall_us` | ≈ 1.5 × | asio worker thread active in parallel with bench loop |
| `minor_faults` | 172 k on 533 k sends | ≈ 3 fresh pages per `send` — allocator churn |
| `vol_ctx_sw` | 176 k | ≈ 1 voluntary context switch per `send` — asio strand hop |
| `rss_kb_delta` | ≈ 670 MiB | heap growth not reclaimed in the bench window |
| `major_faults / block_io` | 0 / 0 | pure memory path, no disk |

Same row for Noise transport AEAD @ 8 KiB:

| Counter | Value | Reading |
|---|---|---|
| `cpu_total_us / wall_us` | ≈ 1.0 × | single-thread, no async |
| `minor_faults` | 0 | vec reuse in steady state |
| `vol_ctx_sw / inv_ctx_sw` | 0 / 22 | stayed on CPU; 22 preemptions |
| `rss_kb_delta` | 0 | nothing escapes |

The asymmetry surfaces concrete optimisation targets — see next
section. The fact that the bench harness emits these counters
automatically is what makes the numbers attributable.

## Flagged optimisation targets

1. **UdpLink alloc-per-packet** — `plugins/links/udp/udp.cpp`
   currently allocates a fresh buffer per `send` (172 k minor
   faults / 533 k iterations). An arena / pool refactor would
   collapse the allocator share of the CPU time the
   resource counters show. Highest-impact open target.

2. **UdpLink asio-strand hop on every send** — 1 voluntary
   context switch per `send` (176 k / 533 k). Batching sends or
   posting only when crossing threads would cut ctx-switch
   count. Lower impact than #1 because asio strands are cheap,
   but adds up at million-PPS workloads.

3. **Noise transport returns `std::vector` per call** — at 64 B
   payloads the per-call allocation dominates over the AEAD
   itself (115 MiB/s @ 64 B vs 274 MiB/s @ 64 K = 2.4 × drop).
   A span-based variant that writes into a caller-provided
   buffer would close most of that gap.

Each target has the surfacing bench + counter row tied to it, so
"did the fix actually help" is a single re-run.

## How GoodNet compares architecturally

GoodNet ships a **kernel + C ABI** model: pluggable transports,
security providers, protocol layers, handlers — each its own git
tree, own license, own release cadence. iperf3 is a single tight
loop. libuv is a library. OpenSSL is a crypto library + CLI tools.
libssh is a library. WireGuard is a kernel module. None of them
let you swap the transport layer at config time, run two transports
to the same peer concurrently, or add a new framing without
recompiling the kernel.

The numbers above quantify the **composability budget**: GoodNet
pays ≈ 5 × the raw-TCP throughput because every byte goes through
plugin boundaries (host_api thunks, per-plugin asio strands,
allocator). In return, the same conn id keeps working through
NAT-traversed multi-path failover, the application has 43 LOC of
client + server, and the wire format / security / framing / strategy
are all swappable at deploy time.

The bench tree exists so that trade-off is **observable** —
not asserted, not assumed.

## What's not measured (gaps to close)

- **Real-mode QUIC bench** — `QuicLink::listen/connect` return
  `GN_ERR_NOT_IMPLEMENTED` (composer-only over UDP carrier);
  `bench_real_e2e` needs a LinkCarrier + composer chain
  bring-up in `test_bench_helper.hpp`. Until landed, the iroh
  column in the comparison section has no GoodNet pair.
- **`bench_real_e2e` in the default runner set** — `run_all.sh`
  currently ships TCP / IPC / WS / TLS / ICE / subprocess / failover
  in its `default_set`; `bench_real_e2e` runs standalone but the
  aggregator's `## А. Comparable echo round-trip` section stays
  empty in default reports until the runner picks it up.
- **Production Noise→Null handoff** — B.3 runs through a
  compile-gated `_test_clear_inline_crypto` PoC seam in
  `SecuritySession` (built only with `GOODNET_BENCH_SHOWCASE`;
  default kernel binaries drop the symbol entirely). A
  kernel-driven `SessionRegistry::downgrade_*`
  API + trust-class hook on connection bring-up + peer-side wire
  signal is planned, so both halves of a session migrate
  symmetrically without bench harness reaching into private state.
- **Kernel-side strategy event emission** — `notify_connect`
  fires `CONN_UP` (`core/kernel/host_api/notifications.cpp:131`)
  and `notify_disconnect` fires `CONN_DOWN`
  (`core/kernel/host_api/notifications.cpp:562`) to every
  registered strategy. B.5 + B.6 nevertheless inject their own
  `on_path_event` calls so the bench can drive specific event
  timing without staging a full kernel connect/disconnect dance;
  the manual injection is bench-side convenience, not a gap.
- **Network mobility** — AF_NETLINK socket on `RTM_NEWLINK` /
  `RTM_DELLINK` is wired via
  `plugins/links/ice/interface_watcher.{hpp,cpp}` and drives an
  ICE host-candidate re-gather on debounced interface events.
  The B.6 bench still injects its own synthetic second carrier so
  the trigger timing is deterministic against the bench window;
  the netlink observer covers the production reachability path.
- **xprocess (inter-process)** — the operator-facing topology;
  current numbers are all in-process.
- **Inter-host LAN** — no two-machine harness in tree yet.
- **10 Gbps NIC** — every datapoint here is loopback.
- **libwebrtc data channel, nginx-quic HTTP/3** — heavy setups
  (Docker, ~10 GB build). Deferred to opt-in CI.
- **Chaos bench (`tc netem` loss / latency injection)** — opt-in
  via `GN_BENCH_CHAOS=1`, not in default report.

The methodology requires every gap above to be filled — see
[`bench/README.md`](../../bench/README.md) for the recipe.

## How to reproduce

```bash
git clone https://github.com/GoodNet-io/goodnet.git
cd goodnet

# Build with bench (Release — see Build configuration above)
nix develop --command \
    cmake -B build-release -DCMAKE_BUILD_TYPE=Release \
                           -DGOODNET_BUILD_BENCH=ON
nix develop --command cmake --build build-release --target \
    bench_tcp bench_udp bench_ipc bench_ws bench_tls \
    bench_dtls bench_quic bench_ice bench_wss_over_tls \
    bench_tcp_scale bench_noise bench_real_e2e

# Free-kernel showcase (opt-in, needs strategies sub-checkout)
nix develop --command cmake -B build-release \
    -DCMAKE_BUILD_TYPE=Release -DGOODNET_BUILD_BENCH=ON \
    -DGOODNET_BENCH_STRATEGIES=ON
nix develop --command cmake --build build-release --target bench_showcase

# Stage external baselines (one-shot, ~5 min including OpenSSL
# shallow clone)
./bench/comparison/setup/01_openssl.sh
./bench/comparison/setup/02_iperf3.sh
./bench/comparison/setup/03_libuv.sh
./bench/comparison/setup/04_libssh.sh
./bench/comparison/setup/05_openssl_demos.sh

# Run the full matrix + cross-impl baselines + aggregate
nix develop --command bash bench/comparison/runners/run_all.sh
ls bench/reports/  # one .md per commit sha — fair-comparison aggregate

# Run the free-kernel showcase + aggregate (separate report)
nix develop --command \
    ./build-release/bench/bench_showcase \
        --benchmark_out=bench/reports/showcase-raw.json \
        --benchmark_out_format=json \
        --benchmark_min_time=2s
nix develop --command python3 \
    bench/comparison/reports/showcase_aggregate.py \
        "$(git rev-parse --short HEAD)" \
        bench/reports/showcase-$(git rev-parse --short HEAD).md \
        bench/reports/showcase-raw.json
ls bench/reports/showcase-*.md  # showcase narrative report
```

Two reports per run:
* `bench/reports/<sha>.md` — fair-comparison aggregate (section
  А for libp2p / iroh pairing, parody matrix, cost decomposition).
* `bench/reports/showcase-<sha>.md` — free-kernel showcase
  (six B.X sections with acceptance verdicts + ASCII sparks).

Every table in this article is a copy-paste from one of those
two files.
