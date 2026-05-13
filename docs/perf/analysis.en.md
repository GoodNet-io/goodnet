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

Six measurement axes (full table in
[`bench/README.md`](../../bench/README.md)):

| Axis | What it varies |
|---|---|
| **Payload size** | 64 / 1024 / 8192 / 65536 bytes |
| **Connection count** | 1 / 10 / 100 / 1000 parallel conns |
| **Concurrency** | 1 / 2 / 4 / 8 worker threads |
| **Plugin** | TCP / UDP / IPC / TLS / WS / DTLS / QUIC / ICE |
| **Composition depth** | TLS/TCP (2), WSS/TLS/TCP (3), Noise/QUIC/UDP (3) |
| **Strategy** | min-RTT picker over N candidates |

Plus a **topology** dimension (intra-process loopback /
inter-process xprocess / inter-host LAN) and a **cross-impl**
dimension that drives the same payload matrix through external
baselines.

### Measurement shape: send-only vs echo vs handshake

Each bench fixture is one of three shapes. Mixing them in a single
table — "GoodNet 1.6 GiB/s vs libp2p 250 MiB/s" — is the apples-
to-oranges trap this section exists to flag.

| Shape | Hot-loop body | Reads | Compares with |
|---|---|---|---|
| `Throughput` | `client.send(payload)` only | Send-side syscall + plugin overhead, no response | iperf3 raw send |
| `EchoRoundtrip` | `client.send → server.send_back → client.read` | Full stack overhead both directions + 1 RTT | rust-libp2p, iroh, browser data-channel |
| `HandshakeTime` | Set up fresh connection, no traffic | Crypto + control-plane cost only | OpenSSL `s_client` handshake |

Rust P2P stacks expose echo + handshake; iperf3 exposes
send-only. GoodNet exposes all three (`Throughput`,
`EchoRoundtrip`, `HandshakeTime` fixtures per plugin where the
fixture race is fixed). The aggregator never crosses shapes
in a single table — see `## Echo round-trip — side-by-side` for
the round-trip cross-impl matrix.

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

## Results — current snapshot (2026-05-13)

Reference commit: [`bench/reports/80d2a04.md`](../../bench/reports/80d2a04.md).
Bench harness expanded with VmHWM / VmPeak / socket-buffer
counters plus a backpressure stress fixture per
[`bench/README.md`](../../bench/README.md#memory-measurement-caveats);
the report has new sections for `## Binary sizes & deployment
closure` and `## Comparison stack weights` so the size axis is
read side-by-side with the throughput axis.

### Per-plugin throughput

| Plugin | @ 64B | @ 512–1200B | @ 8192B |
|---|---|---|---|
| UDP   | 166 MiB/s | 1.00 GiB/s (512 B) / 1.57 GiB/s (1200 B PMTU) | error (MTU cap) |
| WS    | 128 MiB/s | 736 MiB/s | **1.23 GiB/s** |
| Noise transport (AEAD) | 115 MiB/s | 225 MiB/s | 251 MiB/s |
| Noise transport @ 65 K | — | — | 274 MiB/s |

**Peak:** UDP @ 1200 B PMTU = **1.57 GiB/s ≈ 13.5 Gb/s** (with
+1.3 GiB current RSS, +691 MiB peak — allocator returned ~630 MiB
via `madvise` over the window; the burst-vs-released distinction
the new VmHWM column makes visible).

### Handshake time

| Stack | Median |
|---|---|
| TCP listen+connect | 5.1 ms |
| Noise XX (3 messages, no socket) | 238 μs |
| Noise IK (2 messages + pre-message hash) | 321 μs |
| ICE `composer_connect` dispatch | 75 ns |

IK appears slightly slower than XX on loopback because both share
4 DH operations but IK does 2 extra pre-message hashes. IK wins in
real networks where it saves one RTT — the loopback bench captures
crypto-only cost, not the round-trip differential.

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
`*Fixture/EchoRoundtrip` measures for fair compare.

| Stack | Metric | Throughput @ 8 KiB |
|---|---|---|
| **GoodNet WS echo** | WS over TCP loopback | **136 MiB/s** |
| rust-libp2p 0.55 echo | TCP + Noise + Yamux | 135 MiB/s |
| iroh 0.32 echo | QUIC + TLS 1.3 | 95 MiB/s |

| Stack | Metric | Throughput @ 64 KiB |
|---|---|---|
| GoodNet WS echo | WS over TCP loopback | 185 MiB/s |
| **rust-libp2p 0.55 echo** | TCP + Noise + Yamux | **254 MiB/s** |
| iroh 0.32 echo | QUIC + TLS 1.3 | 194 MiB/s |

GoodNet leads on 8 KiB (frame overhead amortised), libp2p edges
ahead on 64 KiB (yamux's long-substream design wins when stream-open
cost is rare). iroh trails because the bench uses `open_bi()` per
round (RPC-style), so each 65 KiB payload pays one stream-open +
close overhead — symmetric with how applications actually use iroh.

Full payload sweep + handshake numbers live in
`bench/reports/<sha>.md` under **`## Echo round-trip — side-by-side`**.

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

The 2026-05-13 bench expansion sizes every stack on the same
axes (`Binary` on disk + `Lib closure` from `ldd`), so a reader
can compare "what an operator copies onto a fresh host" side-by-
side with the throughput / latency rows.

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

The same report row also tracks the Nix dependency closure (99.8
MiB worst case before store de-duplication) and a
`debian:bookworm-slim`-based Docker image (72.7 MiB; a musl /
scratch base would drop to ~5 MiB but needs a separate musl plugin
port). Full numbers in
[`bench/reports/80d2a04.md` § "Binary sizes & deployment closure"](../../bench/reports/80d2a04.md).

### Memory burst vs. released (new VmHWM column)

The 2026-05-13 harness reads `VmHWM` (peak RSS) alongside
`VmRSS` (current) on every bench. Two patterns the side-by-side
makes visible:

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

### Kernel socket buffers (new sock_mem column)

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

- **TCP throughput / latency in-process** — bench fixture has a
  port-allocation / session-registration race that lets sends
  return `NOT_FOUND`; handshake bench works.
- **TLS / WSS / DTLS / QUIC handshake** — `UseManualTime` shape
  conflicts with the aggregator's median picker (rows show "—").
- **xprocess (inter-process)** — the operator-facing topology;
  current numbers are all in-process.
- **Inter-host LAN** — no two-machine harness in tree yet.
- **10 Gbps NIC** — every datapoint here is loopback.
- **libwebrtc data channel, nginx-quic HTTP/3** — heavy setups
  (Docker, ~10 GB build). Deferred to opt-in CI.
- **Chaos bench (`tc netem` loss / latency injection)** — opt-in
  via `GN_BENCH_CHAOS=1`, not in default report.

The methodology requires every gap above eventually fills — see
[`feedback_bench_methodology.md`](../../bench/README.md) for the
recipe.

## How to reproduce

```bash
git clone https://github.com/goodnet-io/goodnet.git
cd goodnet

# Build with bench (Release — see Build configuration above)
nix develop --command \
    cmake -B build-release -DCMAKE_BUILD_TYPE=Release \
                           -DGOODNET_BUILD_BENCH=ON
nix develop --command cmake --build build-release --target \
    bench_tcp bench_udp bench_ipc bench_ws bench_tls \
    bench_dtls bench_quic bench_ice bench_wss_over_tls \
    bench_tcp_scale bench_noise

# Stage external baselines (one-shot, ~5 min including OpenSSL
# shallow clone)
./bench/comparison/setup/01_openssl.sh
./bench/comparison/setup/02_iperf3.sh
./bench/comparison/setup/03_libuv.sh
./bench/comparison/setup/04_libssh.sh
./bench/comparison/setup/05_openssl_demos.sh

# Run the full matrix + cross-impl baselines + aggregate
nix develop --command bash bench/comparison/runners/run_all.sh
ls bench/reports/  # one .md per commit sha
```

The report at `bench/reports/<sha>.md` is the single source of
truth — every table in this article is a copy-paste from it.
