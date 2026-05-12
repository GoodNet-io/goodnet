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
rss_kb_delta                              # /proc/self/statm
minor_faults / major_faults               # allocator + disk-back
vol_ctx_sw / inv_ctx_sw                   # sync + preemption
block_io_in / block_io_out                # disk
```

This is the minimum surface required to answer "why is the number
what it is" without re-running with a profiler.

## Results — current snapshot (2026-05-12)

Reference commit: `bench/reports/0c90f2e.md`.

### Per-plugin throughput

| Plugin | @ 64B | @ 512–1200B | @ 8192B |
|---|---|---|---|
| UDP   | 164 MiB/s | 1.03 GiB/s (PMTU) | error (MTU cap) |
| WS    | 123 MiB/s | 653 MiB/s | **1.32 GiB/s** |
| Noise transport (AEAD) | 115 MiB/s | 225 MiB/s | 251 MiB/s |
| Noise transport @ 65 K | — | — | 274 MiB/s |

**Peak:** UDP @ 1200 B PMTU = **1.64 GiB/s ≈ 14 Gb/s**.

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
| **iperf3 raw TCP** | TCP single-stream | **7.23 GiB/s ≈ 62 Gb/s** |
| iperf3 raw UDP | UDP, capped via `-b 1000M` | 119 MiB/s |
| **GoodNet UDP @ 1200 B** | UDP composer | **1.64 GiB/s ≈ 14 Gb/s** |
| GoodNet WS @ 8192 B | WS-over-TCP | 1.32 GiB/s ≈ 11 Gb/s |

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
| **GoodNet WS echo** | WS over TCP loopback | **130 MiB/s** |
| rust-libp2p 0.55 echo | TCP + Noise + Yamux | 118 MiB/s |
| iroh 0.32 echo | QUIC + TLS 1.3 | 90 MiB/s |

| Stack | Metric | Throughput @ 64 KiB |
|---|---|---|
| **GoodNet WS echo** | WS over TCP loopback | **219 MiB/s** |
| rust-libp2p 0.55 echo | TCP + Noise + Yamux | 249 MiB/s |
| iroh 0.32 echo | QUIC + TLS 1.3 | 195 MiB/s |

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
