# GoodNet bench suite — coverage axes

The bench tree under `bench/` measures GoodNet on six orthogonal
axes plus an external-baselines axis. Each axis intentionally
varies one thing so the report can attribute regression deltas to
the right cause.

## Axes

| Axis | What it varies | Bench binary | Status |
|---|---|---|---|
| **Payload size** | 64 / 1024 / 8192 / 65536 bytes | `bench_<plugin>` Throughput | ✅ TCP, UDP, IPC, WS |
| **Connection count** | 1 / 10 / 100 parallel conns | `bench_tcp_scale ConnectionCountScale` | ✅ TCP (template for others) |
| **Concurrency** | 1 / 2 / 4 / 8 worker threads, full-duplex | `bench_tcp_scale ConcurrentSaturation` | ✅ TCP |
| **Plugin (single-layer)** | TCP / UDP / IPC / TLS / WS / DTLS / QUIC / ICE | `bench_<plugin>` | ✅ |
| **Composition depth** | TLS/TCP (2) / WSS/TLS/TCP (3) / Noise/QUIC/UDP (3) | `bench_wss_over_tls`, follow-ups | ✅ depth-3 WSS; depth-3 Noise TBD |
| **Strategy** | min-RTT picker over N candidates | `bench_float_send_rtt` | ✅ (opt-in via `GOODNET_BENCH_STRATEGIES`) |

## Topology variants

The default fixture runs **in-process**: server + client are two
plugin instances inside the same bench binary, talking over real
loopback sockets. This isolates plugin overhead from kernel
context-switch costs.

For comparison with external baselines we also support **inter-
process** (separate `goodnet` binary as server, bench as client)
via `bench/comparison/runners/goodnet_xprocess.sh` (TBD). The
inter-process number is what a real operator deployment sees;
the in-process number is what the plugin overhead alone costs.

| Topology | Bench location | When to read |
|---|---|---|
| Intra-process loopback | `bench/plugins/bench_*.cpp` | Plugin internals: lock contention, ASIO dispatch, kernel notify path |
| Inter-process loopback | `bench/comparison/runners/goodnet_xprocess.sh` | Operator-facing performance including kernel + IPC costs |
| Inter-host LAN | manual (`build/bench/<plugin> --server` on host A, `--client` on host B) | Network-bound deployments |

## External baselines

`bench/comparison/` contains shell drivers for mature
implementations the report compares against:

| Stack | Setup | Runner | Compares against |
|---|---|---|---|
| iperf3 (raw TCP/UDP) | `setup/02_iperf3.sh` | `runners/iperf3_{tcp,udp}.sh` | `*Fixture/Throughput` (send-only) |
| openssl s_client | `setup/01_openssl.sh` + `05_openssl_demos.sh` | `runners/tls_handshake.sh` | `TlsFixture/HandshakeTime` |
| socat (AF_UNIX) | (built-in) | `runners/socat_unix.sh` | `IpcFixture/Throughput` |
| libuv / libssh | `setup/03_libuv.sh` + `04_libssh.sh` | (DX LOC only) | `dx_loc_hello_world_echo` |
| **rust-libp2p 0.55** | `setup/06_libp2p_rs.sh` | `runners/libp2p_rs.sh` | `*Fixture/EchoRoundtrip` |
| **iroh 0.32** | `setup/07_iroh.sh` | `runners/iroh.sh` | `*Fixture/EchoRoundtrip` |

Rust P2P baselines run echo round-trip — sources в
`bench/comparison/p2p/` (см. README там); setup is opt-in (~5 min
first-time cargo build + ~300 MB transitive deps). `run_all.sh`
graceful-no-op'ит если бинари не собраны.

Run via:

```bash
# One-shot setup (per baseline you want)
./bench/comparison/setup/01_openssl.sh
./bench/comparison/setup/02_iperf3.sh
./bench/comparison/setup/06_libp2p_rs.sh   # opt-in
./bench/comparison/setup/07_iroh.sh        # opt-in

# Run + aggregate
./bench/comparison/runners/run_all.sh
```

Output: `bench/reports/<commit-sha>.md` — markdown отчёт. Самая
наглядная секция — **`## Echo round-trip — side-by-side`**:
pivoted таблица где payload-size это строки, а GoodNet UDP/WS /
libp2p / iroh — колонки, чтобы глаз видел сравнение в одной
clavicle без скроллинга между секциями.

## Memory measurement caveats

A flat `RSS Δ` does NOT mean the bench was memory-quiet. Four
blind spots routinely lie to a casual reader; the harness now
captures the supplementary metrics to distinguish them, and the
report surfaces all four columns side-by-side so the reader can
triangulate.

**A. Pages released via `madvise(MADV_DONTNEED)` mask bursts.**
`VmRSS` (what `top` / `btop` show, what `RSS Δ` reports) is *the
current resident pages*. An allocator that grew the heap to
200 MiB then returned pages with `madvise(MADV_DONTNEED)` ends
the bench with `VmRSS` back at the starting value — the burst
existed but is invisible to a snapshot read. The harness's
`RSS Peak Δ` column reads `VmHWM` from `/proc/self/status`,
which is the **high-water-mark** the kernel accumulates; a
bench that briefly peaked at 200 MiB reports `RSS Δ = 0` but
`RSS Peak Δ = +182 MiB`. Compare the two columns: equal =
flat-real allocation; peak ≫ current = burst-and-released.

**B. Kernel network buffers are not in process RSS.** Each
TCP / UDP socket carries kernel-side send + receive buffers
(`SO_RCVBUF` / `SO_SNDBUF`, typically 256 KiB – 4 MiB per
socket on Linux). 1000 sockets × 2 MiB = ~2 GiB of *kernel*
memory none of which counts toward `VmRSS`. The harness reads
`/proc/net/sockstat` to capture the system-wide TCP + UDP +
FRAG buffer total and reports its delta as `Sock Mem Δ`.
Per-process attribution (which pid owns which buffers) needs
`ss -tm` or `/proc/<pid>/net/sockstat`; the aggregate window
delta is good enough on a quiet test machine because every
other socket stays at steady state.

**C. Shared libraries are counted once.** Multiple `.so`
files sharing pages (`libstdc++.so`, `libsodium.so`, libssl)
contribute their text segment to `VmRSS` exactly once per
process. The static build (`-DGOODNET_STATIC_PLUGINS=ON`)
duplicates none of this — every plugin's `.text` is one
contiguous section of the kernel binary — so a static-vs-
dynamic comparison must take the **sum** of every plugin's
`.so` plus the kernel binary, not just the kernel binary. The
`## Binary sizes` section in the report shows the apples-to-
apples comparison.

**D. Mostly-idle steady state hides queue depth.** An
`EchoRoundtrip` bench where producer and consumer run in
lockstep (zero queue depth) shows `RSS Δ ≈ 0` simply because
no activity sat in any queue. That's the bench measuring
zero-queue-depth latency — not "the plugin is memory-quiet
under all loads". The
`TcpScaleFixture/BackpressureSlowConsumer/<N>` fixture
deliberately throttles the consumer side via
`LinkStub::inbound_sleep_us` (50 µs sleep per inbound notify);
producer threads then drive the queue to its bounded limit.
The resulting `RSS Peak Δ` shows the worst-case footprint the
plugin holds before backpressure engages; `back_pressure_hits`
counts how often the producer hit `pending_queue_bytes_hard`.
A bench with `bp_ratio > 0` proves the backpressure path
actually fires; one with `bp_ratio == 0` but large
`RSS Peak Δ` means the queue grew unbounded (no host_api
`limits()` callback wired in — common in the bench harness
which is a stub, but a red flag in a real kernel).

## What's not measured (yet)

| Gap | Reason | Plan |
|---|---|---|
| Inter-host LAN bench | Needs two machines | Manual run instructions; CI variant deferred |
| Browser <-> kernel via WASM | WASM loader not landed | Deferred to build-variants module |
| 1000+ conns / 10k+ conns | Kernel ephemeral port pool, fd cap | Add `ulimit -n` documentation + Arg(1000) |
| TCP_NODELAY / SO_RCVBUF tuning | Plugin defaults documented elsewhere | Bench reads from `links.tcp.*` config |
| Failure-injection bench (packet loss, network partition) | Needs tc netem orchestration | Deferred to "chaos bench" follow-up |
| Plugin dlopen vs static-link dispatch overhead | Build variants module dep | Deferred |
