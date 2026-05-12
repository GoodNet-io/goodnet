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
implementations the report compares against. Run via:

```bash
# One-shot setup
./bench/comparison/setup/01_openssl.sh
./bench/comparison/setup/02_iperf3.sh

# Run + aggregate
./bench/comparison/runners/run_all.sh
```

Output: `bench/reports/<commit-sha>.md` — a single markdown table
that interleaves GoodNet numbers with the matching baseline
(iperf3 for TCP/UDP throughput, openssl s_client for TLS
handshake, socat for AF_UNIX echo, etc.).

## What's not measured (yet)

| Gap | Reason | Plan |
|---|---|---|
| Inter-host LAN bench | Needs two machines | Manual run instructions; CI variant deferred |
| Browser <-> kernel via WASM | WASM loader not landed | Deferred to build-variants module |
| 1000+ conns / 10k+ conns | Kernel ephemeral port pool, fd cap | Add `ulimit -n` documentation + Arg(1000) |
| TCP_NODELAY / SO_RCVBUF tuning | Plugin defaults documented elsewhere | Bench reads from `links.tcp.*` config |
| Failure-injection bench (packet loss, network partition) | Needs tc netem orchestration | Deferred to "chaos bench" follow-up |
| Plugin dlopen vs static-link dispatch overhead | Build variants module dep | Deferred |
