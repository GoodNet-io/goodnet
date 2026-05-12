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

## What's not measured (yet)

| Gap | Reason | Plan |
|---|---|---|
| Inter-host LAN bench | Needs two machines | Manual run instructions; CI variant deferred |
| Browser <-> kernel via WASM | WASM loader not landed | Deferred to build-variants module |
| 1000+ conns / 10k+ conns | Kernel ephemeral port pool, fd cap | Add `ulimit -n` documentation + Arg(1000) |
| TCP_NODELAY / SO_RCVBUF tuning | Plugin defaults documented elsewhere | Bench reads from `links.tcp.*` config |
| Failure-injection bench (packet loss, network partition) | Needs tc netem orchestration | Deferred to "chaos bench" follow-up |
| Plugin dlopen vs static-link dispatch overhead | Build variants module dep | Deferred |
