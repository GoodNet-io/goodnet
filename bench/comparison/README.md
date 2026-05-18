# Cross-implementation comparison

Goal: surface UX / DX gaps between GoodNet and mature solutions
(OpenSSL CLI tools, nginx-quic, libwebrtc data channels, plain
libuv echo servers, libssh, etc.) on the same payload matrix the
in-tree bench uses, so the released report can call out areas
where GoodNet underperforms.

## Two report tracks

The aggregator under `reports/` emits two independent markdown
documents per run:

* **`bench/reports/<sha>.md`** — fair-comparison aggregate.
  Section `## А. Comparable echo round-trip — production stack vs
  libp2p / iroh` is the only place that quotes GoodNet next to
  libp2p / iroh; both sides match in stack shape (transport + AEAD
  + framing/mux). Driven by `aggregate.py` + the runners listed in
  this README. See `docs/perf/methodology.en.md` §1.3 (pairing
  rule).
* **`bench/reports/showcase-<sha>.md`** — free-kernel showcase.
  Six narrative sections (multi-connect, strategy-
  driven carrier selection, post-handshake Noise→Null handoff
  PoC, multi-thread fanout, carrier failover, mobility LAN
  shortcut). NOT a fair-comparison surface — every section is a
  capability where libp2p / WebRTC / gRPC have no architectural
  equivalent. Driven by `showcase_aggregate.py` against the
  `bench_showcase` binary. See `bench/showcase/README.md`.

## Layout

```
bench/comparison/
├── README.md                — this file
├── setup/                   — one-shot fetcher / builder scripts
│   ├── 01_openssl.sh        — OpenSSL s_server / s_client baseline
│   ├── 02_iperf3.sh         — iperf3 TCP / UDP throughput baseline
│   ├── 03_libuv.sh          — fetch libuv into the bench cache (DX LOC)
│   ├── 04_libssh.sh         — fetch libssh upstream mirror (DX LOC)
│   ├── 05_openssl_demos.sh  — OpenSSL demos/sslecho for DX LOC
│   ├── 06_libp2p_rs.sh      — build in-tree libp2p-echo binary
│   └── 07_iroh.sh           — build in-tree iroh-echo binary
├── runners/                 — payload-matrix drivers
│   ├── binary_sizes.sh      — JSON of every shippable artifact size
│   ├── comparison_weights.sh — JSON of "deployment weight" per stack
│   ├── dx_loc_count.sh      — counts LOC for "hello echo" per stack
│   ├── iperf3_tcp.sh        — raw TCP throughput via iperf3
│   ├── iperf3_udp.sh        — raw UDP throughput via iperf3
│   ├── iroh.sh              — run staged iroh-echo across payload sweep
│   ├── libp2p_rs.sh         — run staged libp2p-echo across payload sweep
│   ├── run_all.sh           — orchestrator over every runner + aggregator
│   ├── socat_unix.sh        — socat AF_UNIX echo (baseline for bench_ipc)
│   └── tls_handshake.sh     — TLS handshake time per stack
└── reports/
    └── (generated *.md)
```

## Why shell, not C++

Each baseline lives in its own ecosystem (Go module, Docker image,
Python venv, etc.). Building them in-tree would pull in dependencies
GoodNet itself doesn't need and tie release timing to upstreams.
Shell drivers wrap whatever's on `PATH` after the setup scripts run;
each baseline's footprint stays in `~/.cache/goodnet-bench-refs/`
unless `GN_BENCH_REFS_DIR` overrides.

## Running

```bash
# Stage external baselines (one-shot)
./bench/comparison/setup/01_openssl.sh
./bench/comparison/setup/02_iperf3.sh
./bench/comparison/setup/06_libp2p_rs.sh
./bench/comparison/setup/07_iroh.sh
# ...

# Drive matrix
./bench/comparison/runners/iperf3_tcp.sh     > /tmp/tcp.json
./bench/comparison/runners/iperf3_udp.sh     > /tmp/udp.json
./bench/comparison/runners/tls_handshake.sh  > /tmp/tls.json
./bench/comparison/runners/dx_loc_count.sh   > /tmp/dx.json
./bench/comparison/runners/libp2p_rs.sh      > /tmp/libp2p.json
./bench/comparison/runners/iroh.sh           > /tmp/iroh.json

# Or run every runner + aggregator in one shot
./bench/comparison/runners/run_all.sh

# Aggregate manually (parses GoodNet google-benchmark JSON and the
# baseline JSON output above)
python3 bench/comparison/reports/aggregate.py /tmp/*.json \
    > bench/reports/<commit-sha>-comparison.md
```

## What gets measured

| Axis | GoodNet | Reference | Runner |
|---|---|---|---|
| TCP throughput | `bench_real_e2e RealFixtureTcpEcho` | iperf3 | `iperf3_tcp.sh` |
| UDP throughput | `bench_real_e2e RealFixtureUdpEcho` | iperf3 | `iperf3_udp.sh` |
| AF_UNIX echo | `bench_real_e2e RealFixtureIpcEcho` | socat | `socat_unix.sh` |
| TLS handshake time | `bench_tls` | `openssl s_client` + s_server | `tls_handshake.sh` |
| Production-stack echo round-trip | `bench_real_e2e *EchoRoundtrip` | libp2p-echo + iroh-echo | `libp2p_rs.sh` + `iroh.sh` |
| DX LOC for "hello echo" | `examples/hello-echo/` | upstream `hello echo` samples staged by `setup/03..07` | `dx_loc_count.sh` |
| Binary size | kernel + plugin .so files | per-stack reference binaries | `binary_sizes.sh` |
| Deployment weight | comparison-weights JSON | each comparison stack | `comparison_weights.sh` |

## DX axis

The LOC + first-byte axes specifically target the UX / DX angle.
"Hello world" is a tiny client + server that connects, sends one
buffer, prints what it got back, and shuts down cleanly. The LOC
count for each reference stack is taken from upstream-published
examples (OpenSSL `s_client`, libwebrtc data channel sample,
libssh `examples/sshd_direct-tcpip.c`, etc.); GoodNet's number
comes from `examples/hello-echo/` using the new
`gn::sdk::connect_to` sugar.

The goal isn't to win every axis — it's to make weaknesses visible
so they can be prioritised. A bigger LOC count for the same
functionality is a DX gap; longer first-byte time is a UX gap.
Each row in the report names the source files counted so the
comparison is auditable.
