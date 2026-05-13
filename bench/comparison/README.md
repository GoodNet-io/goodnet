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
* **`bench/reports/showcase-<sha>.md`** — free-kernel showcase
  ("track Б"). Six narrative sections (multi-connect, strategy-
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
│   ├── 02_nginx_quic.sh     — nginx-quic Docker image + cert
│   ├── 03_libuv_echo.sh     — plain libuv echo server (raw TCP)
│   ├── 04_libwebrtc.sh      — libwebrtc data channel echo
│   └── 05_libssh_echo.sh    — libssh-based SSH echo
├── runners/                 — payload-matrix drivers
│   ├── tcp_throughput.sh    — runs every TCP-class baseline
│   ├── tls_handshake.sh     — measures handshake time per stack
│   ├── quic_throughput.sh
│   └── dx_loc_count.sh      — counts LOC for "hello world" per stack
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
# Stage external baselines (one-shot, ~10-30 min depending on
# network + Docker image pulls)
./bench/comparison/setup/01_openssl.sh
./bench/comparison/setup/02_nginx_quic.sh
# ...

# Drive matrix
./bench/comparison/runners/tcp_throughput.sh > /tmp/tcp.json
./bench/comparison/runners/tls_handshake.sh > /tmp/tls.json
./bench/comparison/runners/dx_loc_count.sh   > /tmp/dx.json

# Aggregate (parses both GoodNet google-benchmark JSON and the
# baseline JSON output above)
python3 bench/comparison/reports/aggregate.py /tmp/*.json \
    > bench/reports/<commit-sha>-comparison.md
```

## What gets measured

| Axis | GoodNet | Reference | Surface |
|---|---|---|---|
| TCP throughput | `bench_tcp` | libuv echo | 64B / 1KB / 8KB / 64KB |
| TLS handshake time | `bench_tls` | `openssl s_client` + s_server | median + P99 |
| TLS throughput | `bench_tls` | `openssl s_client -tlsextdebug` | 1KB / 64KB |
| QUIC throughput | `bench_quic` | nginx-quic + h3 client | 1KB / 64KB |
| Data channel | `bench_quic+ice` | libwebrtc data channel echo | RTT + 1KB throughput |
| SSH echo | `bench_ssh` (future) | libssh `ssh_channel_write` echo | 64B latency |
| LOC for hello-world echo | counted from `examples/hello-echo` | counted from each ref's hello-echo | min / max / median |
| RSS baseline | `getrusage` after handshake | `ps -o rss` post-handshake | KB |
| First-byte time | timestamp from connect to first decrypted byte | per-stack instrumentation | μs |

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
