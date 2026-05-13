# Rust P2P baselines

Fair-compare loopback echo round-trip между GoodNet
(`UdpFixture/EchoRoundtrip`, `WsFixture/EchoRoundtrip` in
`bench/plugins/`) и двумя зрелыми Rust P2P-стеками: **rust-libp2p
0.55** (TCP + Noise + Yamux) и **iroh 0.32** (QUIC + TLS 1.3).
Одна и та же hot-loop форма с обеих сторон даёт честное cross-impl
число, без apples-to-oranges пересчёта.

## Layout

```
bench/comparison/p2p/
├── libp2p-echo/        — TCP + Noise + Yamux + libp2p-stream
│   ├── Cargo.toml
│   └── src/main.rs
└── iroh-echo/          — QUIC + TLS 1.3
    ├── Cargo.toml
    └── src/main.rs
```

Каждый — single-file `src/main.rs` и минимальный `Cargo.toml` с
pinned release profile (`opt-level=3`, `lto=thin`,
`codegen-units=1`). Cargo target tree выезжает наружу репозитория
в `build-release/p2p-bench/target/` чтобы не таскать ~3 GB
артефактов под `git`.

## Build

```bash
bash bench/comparison/setup/06_libp2p_rs.sh   # libp2p
bash bench/comparison/setup/07_iroh.sh        # iroh
```

Setup-скрипты:
1. shallow-clone upstream repo в `~/.cache/goodnet-bench-refs/<stack>/`
   и symlink'нут upstream `examples/<hello>.rs` для `dx_loc_count.sh`
2. `cp -R` соответствующий subtree из `p2p/<stack>-echo/` в
   build-каталог
3. вызовут `cargo build --release` — если `cargo` нет в `PATH`, оборачиваются
   через `nix shell nixpkgs#{cargo,rustc,pkg-config,openssl}`

Артефакт — `build-release/p2p-bench/target/release/{libp2p,iroh}-echo`.

Первый билд занимает ~5 минут (LTO + transitive deps); incremental
rebuild — секунды.

## Run

```bash
bash bench/comparison/runners/libp2p_rs.sh [duration_s]
bash bench/comparison/runners/iroh.sh     [duration_s]
```

Runner проходит по payload sweep (64 / 1024 / 8192 / 65536 B),
запускает соответствующий binary, парсит его stdout и эмитит JSON
совместимый с `aggregate.py`:

```json
{"metric": "libp2p_echo_throughput",
 "note":   "...",
 "rows":   [{"stack":"libp2p","payload":64,"bytes_per_sec":...,"handshake_ms":...}, ...]}
```

`run_all.sh` подцепляет runner'ы автоматически если бинарь
существует; иначе — graceful no-op (нет setup'а — нет строк в отчёте).

## Environment variables

| Var | Default | Effect |
|---|---|---|
| `ECHO_PAYLOAD` | `8192` | Per-round payload в байтах |
| `ECHO_DURATION` | `3` | Длина hot loop в секундах |
| `GN_BENCH_P2P_DIR` | `<repo>/build-release/p2p-bench` | Где хранится cargo target |
| `GN_BENCH_REFS_DIR` | `~/.cache/goodnet-bench-refs` | Кеш upstream sources |

## Methodology

Hot loop:

```
client.send(payload)  →  server.read()  →  server.send(payload)  →  client.read()
```

Считается общее число успешно «прокачанных туда-обратно» байт за
`ECHO_DURATION`. Это симметрично с GoodNet `EchoRoundtrip`
фикстурами (`bench_udp`, `bench_ws`) — те же байты считаются
по тем же правилам.

**libp2p**: один длинный bi-directional yamux substream, `write_all
+ read_exact` цикл. Substream open платится один раз; steady-state
limited by yamux frame overhead.

**iroh**: `conn.open_bi()` + `send.write_all` + `send.finish()` +
`recv.read_to_end()` **per round** (RPC-style). Каждый round
платит open + close стрима — отсюда near-zero throughput на
64 / 1024 B. На больших payloads overhead амортизируется.

## Fair-compare caveat

GoodNet `Throughput` бенчи (`UdpFixture::Throughput`,
`WsFixture::Throughput`) — **send-only**: считают только
одностороннюю прокачку. Цифры вроде «UDP @ 1200 B = 1.6 GiB/s» не
сравниваются напрямую с libp2p / iroh — те всегда round-trip.

Для честного сравнения смотрят:

| Фикстура | Methodology |
|---|---|
| `UdpFixture/Throughput/<N>` | send-only (vs iperf3 UDP) |
| `WsFixture/Throughput/<N>` | send-only (vs iperf3 TCP) |
| **`UdpFixture/EchoRoundtrip/<N>`** | round-trip (vs libp2p / iroh) |
| **`WsFixture/EchoRoundtrip/<N>`** | round-trip (vs libp2p / iroh) |

Aggregator выводит side-by-side table в `## Echo round-trip —
side-by-side` секции отчёта, где GoodNet UDP/WS EchoRoundtrip
стоят рядом со строками libp2p и iroh per payload.

## Versions pinned

| Stack | Crate | Version |
|---|---|---|
| libp2p | `libp2p` | 0.55 (`tcp`, `noise`, `yamux`, `macros`) |
| libp2p | `libp2p-stream` | `=0.3.0-alpha` |
| iroh | `iroh` | 0.32 |

Bumping a crate version requires re-running setup so cargo
re-resolves. Pin enforced via `=` или upper-bound in Cargo.toml.
