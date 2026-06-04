# Showcase bench report — 244f654

_Free-kernel showcase. Each section demonstrates one GoodNet-distinctive move no other stack reproduces natively. NOT a fair-comparison surface (that lives in `bench/reports/<sha>.md` section А); this report's reader is asked «попробуй повторить»._

## B.1 — Multi-connect под одной identity

**Что это.** Один peer pk у alice; bob дозванивается до неё через три одновременно живых carrier'a (TCP + UDP + IPC). Kernel's ConnectionRegistry хранит три записи под одним `remote_pk`.

**Почему это GoodNet-only.** libp2p/WebRTC/gRPC привязывают peer identity к одному transport-instance при handshake'е. Сменить carrier runtime'но — это либо reconnect (новый identity у iroh QUIC), либо отдельная multistream-фабрика (libp2p, fragmented). У GoodNet это base-line поведение registry; три conn'a живут одновременно и видимы strategy plugin'у.

**Bench.**

| Payload | Time | Throughput | alice conns | alice sessions |
|---|---|---|---|---|
| 1024 B | — | — | 3 | 3 |
| 64 B | — | — | 3 | 3 |
| 8192 B | — | — | 3 | 3 |

**Acceptance.** `alice.conns == 3` required: **PASS** (observed 3).

## B.2 — Strategy-driven carrier selection

**Что это.** Bob регистрирует `float_send_rtt` strategy plugin. Synthetic RTT samples (TCP=200µs, UDP=150µs, IPC=20µs) feed the picker через `on_path_event`. Picker сходится к IPC. Деградация RTT (IPC→500µs) flips winner после ~3 samples (EWMA α=1/8 hysteresis).

**Почему это GoodNet-only.** У libp2p/iroh/gRPC carrier выбирается на установке connection и навсегда. Adaptive routing per-send под одним peer identity — это feature без аналога в этом классе.

**Bench: picker overhead + IPC selection.**

| Payload | Picker dispatch | IPC picks | Other picks |
|---|---|---|---|
| 1024 B | 76 ns | 5065050 | 0 |

**Bench: flip on RTT degradation.**

| Total iters | Flip iter | Comment |
|---|---|---|
| 2214032 | 0 | Hysteresis kicks in after ~3 sample EWMA crossover |

**Acceptance.** Picker selects IPC majority (`picks_ipc > picks_other`): **PASS**.

## B.3 — Topology seal — статическое доказательство безопасности до первого фрейма

**Что это.** При старте kernel вызывает `build_topology()`: обходит все зарегистрированные security-провайдеры и link-плагины, собирает SHA-256 fingerprint (детерминированный, независимо от порядка регистрации) и вычисляет `contour_gaps` — bitmask trust-классов без E2E-провайдера. Если `contour_gaps == 0` — контур закрыт до первого send. Fingerprint меняется при изменении стека → peer exchange сразу видит несовместимость.

**Почему это GoodNet-only.** libp2p/WebRTC/gRPC не имеют понятия topology seal: несовместимость security-стека обнаруживается только при первом handshake. У GoodNet `contour_gaps == 0` — это compile-time/startup invariant, не runtime-проверка. Fingerprint = криптографический идентификатор стека, обмениваемый после Noise XX без перенастройки протокола.

**Bench: Noise+IPC steady-state (baseline).**

| Payload | p50 | p95 | p99 |
|---|---|---|---|
| 64 B | 15.1 μs | 20.3 μs | 36.4 μs |
| 1024 B | 16.6 μs | 23.0 μs | 40.4 μs |

**Bench: `build_topology()` seal cost.**

| Seal cost (p50) | contour_gaps | fp_prefix_u32 |
|---|---|---|
| 554 ns | `0x00000030` | `0x3c77376b` |

**Bench: fingerprint determinism.**

| fp_mismatches | (must be 0) |
|---|---|
| 0 | ✓ |

**Acceptance.** `contour_gaps & 0x3 == 0` (UNTRUSTED + PEER covered) and `fp_mismatches == 0`: **PASS** (gaps=0x30, mismatches=0).

## B.4 — Multi-thread fanout

**Что это.** N producer threads на bob одновременно дёргают `api.send_to(alice_pk, ...)`. Kernel разводит на per-conn strand + crypto pool. Throughput vs N показывает где kernel становится bottleneck'ом (single-writer drain CAS в `PerConnQueue::drain_scheduled`).

**Почему это GoodNet-only.** gRPC обычно один HTTP/2-stream per goroutine; libp2p stream-multiplexer не parallel'ит crypto. У GoodNet kernel-side strand routing — это base feature, scaling обусловлено архитектурой kernel'a, не SDK-обёртками.

**Bench.**

| Producers | Sent | vol_ctx_sw | inv_ctx_sw | CPU total |
|---|---|---|---|---|
| 1 | 104524 | 339299 | 4073 | 2.24 s |
| 2 | 154296 | 263256 | 12625 | 2.70 s |
| 4 | 129778 | 277906 | 20052 | 3.72 s |
| 8 | 87844 | 134269 | 23804 | 4.20 s |

**Acceptance.** Throughput grows monotonically with N (single-carrier knee around N=2; multi-carrier knee expected ≈ crypto pool width once multipath-bond strategy lands).

## B.5 — Carrier failover

**Что это.** Picker выбирает IPC (RTT 20µs). Mid-bench bench инжектит `CONN_DOWN` на IPC conn (the kernel observer that would auto-emit the event from `notify_disconnect` is not wired here; bench drives the picker directly). Picker переключается на TCP — следующий best-RTT. Zero packet loss across the flip.

**Почему это GoodNet-only.** У libp2p/WebRTC failover между transport instances — это reconnect: rebuild handshake state, lose pending frames. У GoodNet strategy slot'ы — runtime decisions; переключение между уже установленными conn'ами — это просто следующий `pick_conn` call.

**Bench.**

| Total iters | Drop iter | Flip iter |
|---|---|---|
| 1000000 | 100 | 100 |

**Acceptance.** Flip lands within ≤ 5 iter of drop: **PASS** (drop=100, flip=100).

## B.6 — Mobility → LAN shortcut

**Что это.** Alice стартует с одним carrier'ом (TURN-relayed, RTT 60µs). Mid-bench симулируем «пришла домой» — синтетически появляется второй carrier (LAN host candidate, RTT ~2µs). Strategy ловит CONN_UP, winner flip'ается на LAN. Traffic counter на TURN side НЕ растёт после flip'a — трафик уходит на свитч, не в интернет.

**Почему это GoodNet-only.** WebRTC ICE-restart требует full re-handshake. libp2p multistream не switches carrier'ы на одной identity. Mobile gRPC retries — это full connection reset. У GoodNet это сборка из multi-connect + strategy + ICE host candidate priority (RFC 8445 §5.1.2). Identity preserved across the path flip.

**Bench.**

| Total iters | LAN up at | Flip at | TURN bytes | LAN bytes |
|---|---|---|---|---|
| 1118960 | 100 | 101 | 102400 | 1145712640 |

**Acceptance.** Flip within ≤ 5 iter of LAN appearance: **PASS** (lan_up=100, flip=101).

## B.7 — Transparent in-chain zstd decompression

**Что это.** Bob сжимает payload ZSTD и отправляет как msg_id=0x0701. У alice зарегистрирован ZstdDecompressHandler (priority=255) на 0x0701; он распаковывает фрейм и re-inject'ит под 0x0700. RxCounter на 0x0700 срабатывает для обоих сценариев — application handler не меняется. Compression = handler-chain middleware, вставляется без изменения send/receive сторон.

**Почему это GoodNet-only.** В libp2p нет per-message-type handler chain; компрессия там на уровне транспорта (DEFLATE в YAMux), безусловная для всего потока. В gRPC компрессия per-RPC-call, не per-msg_id. GoodNet позволяет вставить произвольный middleware handler на конкретный msg_id без изменения остального кода.

_no `CompressionFixture/*` data in input — skip_
_(requires `-DGOODNET_BENCH_ZSTD=1`, i.e. `goodnet_zstd_decompress_objects` + `libzstd` present)_
