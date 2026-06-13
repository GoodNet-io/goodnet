# Benchmark report — 2fe45ee

_Baseline: `bench/reports/7b4ef07.md` — Δ-vs-baseline column in `## Parody` / `## Real` tables flags regressions (`[REGRESSION]` marker on >15% latency slowdown or >10% throughput drop)._

## Environment

| Fact | Value |
|---|---|
| CPU | 12th Gen Intel(R) Core(TM) i5-1235U (12 cores) |
| RAM | 31834 MiB |
| Kernel | 6.18.33 |
| CPU governor | `powersave` (run `cpupower frequency-set -g performance` for production-grade numbers — see `docs/perf/methodology.en.md` §Environmental controls) |
| Turbo | enabled (intel_pstate) |
| SMT | on |
| ASLR | 2 (0=off, 1=stack, 2=full) |
| NUMA nodes | 1 |

## TL;DR — 1024 B payload, all stacks

_Headline throughput across every stack the bench runner observed at the canonical 1024-byte payload. `shape` = `real` for production-equivalent stacks (libp2p TCP+Noise+Yamux, iroh TLS1.3+QUIC, GoodNet `RealFixture/...`) and `parody` for raw-transport baselines (iperf3, GoodNet plugin matrix without security/protocol). Compare same-shape rows only — a `real` vs `parody` delta IS the cost of running the production stack, not a stack quality signal._

| Stack | Shape | Kind | Throughput | P50 RTT | P99 RTT |
|---|---|---|---|---|---|
| GoodNet IPC+Noise+gnet | `real` | echo-RTT | 55.14 MiB/s | 33.2 μs | 69.3 μs |
| GoodNet IPC+Noise+gnet | `real` | echo-one-way | 54.38 MiB/s | 16.8 μs | 35.0 μs |
| GoodNet TCP+Noise+gnet | `real` | echo-one-way | 45.53 MiB/s | 20.2 μs | 48.3 μs |
| GoodNet UDP+Noise+gnet | `real` | echo-RTT | 43.33 MiB/s | 41.7 μs | 97.3 μs |
| GoodNet UDP+Noise+gnet | `real` | echo-one-way | 43.25 MiB/s | 21.5 μs | 49.3 μs |
| GoodNet TCP+Noise+gnet | `real` | echo-RTT | 41.73 MiB/s | 42.8 μs | 101.0 μs |
| iperf3 (raw TCP) | `parody` | tcp_throughput_bps | 7.36 GiB/s | — | — |
| GoodNet TCP | `parody` | send-only | 1.59 GiB/s | — | — |
| GoodNet IPC | `parody` | send-only | 1.08 GiB/s | — | — |
| GoodNet WS | `parody` | send-only | 650.60 MiB/s | — | — |
| iperf3 (raw UDP) | `parody` | udp_throughput_bps | 119.21 MiB/s | — | — |
| GoodNet UDP | `parody` | echo-RTT | 34.49 MiB/s | — | — |
| GoodNet WS | `parody` | echo-RTT | 25.85 MiB/s | — | — |

## А. Comparable echo round-trip — production stack vs libp2p / iroh

_Same conceptual stack on every row: transport + AEAD + framing/mux. GoodNet rows are `RealFixture<plug>Echo` cases (kernel + Noise XX + gnet protocol). libp2p uses Noise XX + Yamux; iroh uses TLS 1.3 + QUIC streams. Compare directly within this section. iperf3 / socat parody rows live in `## Cross-implementation throughput` and are NOT directly comparable — see `docs/perf/methodology.en.md` §1.3 (pairing rule). Real-QUIC fixture is not wired; the QuicLink carrier-bring-up path needs a LinkCarrier + `composer_listen` / `composer_connect` fixture before the iroh row can land here._

| Payload | GoodNet TCP+Noise+gnet | GoodNet IPC+Noise+gnet | GoodNet QUIC+Noise+gnet | libp2p (TCP+Noise+Yamux) | iroh (QUIC+TLS1.3) |
|---|---|---|---|---|---|
| 64 B | 2.91 MiB/s | 3.91 MiB/s | — | — | — |
| 1024 B | 41.73 MiB/s | 55.14 MiB/s | — | — | — |
| 8192 B | 183.31 MiB/s | 211.88 MiB/s | — | — | — |
| 32768 B | 292.65 MiB/s | 324.72 MiB/s | — | — | — |

## Handshake cost — fresh connection setup time

_The connect → first-handler-byte round trip for each transport. TCP is the bare three-way (SYN / SYN-ACK / ACK); TLS adds the 1-RTT handshake on top; QUIC bakes the crypto into the first flight; DTLS is the UDP variant of TLS. Operators serving connection-churn workloads (short-lived RPC, mobile reconnect storms) weight this column heavier than steady-state throughput. Sorted ascending by P50._

| Stack | Case | P50 | P99 |
|---|---|---|---|
| GoodNet TCP | `TcpFixture/HandshakeTime/manual_time` | 53.1 μs | — |
| GoodNet TLS | `TlsFixture/HandshakeTime/manual_time` | 3.6 ms | — |
| openssl s_client | `handshake_ns` | 21.3 ms | 28.1 ms |
| GoodNet DTLS | `DtlsFixture/HandshakeTime/manual_time` | 21.4 ms | — |
| GoodNet QUIC | `QuicFixture/HandshakeTime/manual_time` | 22.2 ms | — |
| GoodNet WSS | `WssFixture/HandshakeTime/iterations:5/manual_time` | — | — |

## Parody — GoodNet plugin matrix (raw transport, no security, no protocol layer)

_**Shape**: bench fixtures wire the link plugin to a test stub `host_api` — no security provider is registered, no protocol layer frames the bytes. Numbers are the upper-bound the plugin can deliver to a downstream that drains as fast as the link writes. Compare against `iperf3` rows below (also no security, no framing) for a fair stack-by-stack delta. For production-shape numbers compare to the `## Real` section (`RealFixture/...` cases) — the delta IS the cost of the production stack._

_`CPU/B` = CPU-nanoseconds per byte sent, derived from getrusage user+sys time and effective throughput. Compare across rows at the same payload size: per-byte cost is the dimension that stays meaningful when the absolute Gbps number moves with link speed or packet size._

_Memory deltas: `RSS Δ` = `VmRSS_end − VmRSS_start` (current; allocator `madvise(MADV_DONTNEED)` masks bursts that returned). `RSS Peak Δ` = `VmHWM_end − VmHWM_start` (high-water-mark; catches bursts). `VSZ Peak Δ` = same for VmPeak (virtual address space, includes mmap'd-but-untouched). `Sock Mem Δ` = kernel TCP+UDP+FRAG buffers from `/proc/net/sockstat` (system-wide; bench attribution via window-delta — every other socket on a quiet test machine stays at steady state)._

| Case | Status | Time | Throughput | Δ vs baseline | CPU/B | P50 lat | P99 lat | RSS Δ | RSS Peak Δ | VSZ Peak Δ | Sock Mem Δ | Minor Faults | Ctx Sw (vol/inv) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| DtlsFixture/HandshakeTime/manual_time | ok | 21.4 ms | - | (new) | — | — | — | — | — | — | — | — | — |
| FailoverFixture/IceConsentLossRecoveryDispatch/iterations:1000 | ok | 20 ns | - | — | — | — | — | 0 | 0 | 0 | 0 | — | 0 / 0 |
| FailoverFixture/RestartDispatchCost/iterations:1000 | ok | 73 ns | - | — | — | — | — | +32 KiB | +40 KiB | +128.0 MiB | 0 | 8 | 0 / 0 |
| HandlerRegistryFixture/HandlerChainDepth/1/real_time | ok | 21.0 μs | 2.90 MiB/s | (new) | 673.5 ns/B | — | — | +16 KiB | +16 KiB | 0 | +1.0 MiB | 4 | 79,873 / 98 |
| HandlerRegistryFixture/HandlerChainDepth/2/real_time | ok | 20.0 μs | 3.05 MiB/s | (new) | 644.8 ns/B | — | — | 0 | 0 | 0 | +1.3 MiB | — | 76,430 / 71 |
| HandlerRegistryFixture/HandlerChainDepth/4/real_time | ok | 20.9 μs | 2.92 MiB/s | (new) | 668.7 ns/B | — | — | 0 | 0 | 0 | -300 KiB | — | 82,225 / 97 |
| HandlerRegistryFixture/HandlerChainDepth/8/real_time | ok | 21.0 μs | 2.91 MiB/s | (new) | 675.2 ns/B | — | — | 0 | 0 | 0 | 0 | — | 75,164 / 39 |
| HandlerRegistryFixture/HandlerChainDepth/16/real_time | SKIP: chain depth exceeds max_chain_length=8 | — | - | (new) | — | — | — | — | — | — | — | — | — |
| HandlerRegistryFixture/HandlerChainDepth/32/real_time | SKIP: chain depth exceeds max_chain_length=8 | — | - | (new) | — | — | — | — | — | — | — | — | — |
| HandlerRegistryFixture/HandlerNamespaceFanout/1/16/real_time | SKIP: handlers_per_ns exceeds max_chain_length=8 | — | - | (new) | — | — | — | — | — | — | — | — | — |
| HandlerRegistryFixture/HandlerNamespaceFanout/4/4/real_time | ok | 22.8 μs | 2.68 MiB/s | (new) | 733.4 ns/B | — | — | +12 KiB | +12 KiB | 0 | -1.0 MiB | 3 | 71,428 / 107 |
| HandlerRegistryFixture/HandlerNamespaceFanout/16/1/real_time | ok | 25.8 μs | 2.37 MiB/s | (new) | 821.2 ns/B | — | — | 0 | 0 | 0 | 0 | — | 71,733 / 349 |
| HandlerRegistryFixture/HandlerNamespaceFanout/4/8/real_time | ok | 31.9 μs | 1.91 MiB/s | (new) | 1.01 μs/B | — | — | 0 | 0 | 0 | 0 | — | 55,831 / 184 |
| HandlerRegistryFixture/HandlerNamespaceFanout/8/4/real_time | ok | 27.3 μs | 2.24 MiB/s | (new) | 875.0 ns/B | — | — | 0 | 0 | 0 | +300 KiB | — | 64,477 / 79 |
| HandlerRegistryFixture/HandlerPriorityOrder/4/real_time | ok | 23.7 μs | - | (new) | — | — | — | +8 KiB | +8 KiB | 0 | 0 | 2 | 71,067 / 311 |
| HandlerRegistryFixture/HandlerPriorityOrder/8/real_time | ok | 23.3 μs | - | (new) | — | — | — | 0 | 0 | 0 | 0 | — | 71,047 / 82 |
| HandlerRegistryFixture/HandlerPriorityOrder/16/real_time | SKIP: chain depth exceeds max_chain_length=8 | — | - | (new) | — | — | — | — | — | — | — | — | — |
| HandlerRegistryFixture/RegistryConcurrentModify/2/real_time | ok | 25.7 μs | - | (new) | — | — | — | +4 KiB | +4 KiB | 0 | 0 | 1 | 186,911 / 136 |
| HandlerRegistryFixture/RegistryConcurrentModify/4/real_time | ok | 32.8 μs | - | (new) | — | — | — | +16 KiB | +16 KiB | 0 | -300 KiB | 4 | 199,202 / 1,623 |
| HandlerRegistryFixture/RegistryConcurrentModify/8/real_time | ok | 34.2 μs | - | (new) | — | — | — | +4 KiB | +4 KiB | 0 | 0 | 1 | 380,445 / 4,151 |
| IceFixture/ComposerConnectCidAllocation/iterations:100000 | ok | 146 ns | - | — | — | — | — | — | — | — | — | — | — |
| IceFixture/NominationMetricsLookup/iterations:100000 | ok | 19 ns | - | — | — | — | — | — | — | — | — | — | — |
| IceFixture/ComposerConnectFreshSession/iterations:64 | ok | 9.6 μs | - | — | — | — | — | — | — | — | — | — | — |
| IceFixture/CheckListRestartDispatch/iterations:100000 | ok | 18 ns | - | — | — | — | — | — | — | — | — | — | — |
| IpcFixture/Throughput/64/real_time | ok | 427 ns | 142.91 MiB/s | +40942681.2% improvement | 26.2 ns/B | — | — | +152.0 MiB | +151.9 MiB | +129.8 MiB | 0 | 39,249 | 322,471 / 258 |
| IpcFixture/Throughput/1024/real_time | ok | 884 ns | 1.08 GiB/s | +158057335.0% improvement | 2.23 ns/B | — | — | +689.7 MiB | +682.5 MiB | +575.9 MiB | 0 | 176,553 | 309,715 / 259 |
| IpcFixture/Throughput/8192/real_time | ok | 2.7 μs | 2.88 GiB/s | +99647324232.9% improvement | 1.45 ns/B | — | — | +967.0 MiB | +555.1 MiB | +313.4 MiB | 0 | 248,314 | 253,123 / 1,075 |
| IpcFixture/Throughput/65536/real_time | ok | 18.0 μs | 3.40 GiB/s | +20831055300.6% improvement | 0.85 ns/B | — | — | +1424.2 MiB | +892.4 MiB | +905.5 MiB | 0 | 364,580 | 116,620 / 809 |
| BM_NoiseHandshakeXX | ok | 259.1 μs | - | (new) | — | — | — | — | — | — | — | — | — |
| BM_NoiseHandshakeIK | ok | 319.8 μs | - | (new) | — | — | — | — | — | — | — | — | — |
| BM_NoiseTransportEncryptDecrypt/64 | ok | 527 ns | 117.00 MiB/s | (new) | 8.08 ns/B | — | — | 0 | 0 | 0 | 0 | — | 0 / 24 |
| BM_NoiseTransportEncryptDecrypt/1024 | ok | 3.8 μs | 254.97 MiB/s | (new) | 3.72 ns/B | — | — | 0 | 0 | 0 | 0 | — | 0 / 20 |
| BM_NoiseTransportEncryptDecrypt/8192 | ok | 29.0 μs | 271.00 MiB/s | (new) | 3.49 ns/B | — | — | 0 | 0 | 0 | 0 | — | 0 / 24 |
| BM_NoiseTransportEncryptDecrypt/65536 | ok | 224.7 μs | 279.89 MiB/s | (new) | 3.39 ns/B | — | — | +64 KiB | +64 KiB | 0 | 0 | 16 | 0 / 22 |
| QuicFixture/HandshakeTime/manual_time | ok | 22.2 ms | - | — | — | — | — | — | — | — | — | — | — |
| MultiConnFixture/FallbackThroughput/64/real_time | ok | 23.0 μs | - | (new) | — | — | — | — | — | — | — | — | — |
| MultiConnFixture/FallbackThroughput/1024/real_time | ok | 23.2 μs | - | (new) | — | — | — | — | — | — | — | — | — |
| MultiConnFixture/FallbackThroughput/8192/real_time | ok | 43.0 μs | - | (new) | — | — | — | — | — | — | — | — | — |
| StrategyFixture/PickerSelectsIpc/64/real_time | ok | 89 ns | - | (new) | — | — | — | — | — | — | — | — | — |
| StrategyFixture/PickerSelectsIpc/1024/real_time | ok | 94 ns | - | (new) | — | — | — | — | — | — | — | — | — |
| StrategyFixture/FlipOnRttDegradation/200/real_time | ok | 203 ns | - | (new) | — | — | — | — | — | — | — | — | — |
| HandoffFixture/NoiseSteady/64/real_time | ok | 16.1 μs | 3.79 MiB/s | (new) | — | 15.4 μs | 27.7 μs | — | — | — | — | — | — |
| HandoffFixture/NoiseSteady/1024/real_time | ok | 18.6 μs | 52.61 MiB/s | (new) | — | 17.6 μs | 33.1 μs | — | — | — | — | — | — |
| HandoffFixture/TriggerStep/1024/real_time | ok | 54.5 μs | - | (new) | — | — | — | — | — | — | — | — | — |
| FanoutFixture/Producers/1/real_time | ok | 57.8 μs | - | (new) | — | — | — | +64 KiB | +64 KiB | 0 | 0 | 16 | 347,479 / 14,655 |
| FanoutFixture/Producers/2/real_time | ok | 59.8 μs | - | (new) | — | — | — | +908 KiB | +908 KiB | 0 | 0 | 227 | 270,570 / 18,338 |
| FanoutFixture/Producers/4/real_time | ok | 62.1 μs | - | (new) | — | — | — | +1.1 MiB | +1.1 MiB | 0 | 0 | 283 | 251,101 / 21,112 |
| FanoutFixture/Producers/8/real_time | ok | 63.7 μs | - | (new) | — | — | — | +428 KiB | +2.6 MiB | 0 | 0 | 1,264 | 154,792 / 25,950 |
| FailoverFixture/IpcDrop/200/real_time | ok | 173 ns | - | (new) | — | — | — | — | — | — | — | — | — |
| MobilityFixture/LanShortcut/300/real_time | ok | 175 ns | - | (new) | — | — | — | — | — | — | — | — | — |
| SubprocessLinkFixture/HostCallRoundtrip/64/real_time | ok | 21.1 μs | 2.89 MiB/s | +14351959.7% improvement | 215.6 ns/B | — | — | 0 | 0 | 0 | +1.0 MiB | 1 | 78,628 / 28 |
| SubprocessLinkFixture/HostCallRoundtrip/1024/real_time | ok | 19.9 μs | 49.09 MiB/s | +225762414.8% improvement | 13.1 ns/B | — | — | +4 KiB | +4 KiB | 0 | +1.0 MiB | 4 | 79,206 / 28 |
| SubprocessLinkFixture/HostCallRoundtrip/8192/real_time | ok | 29.7 μs | 262.82 MiB/s | +897690775.4% improvement | 2.30 ns/B | — | — | 0 | 0 | 0 | +1.0 MiB | 8 | 59,464 / 26 |
| SubprocessHandlerFixture/HandlerHandleMessage/64/real_time | ok | 22.0 μs | 2.77 MiB/s | +12699122.7% improvement | 230.3 ns/B | — | — | 0 | 0 | 0 | +1.0 MiB | 3 | 80,328 / 154 |
| SubprocessHandlerFixture/HandlerHandleMessage/1024/real_time | ok | 20.9 μs | 46.64 MiB/s | +211701079.5% improvement | 13.4 ns/B | — | — | 0 | 0 | 0 | -1.0 MiB | 3 | 81,913 / 49 |
| SubprocessSecurityFixture/SecurityEncryptDecrypt/64/real_time | ok | 24.6 μs | 4.97 MiB/s | +19213573.7% improvement | 138.2 ns/B | — | — | 0 | 0 | 0 | 0 | 1 | 73,869 / 110 |
| SubprocessSecurityFixture/SecurityEncryptDecrypt/1024/real_time | ok | 26.1 μs | 74.76 MiB/s | +268474445.9% improvement | 9.43 ns/B | — | — | 0 | 0 | 0 | -1.0 MiB | 3 | 72,576 / 52 |
| TcpFixture/Throughput/64/real_time | ok | 347 ns | 175.88 MiB/s | +56570870.2% improvement | 16.0 ns/B | — | — | +133.6 MiB | +133.6 MiB | +67.1 MiB | -2.0 MiB | 34,441 | 106,961 / 222 |
| TcpFixture/Throughput/1024/real_time | ok | 599 ns | 1.59 GiB/s | +307965413.5% improvement | 1.79 ns/B | — | — | +1158.8 MiB | +1158.8 MiB | +1147.1 MiB | -2.0 MiB | 296,839 | 256,494 / 342 |
| TcpFixture/Throughput/8192/real_time | ok | 2.6 μs | 2.99 GiB/s | +133794647919.8% improvement | 0.98 ns/B | — | — | +1251.3 MiB | +206.6 MiB | 0 | -1.0 MiB | 320,321 | 153,753 / 420 |
| TcpFixture/Throughput/65536/real_time | ok | 17.0 μs | 3.58 GiB/s | +23295882382.2% improvement | 0.68 ns/B | — | — | +1509.7 MiB | +608.1 MiB | +711.9 MiB | +3.2 MiB | 387,260 | 67,868 / 176 |
| TcpFixture/LatencyRoundtrip/64/real_time | ok | 9.6 μs | - | — | — | 8.7 μs | 22.8 μs | +2.4 MiB | 0 | 0 | +92 KiB | 624 | 225,556 / 907 |
| TcpFixture/LatencyRoundtrip/1024/real_time | ok | 11.0 μs | - | — | — | 9.8 μs | 30.5 μs | +15.8 MiB | 0 | 0 | -92 KiB | 4,033 | 218,818 / 653 |
| TcpFixture/HandshakeTime/manual_time | ok | 53.1 μs | - | — | — | — | — | — | — | — | — | — | — |
| TcpScaleFixture/ConnectionCountScale/1/real_time | ok | 649 ns | 1.47 GiB/s | +2645622466.3% improvement | 1.63 ns/B | — | — | +608.9 MiB | +608.9 MiB | +578.8 MiB | 0 | 156,030 | 153,379 / 146 |
| TcpScaleFixture/ConnectionCountScale/10/real_time | ok | 1.2 μs | 822.94 MiB/s | +1698641516.5% improvement | 9.03 ns/B | — | — | +199.7 MiB | +199.7 MiB | +6.8 MiB | +1016 KiB | 52,280 | 137,120 / 3,389 |
| TcpScaleFixture/ConnectionCountScale/100/real_time | ok | 1.3 μs | 733.26 MiB/s | +1492959589.4% improvement | 9.68 ns/B | — | — | +295.3 MiB | +295.3 MiB | +259.0 MiB | +1012 KiB | 77,122 | 186,176 / 4,193 |
| TcpScaleFixture/ConnectionCountScale/1000/real_time | ok | 1.4 μs | 677.49 MiB/s | +1325365204.3% improvement | 10.2 ns/B | — | — | +189.9 MiB | +189.9 MiB | +128.0 MiB | +4.0 MiB | 48,618 | 139,610 / 4,780 |
| TcpScaleFixture/ConcurrentSaturation/1/iterations:1/real_time | ok | 1.9 μs | - | — | — | — | — | — | — | — | — | — | — |
| TcpScaleFixture/ConcurrentSaturation/2/iterations:1/real_time | ok | 1.6 μs | - | — | — | — | — | — | — | — | — | — | — |
| TcpScaleFixture/ConcurrentSaturation/4/iterations:1/real_time | ok | 1.8 μs | - | — | — | — | — | — | — | — | — | — | — |
| TcpScaleFixture/ConcurrentSaturation/8/iterations:1/real_time | ok | 2.2 μs | - | — | — | — | — | — | — | — | — | — | — |
| TcpScaleFixture/BackpressureSlowConsumer/2/iterations:1/real_time | ok | 2.00 s | - | — | — | — | — | +1.1 MiB | +1.1 MiB | 0 | +3.9 MiB | 276 | 546,668 / 870 |
| TcpScaleFixture/BackpressureSlowConsumer/8/iterations:1/real_time | ok | 2.00 s | - | — | — | — | — | +4.2 MiB | +4.3 MiB | +128.0 MiB | +20.8 MiB | 1,090 | 1,012,411 / 10,119 |
| TlsFixture/HandshakeTime/manual_time | ok | 3.6 ms | - | — | — | — | — | — | — | — | — | — | — |
| UdpFixture/Throughput/64/real_time | ok | 342 ns | 178.61 MiB/s | +54921676.8% improvement | 14.6 ns/B | — | — | +454.3 MiB | +424.4 MiB | +435.2 MiB | -2.0 MiB | 116,638 | 178,595 / 203 |
| UdpFixture/Throughput/512/real_time | ok | 464 ns | 1.03 GiB/s | +232150135.1% improvement | 2.00 ns/B | — | — | +696.2 MiB | +330.1 MiB | +324.4 MiB | 0 | 178,619 | 180,827 / 295 |
| UdpFixture/Throughput/1200/real_time | ok | 732 ns | 1.53 GiB/s | +222900861.0% improvement | 1.56 ns/B | — | — | +1753.3 MiB | +1132.3 MiB | +1029.7 MiB | -8 KiB | 449,611 | 329,047 / 510 |
| UdpFixture/EchoRoundtrip/64/real_time | ok | 28.1 μs | 2.17 MiB/s | +9250310.1% improvement | 1.09 μs/B | — | — | +32 KiB | 0 | 0 | -8 KiB | 8 | 122,569 / 215 |
| UdpFixture/EchoRoundtrip/512/real_time | ok | 29.3 μs | 16.65 MiB/s | +69822448.0% improvement | 136.3 ns/B | — | — | +40 KiB | 0 | 0 | +4 KiB | 10 | 111,382 / 253 |
| UdpFixture/EchoRoundtrip/1024/real_time | ok | 28.3 μs | 34.49 MiB/s | +142378252.9% improvement | 65.7 ns/B | — | — | +40 KiB | 0 | 0 | 0 | 10 | 107,573 / 196 |
| UdpFixture/EchoRoundtrip/1200/real_time | ok | 31.6 μs | 36.27 MiB/s | +147993500.1% improvement | 60.0 ns/B | — | — | +32 KiB | 0 | 0 | +1.0 MiB | 8 | 71,195 / 186 |
| UdpFixture/MtuBoundary/-1/real_time | ok | 799 ns | 1.40 GiB/s | (new) | 1.58 ns/B | — | — | +1451.8 MiB | 0 | 0 | -2.1 MiB | 371,659 | 310,138 / 393 |
| UdpFixture/MtuBoundary/0/real_time | ok | 799 ns | 1.40 GiB/s | (new) | 1.53 ns/B | — | — | +1587.6 MiB | 0 | +56.0 MiB | +976 KiB | 406,433 | 309,309 / 506 |
| UdpFixture/MtuBoundary/1/real_time | ok | 2 ns | - | (new) | — | — | — | 0 | 0 | 0 | -1.0 MiB | — | 1 / 0 |
| WsFixture/Throughput/64/real_time | ok | 486 ns | 125.71 MiB/s | +25203162.0% improvement | 25.0 ns/B | — | — | +79.1 MiB | +78.9 MiB | +56.2 MiB | -1.0 MiB | 20,550 | 230,896 / 141 |
| WsFixture/Throughput/1024/real_time | ok | 1.5 μs | 650.60 MiB/s | +48728984565.4% improvement | 4.87 ns/B | — | — | +222.5 MiB | +186.3 MiB | +146.9 MiB | 0 | 56,957 | 236,803 / 943 |
| WsFixture/Throughput/8192/real_time | ok | 6.0 μs | 1.28 GiB/s | +21097842141.2% improvement | 2.71 ns/B | — | — | +619.4 MiB | +399.3 MiB | +366.2 MiB | +2.4 MiB | 158,546 | 233,040 / 232 |
| WsFixture/EchoRoundtrip/64/real_time | ok | 29.9 μs | 2.04 MiB/s | +7106773.7% improvement | 1.12 μs/B | — | — | +3.1 MiB | +3.1 MiB | 0 | 0 | 790 | 112,965 / 135 |
| WsFixture/EchoRoundtrip/1024/real_time | ok | 37.8 μs | 25.85 MiB/s | +70947576.3% improvement | 78.8 ns/B | — | — | +21.0 MiB | +21.0 MiB | 0 | -1.0 MiB | 5,388 | 91,939 / 110 |
| WsFixture/EchoRoundtrip/8192/real_time | ok | 58.7 μs | 133.15 MiB/s | +252921725.6% improvement | 14.7 ns/B | — | — | +97.0 MiB | +88.2 MiB | +142.4 MiB | -400 KiB | 24,841 | 57,428 / 125 |
| WsFixture/EchoRoundtrip/65536/real_time | ok | 884.2 μs | 70.69 MiB/s | +28829254.5% improvement | 16.4 ns/B | — | — | +28.7 MiB | 0 | 0 | -1.4 MiB | 7,357 | 6,557 / 28 |
| WssFixture/HandshakeTime/iterations:5/manual_time | SKIP: server listen failed | — | - | (new) | — | — | — | — | — | — | — | — | — |

## Latency tail — P50 → P99.99 ladder

_Tail latency is the dimension that distinguishes an evenly-paced p2p stack from one that pauses on GC / strand-hop / allocator slow paths. A widening gap between P99 and P99.9 across rows is the signal — flat rows mean the bench body is uniformly fast. Cases with fewer than 10 000 samples report P99.99 == P99.9 by linear interpolation; the `samples` column makes the underlying N visible so operators can tell which rows have enough mass for the deepest tail. See `docs/perf/methodology.en.md` §4.4 for the fixture-by-fixture interpretation guide._

| Case | Samples | P50 | P95 | P99 | P99.9 | P99.99 |
|---|---|---|---|---|---|---|
| real:Tcp/TcpEcho/64/real_time | 19,471 | 19.4 μs | 29.6 μs | 47.0 μs | 85.2 μs | 638.1 μs |
| real:Tcp/TcpEcho/1024/real_time | 19,747 | 20.2 μs | 29.6 μs | 48.3 μs | 89.0 μs | 626.5 μs |
| real:Tcp/TcpEcho/8192/real_time | 12,273 | 34.8 μs | 48.8 μs | 71.8 μs | 122.8 μs | 533.6 μs |
| real:Tcp/TcpEcho/32768/real_time | 4,227 | 94.4 μs | 136.3 μs | 168.8 μs | 212.9 μs | 650.5 μs |
| real:TcpEcho/TcpEchoRoundtrip/64/real_time | 10,544 | 38.2 μs | 64.2 μs | 93.2 μs | 190.0 μs | 761.8 μs |
| real:TcpEcho/TcpEchoRoundtrip/1024/real_time | 8,874 | 42.8 μs | 66.7 μs | 101.0 μs | 241.9 μs | 896.9 μs |
| real:TcpEcho/TcpEchoRoundtrip/8192/real_time | 4,901 | 78.9 μs | 117.6 μs | 163.8 μs | 685.1 μs | 1.1 ms |
| real:TcpEcho/TcpEchoRoundtrip/32768/real_time | 1,979 | 202.2 μs | 275.7 μs | 346.1 μs | 803.9 μs | 835.1 μs |
| real:Udp/UdpEcho/64/real_time | 21,617 | 19.0 μs | 26.8 μs | 43.7 μs | 81.7 μs | 622.6 μs |
| real:Udp/UdpEcho/1024/real_time | 18,277 | 21.5 μs | 30.9 μs | 49.3 μs | 80.9 μs | 228.8 μs |
| real:UdpEcho/UdpEchoRoundtrip/64/real_time | 10,496 | 37.5 μs | 59.4 μs | 87.7 μs | 163.0 μs | 630.6 μs |
| real:UdpEcho/UdpEchoRoundtrip/1024/real_time | 8,529 | 41.7 μs | 62.5 μs | 97.3 μs | 174.8 μs | 611.1 μs |
| real:Ipc/IpcEcho/64/real_time | 26,429 | 15.2 μs | 20.9 μs | 32.5 μs | 89.3 μs | 609.0 μs |
| real:Ipc/IpcEcho/1024/real_time | 23,027 | 16.8 μs | 23.0 μs | 35.0 μs | 79.6 μs | 498.4 μs |
| real:Ipc/IpcEcho/8192/real_time | 10,189 | 34.0 μs | 44.3 μs | 64.5 μs | 145.8 μs | 647.6 μs |
| real:Ipc/IpcEcho/32768/real_time | 4,384 | 87.6 μs | 116.2 μs | 149.9 μs | 206.3 μs | 564.1 μs |
| real:IpcEcho/IpcEchoRoundtrip/64/real_time | 14,267 | 28.6 μs | 41.1 μs | 68.6 μs | 181.6 μs | 688.4 μs |
| real:IpcEcho/IpcEchoRoundtrip/1024/real_time | 11,631 | 33.2 μs | 44.9 μs | 69.3 μs | 145.2 μs | 649.7 μs |
| real:IpcEcho/IpcEchoRoundtrip/8192/real_time | 5,881 | 69.9 μs | 95.7 μs | 130.2 μs | 240.9 μs | 727.3 μs |
| real:IpcEcho/IpcEchoRoundtrip/32768/real_time | 2,162 | 186.3 μs | 223.3 μs | 270.1 μs | 821.2 μs | 834.7 μs |
| HandoffFixture/NoiseSteady/64/real_time | 27,729 | 15.4 μs | 19.5 μs | 27.7 μs | 69.4 μs | 475.0 μs |
| HandoffFixture/NoiseSteady/1024/real_time | 22,367 | 17.6 μs | 21.9 μs | 33.1 μs | 67.0 μs | 569.6 μs |
| TcpFixture/LatencyRoundtrip/64/real_time | 45,855 | 8.7 μs | 17.8 μs | 22.8 μs | 49.2 μs | 575.2 μs |
| TcpFixture/LatencyRoundtrip/1024/real_time | 42,759 | 9.8 μs | 21.9 μs | 30.5 μs | 60.2 μs | 689.2 μs |

## Real — production-shape echo (kernel + security + protocol)

_**Shape**: bench fixtures boot a real kernel, load the matching security provider (`gn.security.noise` for peer trust, `gn.security.null` for loopback per StackRegistry), and frame bytes through `gn.protocol.gnet`. Numbers match the cost an operator-facing `send()` actually incurs in production — compare against `rust-libp2p` (Noise XX + Yamux) and `iroh` (TLS 1.3 + QUIC) rows in `## Cross-implementation throughput` below for a fair real-vs-real stack-quality signal._

_Per-byte cost in this section reflects the full send path: protocol framing + AEAD encrypt + link write. Subtract the same-payload row from `## Parody` above to isolate the security + protocol overhead._

| Case | Status | Time | Throughput | Δ vs baseline | CPU/B | P50 lat | P99 lat | RSS Δ | RSS Peak Δ | VSZ Peak Δ | Sock Mem Δ | Minor Faults | Ctx Sw (vol/inv) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Tcp/TcpEcho/64/real_time | ok | 21.4 μs | 2.86 MiB/s | (new) | 682.0 ns/B | 19.4 μs | 47.0 μs | +164 KiB | +164 KiB | +268 KiB | +1.1 MiB | 74 | 77,920 / 104 |
| Tcp/TcpEcho/1024/real_time | ok | 21.4 μs | 45.53 MiB/s | (new) | 43.8 ns/B | 20.2 μs | 48.3 μs | +204 KiB | +204 KiB | +100 KiB | -1.0 MiB | 51 | 79,214 / 201 |
| Tcp/TcpEcho/8192/real_time | ok | 36.6 μs | 213.46 MiB/s | (new) | 8.56 ns/B | 34.8 μs | 71.8 μs | +108 KiB | +108 KiB | 0 | +840 KiB | 27 | 49,116 / 143 |
| Tcp/TcpEcho/32768/real_time | ok | 101.8 μs | 306.96 MiB/s | (new) | 5.65 ns/B | 94.4 μs | 168.8 μs | +8 KiB | +8 KiB | 0 | 0 | 2 | 26,472 / 157 |
| TcpEcho/TcpEchoRoundtrip/64/real_time | ok | 42.0 μs | 2.91 MiB/s | (new) | 717.7 ns/B | 38.2 μs | 93.2 μs | +96 KiB | +96 KiB | 0 | 0 | 24 | 74,115 / 199 |
| TcpEcho/TcpEchoRoundtrip/1024/real_time | ok | 46.8 μs | 41.73 MiB/s | (new) | 49.2 ns/B | 42.8 μs | 101.0 μs | +12 KiB | +12 KiB | 0 | 0 | 3 | 63,142 / 1,279 |
| TcpEcho/TcpEchoRoundtrip/8192/real_time | ok | 85.2 μs | 183.31 MiB/s | (new) | 10.4 ns/B | 78.9 μs | 163.8 μs | 0 | 0 | 0 | -1.0 MiB | — | 34,529 / 243 |
| TcpEcho/TcpEchoRoundtrip/32768/real_time | ok | 213.6 μs | 292.65 MiB/s | (new) | 6.39 ns/B | 202.2 μs | 346.1 μs | 0 | 0 | 0 | -1.5 MiB | — | 22,501 / 198 |
| Udp/UdpEcho/64/real_time | ok | 20.0 μs | 3.06 MiB/s | (new) | 647.8 ns/B | 19.0 μs | 43.7 μs | +228 KiB | +228 KiB | +256 KiB | 0 | 57 | 86,538 / 185 |
| Udp/UdpEcho/1024/real_time | ok | 22.6 μs | 43.25 MiB/s | (new) | 45.3 ns/B | 21.5 μs | 49.3 μs | +192 KiB | +192 KiB | 0 | +1.0 MiB | 48 | 73,170 / 149 |
| UdpEcho/UdpEchoRoundtrip/64/real_time | ok | 40.7 μs | 3.00 MiB/s | (new) | 691.9 ns/B | 37.5 μs | 87.7 μs | +208 KiB | +208 KiB | 0 | -1020 KiB | 52 | 73,734 / 234 |
| UdpEcho/UdpEchoRoundtrip/1024/real_time | ok | 45.1 μs | 43.33 MiB/s | (new) | 47.3 ns/B | 41.7 μs | 97.3 μs | +4 KiB | +4 KiB | 0 | 0 | 1 | 60,029 / 188 |
| Ipc/IpcEcho/64/real_time | ok | 16.3 μs | 3.75 MiB/s | (new) | 585.4 ns/B | 15.2 μs | 32.5 μs | +272 KiB | +272 KiB | 0 | 0 | 68 | 105,762 / 324 |
| Ipc/IpcEcho/1024/real_time | ok | 18.0 μs | 54.38 MiB/s | (new) | 39.5 ns/B | 16.8 μs | 35.0 μs | +232 KiB | +232 KiB | 0 | -1.0 MiB | 58 | 92,133 / 157 |
| Ipc/IpcEcho/8192/real_time | ok | 35.2 μs | 221.95 MiB/s | (new) | 8.57 ns/B | 34.0 μs | 64.5 μs | +88 KiB | +88 KiB | 0 | +1.0 MiB | 22 | 40,763 / 114 |
| Ipc/IpcEcho/32768/real_time | ok | 91.8 μs | 340.43 MiB/s | (new) | 5.27 ns/B | 87.6 μs | 149.9 μs | +12 KiB | +12 KiB | 0 | -4 KiB | 3 | 26,530 / 148 |
| IpcEcho/IpcEchoRoundtrip/64/real_time | ok | 31.2 μs | 3.91 MiB/s | (new) | 590.9 ns/B | 28.6 μs | 68.6 μs | +48 KiB | +48 KiB | 0 | +1.0 MiB | 12 | 100,419 / 464 |
| IpcEcho/IpcEchoRoundtrip/1024/real_time | ok | 35.4 μs | 55.14 MiB/s | (new) | 41.2 ns/B | 33.2 μs | 69.3 μs | +4 KiB | +4 KiB | 0 | 0 | 1 | 81,642 / 175 |
| IpcEcho/IpcEchoRoundtrip/8192/real_time | ok | 73.7 μs | 211.88 MiB/s | (new) | 9.63 ns/B | 69.9 μs | 130.2 μs | +12 KiB | +12 KiB | 0 | -1.0 MiB | 3 | 41,353 / 181 |
| IpcEcho/IpcEchoRoundtrip/32768/real_time | ok | 192.5 μs | 324.72 MiB/s | (new) | 5.94 ns/B | 186.3 μs | 270.1 μs | +32 KiB | +32 KiB | 0 | -1.0 MiB | 8 | 24,033 / 141 |

## Cost decomposition — production overhead at 1024 B payload

_For each plugin family present in both shapes, the row pairs the FASTEST parody measurement at this payload against the matching real-mode row and surfaces the cost of running through the production stack (security + protocol + kernel dispatch). `Overhead` is signed — negative means real-mode is slower than parody by that percentage, which is the expected direction. `Δ CPU/B` is the per-byte CPU cost the production layers add on top of raw transport._

| Plugin | Parody | Real | Overhead | CPU/B parody | CPU/B real | Δ CPU/B |
|---|---|---|---|---|---|---|
| TCP | 1.59 GiB/s | 45.53 MiB/s | -97.2% | 1.79 ns/B | 43.8 ns/B | 42.0 ns/B |
| TCP | 1.59 GiB/s | 41.73 MiB/s | -97.4% | 1.79 ns/B | 49.2 ns/B | 47.4 ns/B |
| UDP | 34.49 MiB/s | 43.25 MiB/s | +25.4% | 65.7 ns/B | 45.3 ns/B | — |
| UDP | 34.49 MiB/s | 43.33 MiB/s | +25.6% | 65.7 ns/B | 47.3 ns/B | — |
| IPC | 1.08 GiB/s | 54.38 MiB/s | -95.1% | 2.23 ns/B | 39.5 ns/B | 37.3 ns/B |
| IPC | 1.08 GiB/s | 55.14 MiB/s | -95.0% | 2.23 ns/B | 41.2 ns/B | 38.9 ns/B |

## Cross-implementation latency / handshake

| Stack | Metric | Mean | P50 | P99 |
|---|---|---|---|---|
| openssl s_client | handshake_ns | 22.0 ms | 21.3 ms | 28.1 ms |

## Cross-implementation throughput

_**Stack shapes** for the row that follows so the numbers aren't apples-to-oranges:_

| Stack | What's measured |
|---|---|
| `iperf3 TCP/UDP` | raw socket throughput, no security, no framing |
| `rust-libp2p` | Noise XX + Yamux + libp2p-stream (full mesh stack) |
| `iroh` | TLS 1.3 + QUIC + RPC open_bi per round |
| `GoodNet parody` | TcpLink/UdpLink/WsLink through a stub host_api — no security, no framing, matches `iperf3` shape |
| `GoodNet real` (planned) | full kernel: TcpLink + Noise + gnet protocol — matches `libp2p` shape |

| Stack | Metric | Throughput | Detail |
|---|---|---|---|
| iperf3 (raw TCP) | tcp_throughput_bps | 7.36 GiB/s | 3 s, 0 retr |
| iperf3 (raw UDP) | udp_throughput_bps | 119.21 MiB/s | 3 s, 0% lost |

## Binary sizes & deployment closure

_Release + LTO + mold. `Dynamic shipping` is what an operator copies to a host: the kernel binary plus N plugin `.so` files. `Static` is `make build-static` — every plugin's `.text` linked into the kernel binary. `Nix closure` is the worst-case `nix profile install` cost (transitive dependency tree, de-dup'd on real deployments via store sharing). `Docker image` uses `debian:bookworm-slim` as the glibc base (see `dist/Dockerfile.static`); a `scratch`-based musl build would land near ~5 MiB but needs a separate musl plugin port._

| Artifact | Size |
|---|---|
| Plugin `.so` files (sum, 16 files) | 5.15 MiB |

## Comparison stack weights

_Same axes as `## Binary sizes`, applied to every external stack the bench compares against. `Binary` is the executable on disk; `Lib closure` is the sum of every distinct `.so` the binary maps at runtime (from `ldd`, excluding `linux-vdso`). Rust stacks static-link their crates so `Binary` is the meaningful number and `Lib closure` is just glibc + libgcc_s + libm. C tools take the opposite shape — small binary, large library closure._

| Stack | Binary | Lib closure | Total |
|---|---|---|---|
| iperf3 (TCP/UDP throughput baseline) | 16.5 KiB | 12.16 MiB | **12.18 MiB** |
| socat (AF_UNIX echo baseline) | 565.4 KiB | 11.14 MiB | **11.69 MiB** |
| openssl CLI (handshake baseline) | 1.25 MiB | 11.11 MiB | **12.36 MiB** |

## dx_loc_hello_world_echo

_lower is better; raw LOC counted (comments + blank lines stripped) from each stack's canonical hello-echo example. rust stacks ship single-file examples (server column is the whole file, client=0)_

| stack | client | server | total |
|---|---|---|---|
| goodnet | 58 | 39 | 97 |
| openssl | 324 | 324 | 648 |
| libuv | 50 | 71 | 121 |
| libssh | 0 | 658 | 658 |
| rust-libp2p | 0 | 107 | 107 |
| iroh | 0 | 71 | 71 |
