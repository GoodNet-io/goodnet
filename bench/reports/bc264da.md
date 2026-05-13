# Benchmark report — bc264da

## GoodNet plugin matrix

| Case | Time | Throughput | P50 lat | P99 lat | RSS Delta |
|---|---|---|---|---|---|
| DtlsFixture/HandshakeTime/iterations:10/manual_time | — | - | — | — | - KB |
| IceFixture/ComposerConnectCidAllocation | 80 ns | - | — | — | - KB |
| IpcFixture/Throughput/64/real_time | — | - | — | — | - KB |
| IpcFixture/Throughput/1024/real_time | — | - | — | — | - KB |
| IpcFixture/Throughput/8192/real_time | — | - | — | — | - KB |
| IpcFixture/Throughput/65536/real_time | — | - | — | — | - KB |
| QuicFixture/HandshakeTime/manual_time | — | - | — | — | - KB |
| TcpFixture/Throughput/64/real_time | — | - | — | — | - KB |
| TcpFixture/Throughput/1024/real_time | — | - | — | — | - KB |
| TcpFixture/Throughput/8192/real_time | — | - | — | — | - KB |
| TcpFixture/Throughput/65536/real_time | — | - | — | — | - KB |
| TcpFixture/LatencyRoundtrip/64/real_time | — | - | — | — | - KB |
| TcpFixture/LatencyRoundtrip/1024/real_time | — | - | — | — | - KB |
| TcpFixture/HandshakeTime/manual_time | 5.1 ms | - | — | — | - KB |
| TlsFixture/HandshakeTime/manual_time | — | - | — | — | - KB |
| UdpFixture/Throughput/64/real_time | 372 ns | 163.87 MiB/s | — | — | 422100.0 KB |
| UdpFixture/Throughput/512/real_time | 557 ns | 876.43 MiB/s | — | — | 715940.0 KB |
| UdpFixture/Throughput/1200/real_time | 743 ns | 1.50 GiB/s | — | — | 1309544.0 KB |
| UdpFixture/Throughput/8192/real_time | — | - | — | — | - KB |
| WsFixture/Throughput/64/real_time | 537 ns | 113.65 MiB/s | — | — | 72412.0 KB |
| WsFixture/Throughput/1024/real_time | 2.0 μs | 494.64 MiB/s | — | — | 246412.0 KB |
| WsFixture/Throughput/8192/real_time | 7.1 μs | 1.08 GiB/s | — | — | 472848.0 KB |
| WssFixture/HandshakeTime/iterations:5/manual_time | — | - | — | — | - KB |

## dx_loc_hello_world_echo

_lower is better; raw LOC counted (comments + blank lines stripped) from each stack's canonical hello-echo example_

| stack | client | server | total |
|---|---|---|---|
| goodnet | 24 | 19 | 43 |
| openssl | 0 | 0 | 0 |
| libuv | 0 | 0 | 0 |
| libssh | 0 | 0 | 0 |
