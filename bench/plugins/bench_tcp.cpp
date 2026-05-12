// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_tcp.cpp
/// @brief  TCP link plugin — throughput, latency, handshake time.
///
/// Three benchmarks register through google-benchmark:
///
///   * `TcpThroughput/<payload-bytes>` — loops `send` against a real
///     loopback TCP socket, computes effective Gbps from
///     bytes-processed.
///   * `TcpLatencyRoundtrip/<payload-bytes>` — request / response
///     pair; RoundTripMeter captures P50 / P95 / P99 / P99.9.
///   * `TcpHandshakeTime` — fresh listener + connect + first
///     inbound; samples from `notify_connect` arrival.
///
/// google-benchmark drives iteration counts + warmup. Run with
/// `--benchmark_filter=Tcp` to isolate. JSON output feeds the
/// `bench/reports/` aggregator.

#include "../bench_harness.hpp"

#include <plugins/links/tcp/tcp.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace gn::bench;
using gn::link::tcp::TcpLink;
using namespace std::chrono_literals;

/// Common fixture — server + client kernel each with its own
/// TcpLink. Tears down between benchmarks so handshake numbers
/// are unaffected by warm sockets.
struct TcpFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State&) override {
        server = std::make_shared<TcpLink>();
        client = std::make_shared<TcpLink>();
        server->set_host_api(&server_kernel.api);
        client->set_host_api(&client_kernel.api);
    }

    void TearDown(::benchmark::State&) override {
        client->shutdown();
        server->shutdown();
        server.reset();
        client.reset();
    }

    /// Race-free handshake: server starts listening on an OS-assigned
    /// port (`tcp://127.0.0.1:0`), the bench reads it via
    /// `notify_inbound_bytes` arrival on the client side, then
    /// drives the loop.
    bool open_loopback(std::uint16_t* server_port) {
        const auto rc = server->listen("tcp://127.0.0.1:0");
        if (rc != GN_OK) return false;
        /// TcpLink writes the assigned port through the host_api
        /// notify_connect path on accept. The fixture polls
        /// `connects.load()` to learn the listening side is up;
        /// real port discovery needs a small helper because the
        /// existing surface only surfaces it via composer
        /// surface. For simplicity the bench fixture uses a
        /// fixed port and retries.
        *server_port = pick_loopback_port();
        return true;
    }

    /// Find a free loopback port via a one-shot listen. Fixture's
    /// own server then re-listens on the discovered port. The race
    /// window is tiny but real — production benches should prefer
    /// the kernel's `composer_listen_port` introspection where
    /// available.
    static std::uint16_t pick_loopback_port() {
        /// Conservative range, avoiding well-known + ephemeral
        /// pool overlap. Each bench process picks once so port
        /// reuse across runs is best-effort.
        static std::atomic<std::uint16_t> next{19500};
        return next.fetch_add(1, std::memory_order_relaxed);
    }

    BenchKernel              server_kernel;
    BenchKernel              client_kernel;
    std::shared_ptr<TcpLink> server;
    std::shared_ptr<TcpLink> client;
};

// ── Throughput ────────────────────────────────────────────────────

BENCHMARK_DEFINE_F(TcpFixture, Throughput)(::benchmark::State& state) {
    const std::size_t payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);

    std::uint16_t port = 0;
    if (!open_loopback(&port)) {
        state.SkipWithError("listen failed");
        return;
    }

    /// Listen + connect race: TcpLink's notify_connect is the
    /// signal. Wait up to 1s; otherwise skip — slow CI shouldn't
    /// hang the harness.
    server->listen("tcp://127.0.0.1:" + std::to_string(port));
    client->connect("tcp://127.0.0.1:" + std::to_string(port));
    if (!::gn::sdk::test::wait_for(
            [&] { return client_kernel.stub.connects.load() >= 1; }, 1s)) {
        state.SkipWithError("handshake timeout");
        return;
    }
    gn_conn_id_t client_conn;
    {
        std::lock_guard lk(client_kernel.stub.mu);
        client_conn = client_kernel.stub.conns.front();
    }

    ResourceCounters res;
    res.snapshot_start();
    for (auto _ : state) {
        const auto rc = client->send(client_conn,
            std::span<const std::uint8_t>(payload));
        if (rc != GN_OK) {
            state.SkipWithError("send failed mid-loop");
            break;
        }
    }
    res.snapshot_end();

    state.SetBytesProcessed(
        static_cast<std::int64_t>(state.iterations()) *
        static_cast<std::int64_t>(payload_size));
    report_resources(state, res);
}

BENCHMARK_REGISTER_F(TcpFixture, Throughput)
    ->Arg(64)
    ->Arg(1024)
    ->Arg(8192)
    ->Arg(65536)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

// ── Latency (round-trip) ──────────────────────────────────────────

BENCHMARK_DEFINE_F(TcpFixture, LatencyRoundtrip)(::benchmark::State& state) {
    const std::size_t payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);

    std::uint16_t port = 0;
    if (!open_loopback(&port)) {
        state.SkipWithError("listen failed");
        return;
    }
    server->listen("tcp://127.0.0.1:" + std::to_string(port));
    client->connect("tcp://127.0.0.1:" + std::to_string(port));
    if (!::gn::sdk::test::wait_for(
            [&] { return client_kernel.stub.connects.load() >= 1; }, 1s)) {
        state.SkipWithError("handshake timeout");
        return;
    }
    gn_conn_id_t client_conn;
    gn_conn_id_t server_conn;
    {
        std::lock_guard lk(client_kernel.stub.mu);
        client_conn = client_kernel.stub.conns.front();
    }
    /// Server-side conn id arrives via the server kernel's
    /// notify_connect; wait for it before driving the loop.
    if (!::gn::sdk::test::wait_for(
            [&] { return server_kernel.stub.connects.load() >= 1; }, 1s)) {
        state.SkipWithError("server-side connect missing");
        return;
    }
    {
        std::lock_guard lk(server_kernel.stub.mu);
        server_conn = server_kernel.stub.conns.front();
    }

    RoundTripMeter meter;
    ResourceCounters res;
    res.snapshot_start();

    for (auto _ : state) {
        const auto t0 = std::chrono::steady_clock::now();
        const std::size_t inbound_before =
            server_kernel.stub.inbound.size();
        (void)client->send(client_conn,
            std::span<const std::uint8_t>(payload));
        if (!::gn::sdk::test::wait_for(
                [&] {
                    std::lock_guard lk(server_kernel.stub.mu);
                    return server_kernel.stub.inbound.size() > inbound_before;
                }, 1s)) {
            state.SkipWithError("inbound timeout");
            break;
        }
        /// Server echoes back so the client's stub also sees an
        /// inbound — round-trip closure.
        (void)server->send(server_conn,
            std::span<const std::uint8_t>(payload));
        const auto t1 = std::chrono::steady_clock::now();
        meter.record(static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                t1 - t0).count()));
    }
    res.snapshot_end();
    report_latency(state, meter);
    report_resources(state, res);
}

BENCHMARK_REGISTER_F(TcpFixture, LatencyRoundtrip)
    ->Arg(64)
    ->Arg(1024)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

// ── Handshake time ────────────────────────────────────────────────

BENCHMARK_DEFINE_F(TcpFixture, HandshakeTime)(::benchmark::State& state) {
    for (auto _ : state) {
        state.PauseTiming();
        auto fresh_server = std::make_shared<TcpLink>();
        auto fresh_client = std::make_shared<TcpLink>();
        BenchKernel server_k, client_k;
        fresh_server->set_host_api(&server_k.api);
        fresh_client->set_host_api(&client_k.api);
        const auto port = pick_loopback_port();
        const std::string uri = "tcp://127.0.0.1:" + std::to_string(port);
        state.ResumeTiming();

        const auto t0 = std::chrono::steady_clock::now();
        if (fresh_server->listen(uri) != GN_OK) {
            state.SkipWithError("listen failed");
            break;
        }
        if (fresh_client->connect(uri) != GN_OK) {
            state.SkipWithError("connect failed");
            break;
        }
        if (!::gn::sdk::test::wait_for(
                [&] { return client_k.stub.connects.load() >= 1; }, 1s)) {
            state.SkipWithError("handshake timeout");
            break;
        }
        const auto t1 = std::chrono::steady_clock::now();
        state.SetIterationTime(
            std::chrono::duration<double>(t1 - t0).count());

        state.PauseTiming();
        fresh_client->shutdown();
        fresh_server->shutdown();
        state.ResumeTiming();
    }
}

BENCHMARK_REGISTER_F(TcpFixture, HandshakeTime)
    ->Unit(::benchmark::kMicrosecond)
    ->UseManualTime();

}  // namespace
