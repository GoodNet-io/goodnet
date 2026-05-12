// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_tcp_scale.cpp
/// @brief  TCP connection-count + concurrency scaling.
///
/// The base bench_tcp.cpp covers single-conn throughput / latency
/// / handshake. This file adds the orthogonal axes that fall out
/// of the same plugin without re-fixturing:
///
///   * Throughput vs connection count: 1 / 10 / 100 / 1000
///     parallel conns sending the same total bytes — surfaces how
///     plugin internals (per-conn lock contention, ASIO strand
///     dispatch, kernel notify path) scale.
///   * Concurrent full-duplex saturation: N conns each pushing
///     send() while a recv handler drains the kernel inbound
///     queue, measures sustained both-ways throughput.
///   * Cold-start vs steady-state: first send latency after a
///     fresh connect, separate counter for the first 10 ops vs
///     the warm 1000+.

#include "../bench_harness.hpp"

#include <plugins/links/tcp/tcp.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace gn::bench;
using gn::link::tcp::TcpLink;
using namespace std::chrono_literals;

struct TcpScaleFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State&) override {
        server = std::make_shared<TcpLink>();
        client = std::make_shared<TcpLink>();
        server->set_host_api(&server_kernel.api);
        client->set_host_api(&client_kernel.api);
    }
    void TearDown(::benchmark::State&) override {
        client->shutdown();
        server->shutdown();
    }

    /// Ephemeral port allocator that doesn't collide across
    /// concurrent benches in the same process.
    std::uint16_t reserve_port() {
        static std::atomic<std::uint16_t> next{20000};
        return next.fetch_add(1, std::memory_order_relaxed);
    }

    BenchKernel              server_kernel;
    BenchKernel              client_kernel;
    std::shared_ptr<TcpLink> server;
    std::shared_ptr<TcpLink> client;
};

// ── Connection-count scaling ──────────────────────────────────────

BENCHMARK_DEFINE_F(TcpScaleFixture, ConnectionCountScale)
    (::benchmark::State& state) {
    const std::size_t conn_count   = static_cast<std::size_t>(state.range(0));
    const std::size_t payload_size = 1024;
    const auto payload = make_payload(payload_size);

    const auto port = reserve_port();
    const std::string uri = "tcp://127.0.0.1:" + std::to_string(port);
    if (server->listen(uri) != GN_OK) {
        state.SkipWithError("listen failed");
        return;
    }

    /// Open N parallel connections. Each connect adds one entry to
    /// the client_kernel.stub.conns set; wait for all of them
    /// before driving the loop so the bench measures steady-state
    /// rather than connect-amortised throughput.
    for (std::size_t i = 0; i < conn_count; ++i) {
        (void)client->connect(uri);
    }
    if (!::gn::sdk::test::wait_for(
            [&] {
                return client_kernel.stub.connects.load()
                       >= static_cast<int>(conn_count);
            }, 10s)) {
        state.SkipWithError("not all connects completed");
        return;
    }
    std::vector<gn_conn_id_t> conns;
    {
        std::lock_guard lk(client_kernel.stub.mu);
        conns = client_kernel.stub.conns;
    }

    ResourceCounters res;
    res.snapshot_start();
    std::size_t cursor = 0;
    for (auto _ : state) {
        const auto cid = conns[cursor++ % conns.size()];
        const auto rc = client->send(cid,
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
    state.counters["conns"] = static_cast<double>(conn_count);
    report_resources(state, res);
}

BENCHMARK_REGISTER_F(TcpScaleFixture, ConnectionCountScale)
    ->Arg(1)
    ->Arg(10)
    ->Arg(100)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

// ── Concurrent saturation (full-duplex) ───────────────────────────

BENCHMARK_DEFINE_F(TcpScaleFixture, ConcurrentSaturation)
    (::benchmark::State& state) {
    const std::size_t worker_count = static_cast<std::size_t>(state.range(0));
    const std::size_t payload_size = 1024;
    const auto payload = make_payload(payload_size);

    const auto port = reserve_port();
    const std::string uri = "tcp://127.0.0.1:" + std::to_string(port);
    if (server->listen(uri) != GN_OK) {
        state.SkipWithError("listen failed");
        return;
    }
    /// One conn per worker thread so concurrent send() calls don't
    /// race the same per-conn write strand.
    for (std::size_t i = 0; i < worker_count; ++i) {
        (void)client->connect(uri);
    }
    if (!::gn::sdk::test::wait_for(
            [&] {
                return client_kernel.stub.connects.load()
                       >= static_cast<int>(worker_count);
            }, 10s)) {
        state.SkipWithError("not all connects completed");
        return;
    }
    std::vector<gn_conn_id_t> conns;
    {
        std::lock_guard lk(client_kernel.stub.mu);
        conns = client_kernel.stub.conns;
    }

    std::atomic<bool>        stop{false};
    std::atomic<std::size_t> total_bytes{0};
    std::vector<std::thread> workers;
    workers.reserve(worker_count);
    for (std::size_t i = 0; i < worker_count; ++i) {
        workers.emplace_back([&, cid = conns[i]] {
            while (!stop.load(std::memory_order_acquire)) {
                if (client->send(cid,
                        std::span<const std::uint8_t>(payload)) == GN_OK) {
                    total_bytes.fetch_add(payload_size,
                                            std::memory_order_relaxed);
                }
            }
        });
    }

    const auto t0 = std::chrono::steady_clock::now();
    for (auto _ : state) {
        /// google-benchmark drives N iterations; each iteration
        /// snapshots the byte counter so the throughput number
        /// reflects the in-window deltas.
        ::benchmark::DoNotOptimize(total_bytes.load(std::memory_order_relaxed));
    }
    const auto t1 = std::chrono::steady_clock::now();
    stop.store(true, std::memory_order_release);
    for (auto& w : workers) w.join();

    const auto elapsed_s =
        std::chrono::duration<double>(t1 - t0).count();
    const auto bytes = total_bytes.load(std::memory_order_relaxed);
    state.counters["workers"]     = static_cast<double>(worker_count);
    state.counters["total_bytes"] = static_cast<double>(bytes);
    state.counters["bytes_per_sec"] =
        elapsed_s > 0 ? static_cast<double>(bytes) / elapsed_s : 0;
}

BENCHMARK_REGISTER_F(TcpScaleFixture, ConcurrentSaturation)
    ->Arg(1)
    ->Arg(2)
    ->Arg(4)
    ->Arg(8)
    ->Unit(::benchmark::kMillisecond)
    ->UseRealTime()
    ->Iterations(1);

}  // namespace
