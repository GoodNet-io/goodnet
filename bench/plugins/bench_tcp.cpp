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
    /// google-benchmark calls the benchmark body MULTIPLE TIMES on
    /// the SAME fixture to converge on iteration counts; each call
    /// re-running listen + connect would stack 2N conns into the
    /// shared stub. Do the loopback bring-up exactly once and
    /// guard with `loopback_ready`.
    void SetUp(::benchmark::State&) override {
        if (loopback_ready) return;
        link = std::make_shared<TcpLink>();
        link->set_host_api(&kernel.api);
        if (link->listen("tcp://127.0.0.1:0") != GN_OK) return;
        const auto port = link->listen_port();
        if (port == 0) return;
        (void)link->connect("tcp://127.0.0.1:" + std::to_string(port));
        /// Wait for both sides on the same stub.
        if (!::gn::sdk::test::wait_for(
                [&] { return kernel.stub.connects.load() >= 2; }, 2s)) {
            return;
        }
        if (!::gn::sdk::test::wait_for(
                [&] {
                    return link->stats().active_connections >= 2;
                }, 1s)) {
            return;
        }
        {
            std::lock_guard lk(kernel.stub.mu);
            for (std::size_t i = 0; i < kernel.stub.conns.size(); ++i) {
                if (kernel.stub.roles[i] == GN_ROLE_INITIATOR) {
                    initiator_conn = kernel.stub.conns[i];
                    break;
                }
            }
        }
        loopback_ready = (initiator_conn != GN_INVALID_ID);
    }

    void TearDown(::benchmark::State&) override {
        if (!loopback_ready && !link) return;
        if (link) link->shutdown();
        link.reset();
        loopback_ready = false;
        initiator_conn = GN_INVALID_ID;
    }

    BenchKernel              kernel;
    std::shared_ptr<TcpLink> link;
    std::shared_ptr<TcpLink>& server = link;
    std::shared_ptr<TcpLink>& client = link;
    gn_conn_id_t             initiator_conn = GN_INVALID_ID;
    bool                     loopback_ready = false;
};

// ── Throughput ────────────────────────────────────────────────────

BENCHMARK_DEFINE_F(TcpFixture, Throughput)(::benchmark::State& state) {
    const std::size_t payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);

    if (!loopback_ready) {
        state.SkipWithError("loopback setup failed");
        return;
    }
    const gn_conn_id_t client_conn = initiator_conn;

    ResourceCounters res;
    res.snapshot_start();
    std::size_t sent_ok = 0;
    gn_result_t last_err = GN_OK;
    for (auto _ : state) {
        gn_result_t rc = client->send(client_conn,
            std::span<const std::uint8_t>(payload));
        if (rc == GN_OK) {
            ++sent_ok;
        } else {
            last_err = rc;
            /// Yield once per failed send so the kernel write
            /// pump can drain the per-conn queue. Per-iteration
            /// retries blow up wall-time for high-throughput
            /// payloads so a single yield is a reasonable
            /// compromise.
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
    }
    res.snapshot_end();
    state.counters["last_err"] = static_cast<double>(last_err);

    state.SetBytesProcessed(
        static_cast<std::int64_t>(sent_ok) *
        static_cast<std::int64_t>(payload_size));
    state.counters["sent_ok"] = static_cast<double>(sent_ok);
    state.counters["sent_skip"] =
        static_cast<double>(state.iterations() - sent_ok);
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

    if (!loopback_ready) {
        state.SkipWithError("loopback setup failed");
        return;
    }
    gn_conn_id_t client_conn = initiator_conn;
    gn_conn_id_t server_conn = GN_INVALID_ID;
    {
        std::lock_guard lk(kernel.stub.mu);
        for (std::size_t i = 0; i < kernel.stub.conns.size(); ++i) {
            if (kernel.stub.roles[i] == GN_ROLE_RESPONDER) {
                server_conn = kernel.stub.conns[i];
                break;
            }
        }
    }
    if (server_conn == GN_INVALID_ID) {
        state.SkipWithError("no responder conn found");
        return;
    }

    RoundTripMeter meter;
    ResourceCounters res;
    res.snapshot_start();

    for (auto _ : state) {
        const auto t0 = std::chrono::steady_clock::now();
        const std::size_t inbound_before =
            kernel.stub.inbound.size();
        (void)client->send(client_conn,
            std::span<const std::uint8_t>(payload));
        if (!::gn::sdk::test::wait_for(
                [&] {
                    std::lock_guard lk(kernel.stub.mu);
                    return kernel.stub.inbound.size() > inbound_before;
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
        state.ResumeTiming();

        const auto t0 = std::chrono::steady_clock::now();
        if (fresh_server->listen("tcp://127.0.0.1:0") != GN_OK) {
            state.SkipWithError("listen failed");
            break;
        }
        const auto port = fresh_server->listen_port();
        if (port == 0) {
            state.SkipWithError("listen_port == 0");
            break;
        }
        const std::string uri = "tcp://127.0.0.1:" + std::to_string(port);
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
