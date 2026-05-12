// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_ws.cpp
/// @brief  WebSocket link plugin — frame overhead vs raw TCP.
///
/// WsLink is a kernel-mode L2 plugin that rides `gn.link.tcp`
/// internally. The bench harness exposes that carrier through the
/// BridgeHarness scaffolding from carrier_bridges.hpp.

#include "../bench_harness.hpp"
#include "../carrier_bridges.hpp"

#include <plugins/links/tcp/tcp.hpp>
#include <plugins/links/ws/ws.hpp>

#include <chrono>
#include <memory>
#include <span>
#include <string>

namespace {

using namespace gn::bench;
using gn::link::tcp::TcpLink;
using gn::link::ws::WsLink;
using namespace std::chrono_literals;

struct WsFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State&) override {
        server_h = std::make_unique<BridgeHarness<TcpLink>>("tcp");
        client_h = std::make_unique<BridgeHarness<TcpLink>>("tcp");
        server = std::make_shared<WsLink>();
        client = std::make_shared<WsLink>();
        server->set_host_api(&server_h->api);
        client->set_host_api(&client_h->api);
    }
    void TearDown(::benchmark::State&) override {
        client->shutdown();
        server->shutdown();
        client_h->bridge.plugin->shutdown();
        server_h->bridge.plugin->shutdown();
    }

    std::unique_ptr<BridgeHarness<TcpLink>> server_h;
    std::unique_ptr<BridgeHarness<TcpLink>> client_h;
    std::shared_ptr<WsLink>                 server;
    std::shared_ptr<WsLink>                 client;
};

BENCHMARK_DEFINE_F(WsFixture, Throughput)(::benchmark::State& state) {
    const std::size_t payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);

    if (server->listen("ws://127.0.0.1:0") != GN_OK) {
        state.SkipWithError("listen failed");
        return;
    }
    const auto port = server->listen_port();
    if (port == 0) {
        state.SkipWithError("listen_port returned 0");
        return;
    }
    if (client->connect("ws://127.0.0.1:" + std::to_string(port)) != GN_OK) {
        state.SkipWithError("connect failed");
        return;
    }
    /// WS handshake (HTTP upgrade) completes asynchronously; the
    /// client-side notify_connect fires after the 101 response
    /// parses.
    if (!::gn::sdk::test::wait_for(
            [&] { return client_h->kernel.stub.connects.load() >= 1; },
            5s)) {
        state.SkipWithError("handshake timeout");
        return;
    }
    gn_conn_id_t client_conn;
    {
        std::lock_guard lk(client_h->kernel.stub.mu);
        client_conn = client_h->kernel.stub.conns.front();
    }

    ResourceCounters res;
    res.snapshot_start();
    for ([[maybe_unused]] auto _ : state) {
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

BENCHMARK_REGISTER_F(WsFixture, Throughput)
    ->Arg(64)
    ->Arg(1024)
    ->Arg(8192)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

// ── Echo round-trip throughput ─────────────────────────────────────
//
// Same round-trip pattern as `UdpFixture::EchoRoundtrip` — fair
// compare against round-trip P2P stacks (libp2p, iroh). The WS
// frame overhead (2–14 bytes per frame) appears in the per-byte
// CPU cost; both directions carry the frame header.

BENCHMARK_DEFINE_F(WsFixture, EchoRoundtrip)(::benchmark::State& state) {
    const std::size_t payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);

    if (server->listen("ws://127.0.0.1:0") != GN_OK) {
        state.SkipWithError("listen failed");
        return;
    }
    const auto port = server->listen_port();
    if (port == 0) {
        state.SkipWithError("listen_port returned 0");
        return;
    }
    if (client->connect("ws://127.0.0.1:" + std::to_string(port)) != GN_OK) {
        state.SkipWithError("connect failed");
        return;
    }
    if (!::gn::sdk::test::wait_for(
            [&] {
                return client_h->kernel.stub.connects.load() >= 1
                    && server_h->kernel.stub.connects.load() >= 1;
            }, 5s)) {
        state.SkipWithError("handshake timeout");
        return;
    }
    gn_conn_id_t client_conn = GN_INVALID_ID;
    gn_conn_id_t server_conn = GN_INVALID_ID;
    {
        std::lock_guard lk(client_h->kernel.stub.mu);
        client_conn = client_h->kernel.stub.conns.front();
    }
    {
        std::lock_guard lk(server_h->kernel.stub.mu);
        server_conn = server_h->kernel.stub.conns.front();
    }

    ResourceCounters res;
    res.snapshot_start();
    for ([[maybe_unused]] auto _ : state) {
        const auto srv_before = server_h->kernel.stub.inbound_calls.load();
        const auto cli_before = client_h->kernel.stub.inbound_calls.load();

        if (client->send(client_conn,
                std::span<const std::uint8_t>(payload)) != GN_OK) {
            state.SkipWithError("client send failed mid-loop");
            break;
        }
        const auto deadline_a = std::chrono::steady_clock::now() + 1s;
        while (server_h->kernel.stub.inbound_calls.load() == srv_before) {
            if (std::chrono::steady_clock::now() > deadline_a) {
                state.SkipWithError("server inbound timeout");
                goto done;
            }
            std::this_thread::yield();
        }
        if (server->send(server_conn,
                std::span<const std::uint8_t>(payload)) != GN_OK) {
            state.SkipWithError("server echo send failed");
            break;
        }
        const auto deadline_b = std::chrono::steady_clock::now() + 1s;
        while (client_h->kernel.stub.inbound_calls.load() == cli_before) {
            if (std::chrono::steady_clock::now() > deadline_b) {
                state.SkipWithError("client echo timeout");
                goto done;
            }
            std::this_thread::yield();
        }
    }
done:
    res.snapshot_end();
    state.SetBytesProcessed(
        static_cast<std::int64_t>(state.iterations()) *
        static_cast<std::int64_t>(payload_size));
    report_resources(state, res);
}

BENCHMARK_REGISTER_F(WsFixture, EchoRoundtrip)
    ->Arg(64)
    ->Arg(1024)
    ->Arg(8192)
    ->Arg(65536)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

}  // namespace
