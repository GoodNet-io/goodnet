// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_udp.cpp
/// @brief  UDP link plugin — datagram throughput + latency.
///
/// Datagram semantics differ from TCP: each `send` is one packet,
/// no inbuilt reassembly, no kernel-managed connection state. The
/// benchmark drives `composer_connect` (UDP composer keeps the
/// (peer-ip-port → cid) mapping so sequential sends route through
/// the same socket) and measures send + dispatch overhead.

#include "../bench_harness.hpp"

#include <plugins/links/udp/udp.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace {

using namespace gn::bench;
using gn::link::udp::UdpLink;
using namespace std::chrono_literals;

struct UdpFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State&) override {
        server = std::make_shared<UdpLink>();
        client = std::make_shared<UdpLink>();
        server->set_host_api(&server_kernel.api);
        client->set_host_api(&client_kernel.api);
    }
    void TearDown(::benchmark::State&) override {
        client->shutdown();
        server->shutdown();
        server.reset();
        client.reset();
    }

    BenchKernel              server_kernel;
    BenchKernel              client_kernel;
    std::shared_ptr<UdpLink> server;
    std::shared_ptr<UdpLink> client;
};

BENCHMARK_DEFINE_F(UdpFixture, Throughput)(::benchmark::State& state) {
    const std::size_t payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);

    /// Bind server side, learn the OS-assigned port via composer
    /// listen + listen_port introspection. Avoids the static-port
    /// race in TCP's bench.
    if (server->composer_listen("udp://127.0.0.1:0") != GN_OK) {
        state.SkipWithError("listen failed");
        return;
    }
    std::uint16_t server_port = 0;
    if (server->composer_listen_port(&server_port) != GN_OK
        || server_port == 0) {
        state.SkipWithError("listen port introspection failed");
        return;
    }

    gn_conn_id_t client_conn = GN_INVALID_ID;
    if (client->composer_connect(
            "udp://127.0.0.1:" + std::to_string(server_port),
            &client_conn) != GN_OK) {
        state.SkipWithError("composer_connect failed");
        return;
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

BENCHMARK_REGISTER_F(UdpFixture, Throughput)
    ->Arg(64)
    ->Arg(512)
    ->Arg(1200)   // typical PMTU floor we ship
    ->Arg(8192)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

// ── Echo round-trip throughput ─────────────────────────────────────
//
// Matches the methodology used by libp2p / iroh / nginx-quic external
// benches: client sends payload, server echoes back, client waits for
// echo, then repeats. Counts the round-trip bytes (payload_size per
// iteration — what the application actually transported). This gives
// a fair comparable against round-trip-only Rust P2P stacks; the
// one-way Throughput bench above remains for raw send-side cost.

struct EchoCounters {
    std::atomic<std::uint64_t> server_inbound{0};
    std::atomic<std::uint64_t> client_inbound{0};
    std::atomic<gn_conn_id_t>  server_conn{GN_INVALID_ID};
    UdpLink*                    server_link{nullptr};
};

static void on_server_data(void* user, gn_conn_id_t conn,
                            const std::uint8_t* bytes, std::size_t size) {
    auto* c = static_cast<EchoCounters*>(user);
    c->server_inbound.fetch_add(1, std::memory_order_release);
    /// Server-side echo: reflect the bytes back on the same composer
    /// cid. UdpLink::send under composer-mode looks up the peer in
    /// `composer_peers_`; the conn id was populated when the accept
    /// callback fired so this lookup hits.
    if (c->server_link) {
        (void)c->server_link->send(conn,
            std::span<const std::uint8_t>(bytes, size));
    }
}

static void on_server_accept(void* user, gn_conn_id_t conn,
                              const char* /*peer_uri*/) {
    auto* c = static_cast<EchoCounters*>(user);
    c->server_conn.store(conn, std::memory_order_release);
    if (c->server_link) {
        (void)c->server_link->composer_subscribe_data(
            conn, &on_server_data, user);
    }
}

static void on_client_data(void* user, gn_conn_id_t /*conn*/,
                            const std::uint8_t* /*bytes*/,
                            std::size_t /*size*/) {
    auto* c = static_cast<EchoCounters*>(user);
    c->client_inbound.fetch_add(1, std::memory_order_release);
}

BENCHMARK_DEFINE_F(UdpFixture, EchoRoundtrip)(::benchmark::State& state) {
    const std::size_t payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);

    EchoCounters counters;
    counters.server_link = server.get();

    gn_subscription_id_t accept_tok = 0;
    if (server->composer_subscribe_accept(
            &on_server_accept, &counters, &accept_tok) != GN_OK) {
        state.SkipWithError("server subscribe_accept failed");
        return;
    }
    if (server->composer_listen("udp://127.0.0.1:0") != GN_OK) {
        state.SkipWithError("listen failed");
        return;
    }
    std::uint16_t server_port = 0;
    if (server->composer_listen_port(&server_port) != GN_OK
        || server_port == 0) {
        state.SkipWithError("listen port introspection failed");
        return;
    }

    gn_conn_id_t client_conn = GN_INVALID_ID;
    if (client->composer_connect(
            "udp://127.0.0.1:" + std::to_string(server_port),
            &client_conn) != GN_OK) {
        state.SkipWithError("composer_connect failed");
        return;
    }
    if (client->composer_subscribe_data(
            client_conn, &on_client_data, &counters) != GN_OK) {
        state.SkipWithError("client subscribe_data failed");
        return;
    }

    /// Prime the round-trip — the first send triggers accept-bus on
    /// the server, which installs the per-conn data subscription.
    /// Subsequent datagrams take the steady-state echo path.
    (void)client->send(client_conn, std::span<const std::uint8_t>(payload));
    {
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        while (counters.client_inbound.load(std::memory_order_acquire) == 0) {
            if (std::chrono::steady_clock::now() > deadline) {
                state.SkipWithError("primer echo never reached client");
                return;
            }
            std::this_thread::sleep_for(std::chrono::microseconds{100});
        }
    }

    ResourceCounters res;
    res.snapshot_start();
    /// Tight busy-poll for the echo. wait_for's 5 ms tick collapses
    /// the round-trip rate to ~200 Hz; the bench needs ≥ 10 kHz to
    /// surface real loopback bandwidth. Spin-wait with a 1 μs yield
    /// keeps the rate honest at the cost of one extra core.
    for ([[maybe_unused]] auto _ : state) {
        const auto before = counters.client_inbound.load(
            std::memory_order_acquire);
        if (client->send(client_conn,
                std::span<const std::uint8_t>(payload)) != GN_OK) {
            state.SkipWithError("client send failed mid-loop");
            break;
        }
        const auto deadline = std::chrono::steady_clock::now() + 1s;
        while (counters.client_inbound.load(std::memory_order_acquire)
               == before) {
            if (std::chrono::steady_clock::now() > deadline) {
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

BENCHMARK_REGISTER_F(UdpFixture, EchoRoundtrip)
    ->Arg(64)
    ->Arg(512)
    ->Arg(1024)
    ->Arg(1200)  /// PMTU floor — last size that fits without fragmentation
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

}  // namespace
