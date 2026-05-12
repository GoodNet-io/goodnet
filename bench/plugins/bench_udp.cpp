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

BENCHMARK_REGISTER_F(UdpFixture, Throughput)
    ->Arg(64)
    ->Arg(512)
    ->Arg(1200)   // typical PMTU floor we ship
    ->Arg(8192)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

}  // namespace
