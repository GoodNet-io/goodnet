// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_quic.cpp
/// @brief  QUIC link plugin — handshake + steady-state over a UDP
///         carrier.

#include "../bench_harness.hpp"
#include "../carrier_bridges.hpp"

#include <plugins/links/quic/quic.hpp>
#include <plugins/links/udp/udp.hpp>
#include "../../plugins/links/tls/tests/support/test_self_signed_cert.hpp"

#include <chrono>
#include <memory>
#include <span>
#include <string>

namespace {

using namespace gn::bench;
using gn::link::quic::QuicLink;
using gn::link::udp::UdpLink;
using namespace std::chrono_literals;

struct QuicFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State&) override {
        server_h = std::make_unique<BridgeHarness<UdpLink>>("udp");
        client_h = std::make_unique<BridgeHarness<UdpLink>>("udp");
        /// QUIC handshake fragments routinely exceed the default
        /// UDP MTU; raise the cap so the bench measures QUIC
        /// behaviour rather than fragmentation rejection.
        server_h->bridge.plugin->set_mtu(65000);
        client_h->bridge.plugin->set_mtu(65000);
        server = std::make_shared<QuicLink>();
        client = std::make_shared<QuicLink>();
        server->set_host_api(&server_h->api);
        client->set_host_api(&client_h->api);
        server->set_verify_peer(false);
        client->set_verify_peer(false);
        std::string cert, key;
        if (gn::tests::support::generate_self_signed(cert, key)) {
            server->set_server_credentials(cert, key);
        }
    }
    void TearDown(::benchmark::State&) override {
        client->shutdown();
        server->shutdown();
        client_h->bridge.plugin->shutdown();
        server_h->bridge.plugin->shutdown();
    }

    std::unique_ptr<BridgeHarness<UdpLink>> server_h;
    std::unique_ptr<BridgeHarness<UdpLink>> client_h;
    std::shared_ptr<QuicLink>               server;
    std::shared_ptr<QuicLink>               client;
};

BENCHMARK_DEFINE_F(QuicFixture, HandshakeTime)(::benchmark::State& state) {
    for (auto _ : state) {
        state.PauseTiming();
        auto sh = std::make_unique<BridgeHarness<UdpLink>>("udp");
        auto ch = std::make_unique<BridgeHarness<UdpLink>>("udp");
        sh->bridge.plugin->set_mtu(65000);
        ch->bridge.plugin->set_mtu(65000);
        auto fresh_server = std::make_shared<QuicLink>();
        auto fresh_client = std::make_shared<QuicLink>();
        fresh_server->set_host_api(&sh->api);
        fresh_client->set_host_api(&ch->api);
        fresh_server->set_verify_peer(false);
        fresh_client->set_verify_peer(false);
        std::string cert, key;
        if (gn::tests::support::generate_self_signed(cert, key)) {
            fresh_server->set_server_credentials(cert, key);
        }
        state.ResumeTiming();

        const auto t0 = std::chrono::steady_clock::now();
        if (fresh_server->composer_listen("quic://127.0.0.1:0") != GN_OK) {
            state.SkipWithError("server listen failed");
            break;
        }
        std::uint16_t port = 0;
        if (fresh_server->composer_listen_port(&port) != GN_OK
            || port == 0) {
            state.SkipWithError("listen_port failed");
            break;
        }
        gn_conn_id_t cconn = GN_INVALID_ID;
        if (fresh_client->composer_connect(
                "quic://127.0.0.1:" + std::to_string(port), &cconn) != GN_OK) {
            state.SkipWithError("connect failed");
            break;
        }
        /// Composer accept-bus fires on server side when the QUIC
        /// handshake completes; signal arrives via the kernel stub.
        if (!::gn::sdk::test::wait_for(
                [&] { return sh->kernel.stub.connects.load() >= 1; },
                10s)) {
            state.SkipWithError("handshake timeout");
            break;
        }
        const auto t1 = std::chrono::steady_clock::now();
        state.SetIterationTime(
            std::chrono::duration<double>(t1 - t0).count());

        state.PauseTiming();
        fresh_client->shutdown();
        fresh_server->shutdown();
        ch->bridge.plugin->shutdown();
        sh->bridge.plugin->shutdown();
        state.ResumeTiming();
    }
}

BENCHMARK_REGISTER_F(QuicFixture, HandshakeTime)
    ->Unit(::benchmark::kMicrosecond)
    ->UseManualTime();

}  // namespace
