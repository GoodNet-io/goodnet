// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_dtls.cpp
/// @brief  DTLS link plugin — handshake + datagram throughput.

#include "../bench_harness.hpp"
#include "../carrier_bridges.hpp"

#include <plugins/links/tls/tls.hpp>
#include <plugins/links/udp/udp.hpp>
#include "../../plugins/links/tls/tests/support/test_self_signed_cert.hpp"

#include <chrono>
#include <memory>
#include <span>
#include <string>

namespace {

using namespace gn::bench;
using gn::link::tls::TlsLink;
using gn::link::udp::UdpLink;
using namespace std::chrono_literals;

struct DtlsFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State&) override {
        server_h = std::make_unique<BridgeHarness<UdpLink>>("udp");
        client_h = std::make_unique<BridgeHarness<UdpLink>>("udp");
        server_h->bridge.plugin->set_mtu(65000);
        client_h->bridge.plugin->set_mtu(65000);
        server = std::make_shared<TlsLink>();
        client = std::make_shared<TlsLink>();
        server->set_host_api(&server_h->api);
        client->set_host_api(&client_h->api);
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
    std::shared_ptr<TlsLink>                server;
    std::shared_ptr<TlsLink>                client;
};

BENCHMARK_DEFINE_F(DtlsFixture, HandshakeTime)(::benchmark::State& state) {
    for (auto _ : state) {
        if (server->composer_listen("dtls://127.0.0.1:0") != GN_OK) {
            state.SkipWithError("server listen failed");
            break;
        }
        std::uint16_t port = 0;
        if (server->composer_listen_port(&port) != GN_OK || port == 0) {
            state.SkipWithError("listen_port failed");
            break;
        }
        const auto t0 = std::chrono::steady_clock::now();
        gn_conn_id_t cconn = GN_INVALID_ID;
        if (client->composer_connect(
                "dtls://127.0.0.1:" + std::to_string(port), &cconn) != GN_OK) {
            state.SkipWithError("connect failed");
            break;
        }
        if (!::gn::sdk::test::wait_for(
                [&] { return server_h->kernel.stub.connects.load() >= 1; },
                5s)) {
            state.SkipWithError("handshake timeout");
            break;
        }
        const auto t1 = std::chrono::steady_clock::now();
        state.SetIterationTime(
            std::chrono::duration<double>(t1 - t0).count());
    }
}

BENCHMARK_REGISTER_F(DtlsFixture, HandshakeTime)
    ->Unit(::benchmark::kMicrosecond)
    ->UseManualTime()
    ->Iterations(10);

}  // namespace
