// SPDX-License-Identifier: Apache-2.0
/// @file   bench/composition/bench_wss_over_tls.cpp
/// @brief  Composition depth-3: WSS = WS over TLS over TCP.
///
/// Mirrors test_ws_wss.cpp loopback wiring: two BridgeHarnesses,
/// one per layer (TLS over TCP, WS over TLS). WSS handshake time
/// is the headline metric — surfaces depth-3 composition overhead
/// versus depth-2 TLS-over-TCP.

#include "../bench_harness.hpp"
#include "../carrier_bridges.hpp"

#include <plugins/links/tcp/tcp.hpp>
#include <plugins/links/tls/tls.hpp>
#include <plugins/links/ws/ws.hpp>
#include "../../plugins/links/tls/tests/support/test_self_signed_cert.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <string_view>

namespace {

using namespace gn::bench;
using gn::link::tcp::TcpLink;
using gn::link::tls::TlsLink;
using gn::link::ws::WsLink;
using namespace std::chrono_literals;

/// Two-layer harness: WsLink queries gn.link.tls, TlsLink queries
/// gn.link.tcp. Both bridges live behind one host_api whose
/// query_extension_checked resolves either name to the matching
/// vtable. Keeps the composition explicit so future depth-N stacks
/// follow the same pattern.
struct WssHarness {
    BenchKernel               kernel;
    CarrierBridge<TcpLink>    tcp;
    CarrierBridge<TlsLink>    tls;
    host_api_t                api{};

    WssHarness() {
        tcp.plugin->set_host_api(&kernel.api);

        /// TLS needs its own host_api shaped to find gn.link.tcp
        /// before set_host_api is called; chain two layers of api
        /// where the inner layer exposes gn.link.tcp and the
        /// outer layer exposes gn.link.tls.
        static host_api_t tls_inner_api;
        tls_inner_api = kernel.api;
        tls_inner_api.query_extension_checked = &s_query_tcp;
        tls_inner_api.host_ctx                = this;
        tls.plugin->set_host_api(&tls_inner_api);

        api = kernel.api;
        api.query_extension_checked = &s_query_tls;
        api.host_ctx                = this;
    }

    static gn_result_t s_query_tcp(void* host_ctx, const char* name,
                                     std::uint32_t version,
                                     const void** out) {
        if (!out) return GN_ERR_NULL_ARG;
        *out = nullptr;
        if (version != GN_EXT_LINK_VERSION) return GN_ERR_NOT_FOUND;
        auto* h = static_cast<WssHarness*>(host_ctx);
        if (std::string_view(name) == "gn.link.tcp") {
            *out = &h->tcp.vt;
            return GN_OK;
        }
        return GN_ERR_NOT_FOUND;
    }
    static gn_result_t s_query_tls(void* host_ctx, const char* name,
                                     std::uint32_t version,
                                     const void** out) {
        if (!out) return GN_ERR_NULL_ARG;
        *out = nullptr;
        if (version != GN_EXT_LINK_VERSION) return GN_ERR_NOT_FOUND;
        auto* h = static_cast<WssHarness*>(host_ctx);
        if (std::string_view(name) == "gn.link.tls") {
            *out = &h->tls.vt;
            return GN_OK;
        }
        if (std::string_view(name) == "gn.link.tcp") {
            *out = &h->tcp.vt;
            return GN_OK;
        }
        return GN_ERR_NOT_FOUND;
    }
};

struct WssFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State&) override {
        server_h = std::make_unique<WssHarness>();
        client_h = std::make_unique<WssHarness>();
        server = std::make_shared<WsLink>();
        client = std::make_shared<WsLink>();
        server->set_host_api(&server_h->api);
        client->set_host_api(&client_h->api);

        /// Each layer needs its own cert / verify config. TLS
        /// server credentials live on the server-side TlsLink
        /// instance; client verify gets relaxed for the loopback.
        std::string cert, key;
        if (gn::tests::support::generate_self_signed(cert, key)) {
            server_h->tls.plugin->set_server_credentials(cert, key);
        }
        client_h->tls.plugin->set_verify_peer(false);
    }
    void TearDown(::benchmark::State&) override {
        client->shutdown();
        server->shutdown();
        client_h->tls.plugin->shutdown();
        server_h->tls.plugin->shutdown();
        client_h->tcp.plugin->shutdown();
        server_h->tcp.plugin->shutdown();
    }

    std::unique_ptr<WssHarness> server_h;
    std::unique_ptr<WssHarness> client_h;
    std::shared_ptr<WsLink>     server;
    std::shared_ptr<WsLink>     client;
};

BENCHMARK_DEFINE_F(WssFixture, HandshakeTime)(::benchmark::State& state) {
    for (auto _ : state) {
        if (server->listen("wss://127.0.0.1:0") != GN_OK) {
            state.SkipWithError("server listen failed");
            break;
        }
        const auto port = server->listen_port();
        if (port == 0) {
            state.SkipWithError("listen_port == 0");
            break;
        }
        const auto t0 = std::chrono::steady_clock::now();
        if (client->connect(
                "wss://127.0.0.1:" + std::to_string(port)) != GN_OK) {
            state.SkipWithError("client connect failed");
            break;
        }
        if (!::gn::sdk::test::wait_for(
                [&] { return client_h->kernel.stub.connects.load() >= 1; },
                10s)) {
            state.SkipWithError("WSS handshake timeout");
            break;
        }
        const auto t1 = std::chrono::steady_clock::now();
        state.SetIterationTime(
            std::chrono::duration<double>(t1 - t0).count());
    }
}

BENCHMARK_REGISTER_F(WssFixture, HandshakeTime)
    ->Unit(::benchmark::kMicrosecond)
    ->UseManualTime()
    ->Iterations(5);

}  // namespace
