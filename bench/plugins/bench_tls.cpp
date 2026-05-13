// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_tls.cpp
/// @brief  TLS link plugin — encrypted handshake + steady-state
///         throughput / latency over a UDP-style memory pump.
///
/// The TLS plugin sits over a TCP carrier. The bench instantiates
/// a real TcpLink as the carrier so latency / throughput numbers
/// include the actual encryption overhead, not a synthetic memory
/// pump.

#include "../bench_harness.hpp"

#include <plugins/links/tcp/tcp.hpp>
#include <plugins/links/tls/tls.hpp>
#include "../../plugins/links/tls/tests/support/test_self_signed_cert.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>

namespace {

using namespace gn::bench;
using gn::link::tcp::TcpLink;
using gn::link::tls::TlsLink;
using namespace std::chrono_literals;

/// TLS needs `gn.link.tcp` exposed via host_api->query_extension.
/// Wrap the bench's BenchKernel + a TcpLink instance and route
/// `gn.link.tcp` queries to a manually-constructed vtable that
/// forwards into the TcpLink methods.
struct TlsHarness {
    BenchKernel    kernel;
    std::shared_ptr<TcpLink> tcp = std::make_shared<TcpLink>();
    gn_link_api_t            tcp_vt{};
    host_api_t               api{};

    TlsHarness() {
        tcp->set_host_api(&kernel.api);
        tcp_vt.api_size             = sizeof(tcp_vt);
        tcp_vt.get_capabilities     = &s_caps;
        tcp_vt.send                 = &s_send;
        tcp_vt.close                = &s_close;
        tcp_vt.listen               = &s_listen;
        tcp_vt.connect              = &s_connect;
        tcp_vt.subscribe_data       = &s_sub_data;
        tcp_vt.unsubscribe_data     = &s_unsub_data;
        tcp_vt.subscribe_accept     = &s_sub_accept;
        tcp_vt.unsubscribe_accept   = &s_unsub_accept;
        tcp_vt.composer_listen_port = &s_listen_port;
        tcp_vt.ctx                  = this;

        api = kernel.api;
        api.query_extension_checked = &s_query;
        api.host_ctx                = this;
    }

    static gn_result_t s_query(void* host_ctx, const char* name,
                                 std::uint32_t version, const void** out) {
        if (!out) return GN_ERR_NULL_ARG;
        *out = nullptr;
        if (version != GN_EXT_LINK_VERSION) return GN_ERR_NOT_FOUND;
        auto* h = static_cast<TlsHarness*>(host_ctx);
        if (std::string_view(name) == "gn.link.tcp") {
            *out = &h->tcp_vt;
            return GN_OK;
        }
        return GN_ERR_NOT_FOUND;
    }

    static gn_result_t s_caps(void*, gn_link_caps_t* out) {
        if (out) *out = TcpLink::capabilities();
        return GN_OK;
    }
    static gn_result_t s_send(void* ctx, gn_conn_id_t c,
                               const std::uint8_t* b, std::size_t n) {
        return static_cast<TlsHarness*>(ctx)->tcp->send(
            c, std::span<const std::uint8_t>(b, n));
    }
    static gn_result_t s_close(void* ctx, gn_conn_id_t c, int) {
        return static_cast<TlsHarness*>(ctx)->tcp->disconnect(c);
    }
    static gn_result_t s_listen(void* ctx, const char* uri) {
        return static_cast<TlsHarness*>(ctx)->tcp->composer_listen(uri);
    }
    static gn_result_t s_connect(void* ctx, const char* uri,
                                  gn_conn_id_t* out) {
        return static_cast<TlsHarness*>(ctx)->tcp->composer_connect(uri, out);
    }
    static gn_result_t s_sub_data(void* ctx, gn_conn_id_t c,
                                    gn_link_data_cb_t cb, void* u) {
        return static_cast<TlsHarness*>(ctx)
            ->tcp->composer_subscribe_data(c, cb, u);
    }
    static gn_result_t s_unsub_data(void* ctx, gn_conn_id_t c) {
        return static_cast<TlsHarness*>(ctx)->tcp->composer_unsubscribe_data(c);
    }
    static gn_result_t s_sub_accept(void* ctx, gn_link_accept_cb_t cb,
                                      void* u, gn_subscription_id_t* t) {
        return static_cast<TlsHarness*>(ctx)
            ->tcp->composer_subscribe_accept(cb, u, t);
    }
    static gn_result_t s_unsub_accept(void* ctx, gn_subscription_id_t t) {
        return static_cast<TlsHarness*>(ctx)->tcp->composer_unsubscribe_accept(t);
    }
    static gn_result_t s_listen_port(void* ctx, std::uint16_t* out) {
        return static_cast<TlsHarness*>(ctx)->tcp->composer_listen_port(out);
    }
};

struct TlsFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State&) override {
        server_harness = std::make_unique<TlsHarness>();
        client_harness = std::make_unique<TlsHarness>();
        server = std::make_shared<TlsLink>();
        client = std::make_shared<TlsLink>();
        server->set_host_api(&server_harness->api);
        client->set_host_api(&client_harness->api);
        client->set_verify_peer(false);

        std::string cert, key;
        if (gn::tests::support::generate_self_signed(cert, key)) {
            server->set_server_credentials(cert, key);
        }
    }
    void TearDown(::benchmark::State&) override {
        client->shutdown();
        server->shutdown();
        client_harness->tcp->shutdown();
        server_harness->tcp->shutdown();
    }

    std::unique_ptr<TlsHarness> server_harness;
    std::unique_ptr<TlsHarness> client_harness;
    std::shared_ptr<TlsLink>    server;
    std::shared_ptr<TlsLink>    client;
};

BENCHMARK_DEFINE_F(TlsFixture, HandshakeTime)(::benchmark::State& state) {
    for (auto _ : state) {
        state.PauseTiming();
        TlsHarness sh, ch;
        auto fresh_server = std::make_shared<TlsLink>();
        auto fresh_client = std::make_shared<TlsLink>();
        fresh_server->set_host_api(&sh.api);
        fresh_client->set_host_api(&ch.api);
        fresh_client->set_verify_peer(false);
        std::string cert, key;
        if (gn::tests::support::generate_self_signed(cert, key)) {
            fresh_server->set_server_credentials(cert, key);
        }
        state.ResumeTiming();

        const auto t0 = std::chrono::steady_clock::now();
        if (fresh_server->composer_listen("tls://127.0.0.1:0") != GN_OK) {
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
        const auto rc = fresh_client->composer_connect(
            "tls://127.0.0.1:" + std::to_string(port), &cconn);
        if (rc != GN_OK) {
            state.SkipWithError("connect failed");
            break;
        }
        /// Handshake completion observable through the accept-bus
        /// fire on the server. Wait for it, then record elapsed.
        if (!::gn::sdk::test::wait_for(
                [&] {
                    /// Indirect signal: server got an accept event.
                    return sh.kernel.stub.connects.load() >= 1;
                }, 5s)) {
            state.SkipWithError("handshake timeout");
            break;
        }
        const auto t1 = std::chrono::steady_clock::now();
        state.SetIterationTime(
            std::chrono::duration<double>(t1 - t0).count());

        state.PauseTiming();
        fresh_client->shutdown();
        fresh_server->shutdown();
        ch.tcp->shutdown();
        sh.tcp->shutdown();
        state.ResumeTiming();
    }
}

BENCHMARK_REGISTER_F(TlsFixture, HandshakeTime)
    ->Unit(::benchmark::kMicrosecond)
    ->UseManualTime();

}  // namespace
