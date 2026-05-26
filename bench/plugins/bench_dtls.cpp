// SPDX-License-Identifier: Apache-2.0
/// @file    bench/plugins/bench_dtls.cpp
/// @brief   DTLS link plugin — handshake + datagram throughput.

#include "../bench_harness.hpp"
#include "../carrier_bridges.hpp"

#include <plugins/links/tls/tls.hpp>
#include <plugins/links/udp/udp.hpp>
#include "../../plugins/links/tls/tests/support/test_self_signed_cert.hpp"

#include <atomic>
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
    // Оставляем фикстуру пустой, так как весь жизненный цикл теперь внутри итерации
    void SetUp(::benchmark::State&) override {}
    void TearDown(::benchmark::State&) override {}
};

BENCHMARK_DEFINE_F(DtlsFixture, HandshakeTime)(::benchmark::State& state) {
    for (auto _ : state) {
        state.PauseTiming();
        
        // 1. Создаем изолированное окружение для текущей итерации
        auto sh = std::make_unique<BridgeHarness<UdpLink>>("udp");
        auto ch = std::make_unique<BridgeHarness<UdpLink>>("udp");
        sh->bridge.plugin->set_mtu(65000);
        ch->bridge.plugin->set_mtu(65000);

        auto fresh_server = std::make_shared<TlsLink>();
        auto fresh_client = std::make_shared<TlsLink>();
        
        fresh_server->set_host_api(&sh->api);
        fresh_client->set_host_api(&ch->api);
        fresh_client->set_verify_peer(false);

        std::string cert, key;
        if (gn::tests::support::generate_self_signed(cert, key)) {
            fresh_server->set_server_credentials(cert, key);
        }

        std::atomic<int> accept_count{0};
        gn_subscription_id_t accept_tok = 0;
        if (fresh_server->composer_subscribe_accept(
                +[](void* user, gn_conn_id_t, const char*) {
                    static_cast<std::atomic<int>*>(user)
                        ->fetch_add(1, std::memory_order_release);
                }, &accept_count, &accept_tok) != GN_OK) {
            state.SkipWithError("subscribe_accept failed");
            break;
        }
        
        state.ResumeTiming(); // Замеряем исключительно чистый хэндшейк
        const auto t0 = std::chrono::steady_clock::now();

        if (fresh_server->composer_listen("dtls://127.0.0.1:0") != GN_OK) {
            state.SkipWithError("server listen failed");
            break;
        }
        std::uint16_t port = 0;
        if (fresh_server->composer_listen_port(&port) != GN_OK || port == 0) {
            state.SkipWithError("listen_port failed");
            break;
        }
        gn_conn_id_t cconn = GN_INVALID_ID;
        if (fresh_client->composer_connect(
                "dtls://127.0.0.1:" + std::to_string(port), &cconn) != GN_OK) {
            state.SkipWithError("connect failed");
            break;
        }

        // Используем жесткий poll без уступки кванта планировщику ОС
        if (!::gn::sdk::test::wait_for_bench(
                [&] {
                    return accept_count.load(std::memory_order_acquire) >= 1;
                }, 5s)) {
            state.SkipWithError("handshake timeout");
            break;
        }

        const auto t1 = std::chrono::steady_clock::now();
        state.SetIterationTime(std::chrono::duration<double>(t1 - t0).count());

        state.PauseTiming();
        (void)fresh_server->composer_unsubscribe_accept(accept_tok);
        fresh_client->shutdown();
        fresh_server->shutdown();
        ch->bridge.plugin->shutdown();
        sh->bridge.plugin->shutdown();
        state.ResumeTiming();
    }
}

BENCHMARK_REGISTER_F(DtlsFixture, HandshakeTime)
    ->Unit(::benchmark::kMicrosecond)
    ->UseManualTime();

}  // namespace
