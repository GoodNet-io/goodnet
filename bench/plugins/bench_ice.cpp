// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_ice.cpp
/// @brief  ICE link plugin — composer surface overhead.
///
/// ICE needs ICE signalling exchanged out-of-band before the FSM
/// reaches Connected. Without a real STUN server + signalling
/// transport this bench measures only the URI / cid allocation
/// path (composer_connect / composer_listen / composer_listen_port
/// + send-no-route disposition). That captures plugin surface
/// overhead that a full E2E run would otherwise hide.

#include "../bench_harness.hpp"
#include "../carrier_bridges.hpp"

#include <plugins/links/ice/link_ice.hpp>
#include <plugins/links/udp/udp.hpp>

#include <chrono>
#include <memory>
#include <string>

namespace {

using namespace gn::bench;
using gn::link::ice::IceLink;
using gn::link::udp::UdpLink;

constexpr const char* kPeerPkHex =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct IceFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State&) override {
        harness = std::make_unique<BridgeHarness<UdpLink>>("udp");
        ice     = std::make_shared<IceLink>();
        ice->set_host_api(&harness->api);
    }
    void TearDown(::benchmark::State&) override {
        ice->shutdown();
        harness->bridge.plugin->shutdown();
    }

    std::unique_ptr<BridgeHarness<UdpLink>> harness;
    std::shared_ptr<IceLink>                ice;
};

BENCHMARK_DEFINE_F(IceFixture, ComposerConnectCidAllocation)
    (::benchmark::State& state) {
    const std::string uri = std::string("ice://") + kPeerPkHex;
    for (auto _ : state) {
        gn_conn_id_t cid = GN_INVALID_ID;
        (void)ice->composer_connect(uri, &cid);
        /// composer_connect is idempotent per peer pk; sequential
        /// calls return the same cid. The bench measures call-site
        /// dispatch + lookup, not actual session allocation per
        /// iteration.
        (void)cid;
    }
}

BENCHMARK_REGISTER_F(IceFixture, ComposerConnectCidAllocation)
    ->Unit(::benchmark::kNanosecond);

}  // namespace
