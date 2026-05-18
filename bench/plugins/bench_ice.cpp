// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_ice.cpp
/// @brief  ICE link plugin — composer surface + ICE-specific perf.
///
/// ICE FSM internals (build_check_list, gather, nomination) are
/// strand-private; the public surface (`composer_connect`,
/// `restart_session`, `nomination_metrics`) is the only thing a
/// bench in this process can drive without spinning up a real
/// STUN server + a remote peer. Numbers reported here reflect the
/// kernel-thread dispatch cost on the cold call sites callers
/// invoke at session bring-up + restart time — useful as a
/// regression ratchet for mutex / map / atomic costs. Wire-level
/// numbers (real gather, nomination across hosts, NAT-pinhole
/// recovery) live in `tests/docker/ice-3node/` (#26).
///
/// Fixtures:
///
///   * ComposerConnectCidAllocation — per-call dispatch on the
///     idempotent fast path callers use to refresh a known cid.
///   * NominationMetricsLookup — strategy / consent path's poll
///     surface; lock-acquire + map lookup + atomic read.
///   * ComposerConnectFreshSession — per-call cost for a NEW
///     peer pk every iteration. Hits the slow path inside
///     `composer_connect` — IceSession construction + map
///     insertion. Iteration cap is hard-coded so the strand-side
///     gather pile doesn't outrun the bench loop and exhaust
///     UDP sockets / fds across millions of iterations.
///   * CheckListRestartDispatch — `restart_session` against a
///     composer cid (NOT_FOUND fast path, since `sessions_` and
///     `composer_sessions_` are separate maps). Pins the mutex /
///     map-find sequence so a regression there flags up.
///
/// Per-iteration `composer_connect` posts a `gather()` to the
/// session strand. The UdpLink carrier binds a real loopback UDP
/// socket on the first gather (subsequent sessions on the same
/// IceLink reuse the bound port). Auto-iter ramp at very high
/// iteration counts can outpace strand-side teardown; every
/// fixture that creates fresh sessions caps `Iterations()`
/// explicitly so the bench runs in a bounded window.

#include "../bench_harness.hpp"
#include "../carrier_bridges.hpp"

#include <plugins/links/ice/link_ice.hpp>
#include <plugins/links/udp/udp.hpp>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>

namespace {

using namespace gn::bench;
using gn::link::ice::IceLink;
using gn::link::udp::UdpLink;

constexpr const char* kPeerPkHex =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Build a synthetic 64-hex peer pk string from a sequential
/// index. Each iter that calls this with a different `i` lands a
/// fresh entry in the composer sessions map.
[[nodiscard]] std::string fresh_peer_pk(std::uint64_t i) {
    char buf[17] = {};
    std::snprintf(buf, sizeof(buf), "%016lx",
                  static_cast<unsigned long>(i));
    std::string out;
    out.reserve(64);
    out.append(buf, 16);
    out.append(48, '0');
    return out;
}

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

// ── Composer connect: idempotent fast path ───────────────────────────

BENCHMARK_DEFINE_F(IceFixture, ComposerConnectCidAllocation)
    (::benchmark::State& state) {
    const std::string uri = std::string("ice://") + kPeerPkHex;
    for (auto _ : state) {
        gn_conn_id_t cid = GN_INVALID_ID;
        (void)ice->composer_connect(uri, &cid);
        (void)cid;
    }
}

/// Hard-cap iterations: each call dispatches a strand post on the
/// first invocation (gather kicks in); auto-iter ramp at default
/// `--benchmark_min_time=0.3s` lands ~1M iterations and the strand
/// queue grows faster than it drains, eventually exhausting fds.
/// 100k iter is the balance — large enough that the per-iter
/// number converges, small enough that the strand drain keeps up.
BENCHMARK_REGISTER_F(IceFixture, ComposerConnectCidAllocation)
    ->Iterations(100'000)
    ->Unit(::benchmark::kNanosecond);

// ── Nomination-metrics read cost ─────────────────────────────────────

BENCHMARK_DEFINE_F(IceFixture, NominationMetricsLookup)
    (::benchmark::State& state) {
    const std::string uri = std::string("ice://") + kPeerPkHex;
    gn_conn_id_t cid = GN_INVALID_ID;
    (void)ice->composer_connect(uri, &cid);
    for (auto _ : state) {
        auto m = ice->nomination_metrics(cid);
        ::benchmark::DoNotOptimize(m);
    }
}

BENCHMARK_REGISTER_F(IceFixture, NominationMetricsLookup)
    ->Iterations(100'000)
    ->Unit(::benchmark::kNanosecond);

// ── Composer connect: fresh peer per iteration ───────────────────────

BENCHMARK_DEFINE_F(IceFixture, ComposerConnectFreshSession)
    (::benchmark::State& state) {
    std::uint64_t idx = 0;
    for (auto _ : state) {
        const std::string uri = std::string("ice://")
            + fresh_peer_pk(idx++);
        gn_conn_id_t cid = GN_INVALID_ID;
        (void)ice->composer_connect(uri, &cid);
        ::benchmark::DoNotOptimize(cid);
    }
    state.counters["fresh_sessions_allocated"] =
        static_cast<double>(idx);
}

BENCHMARK_REGISTER_F(IceFixture, ComposerConnectFreshSession)
    ->Unit(::benchmark::kMicrosecond)
    ->Iterations(64);

// ── CheckList restart-dispatch cost ──────────────────────────────────

BENCHMARK_DEFINE_F(IceFixture, CheckListRestartDispatch)
    (::benchmark::State& state) {
    const std::string uri = std::string("ice://") + kPeerPkHex;
    gn_conn_id_t cid = GN_INVALID_ID;
    (void)ice->composer_connect(uri, &cid);
    for (auto _ : state) {
        const auto rc = ice->restart_session(cid);
        ::benchmark::DoNotOptimize(rc);
    }
}

BENCHMARK_REGISTER_F(IceFixture, CheckListRestartDispatch)
    ->Iterations(100'000)
    ->Unit(::benchmark::kNanosecond);

}  // namespace
