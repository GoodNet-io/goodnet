// SPDX-License-Identifier: Apache-2.0
/// @file   bench/strategy/bench_float_send_rtt.cpp
/// @brief  Multi-path strategy bench — float_send_rtt picker
///         under RTT skew.

#include "../bench_harness.hpp"

#include <plugins/strategies/float_send_rtt/float_send_rtt.hpp>
#include <sdk/extensions/strategy.h>

#include <chrono>
#include <cstdint>
#include <vector>

namespace {

using namespace gn::bench;
using gn::strategy::FloatSendRtt;

/// Picker dispatch overhead under increasing candidate-set size.
/// Strategy plugins live on the hot send path; benchmarking the
/// pick-conn microsecond budget surfaces O(N) scans vs O(1)
/// caching choices in future refactors.
static void BM_FloatSendRtt_PickConn(::benchmark::State& state) {
    const std::size_t candidate_count =
        static_cast<std::size_t>(state.range(0));

    FloatSendRtt picker;
    std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES] = {};

    std::vector<gn_path_sample_t> candidates(candidate_count);
    for (std::size_t i = 0; i < candidate_count; ++i) {
        candidates[i].conn          = static_cast<gn_conn_id_t>(i + 1);
        candidates[i].rtt_us        = 1000 + static_cast<std::uint64_t>(i) * 100;
        candidates[i].loss_pct_x100 = 0;
        candidates[i].caps          = 0;
    }

    /// Seed picker with one sample per cand to populate internal
    /// state (otherwise pick_conn cold-cache effects swamp the
    /// steady-state measurement).
    for (const auto& c : candidates) {
        gn_path_sample_t s = c;
        picker.on_path_event(peer_pk, GN_PATH_EVENT_RTT_UPDATE, &s);
    }

    for (auto _ : state) {
        gn_conn_id_t chosen = GN_INVALID_ID;
        (void)picker.pick_conn(peer_pk, candidates.data(),
                                 candidates.size(), &chosen);
        ::benchmark::DoNotOptimize(chosen);
    }
}

BENCHMARK(BM_FloatSendRtt_PickConn)
    ->Arg(2)
    ->Arg(4)
    ->Arg(8)
    ->Arg(16)
    ->Unit(::benchmark::kNanosecond);

}  // namespace
