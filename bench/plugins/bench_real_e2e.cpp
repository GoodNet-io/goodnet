// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_real_e2e.cpp
/// @brief  Production-shape bench (A.2 from the master plan).
///
/// Every existing bench under `bench/plugins/*` wires a link plugin
/// to the `LinkStub` test fixture — no security provider, no
/// protocol layer. The numbers it produces are an upper bound, not
/// the cost an operator-facing `send()` actually pays. This file
/// closes that gap: it boots a real `gn::core::Kernel`, registers
/// the production security + protocol plugins (`gn.security.noise`
/// + `gn.protocol.gnet` + `gn.link.tcp`), and measures the same
/// echo round-trip the operator code path runs.
///
/// Case names carry the `RealFixture/` prefix so
/// `bench/comparison/reports/aggregate.py` routes them into the
/// `## Real — production-shape echo` section instead of mixing
/// them with the parody matrix.
///
/// ## Slice scope
///
/// Slice A.2 lands the **bench file scaffold**: registration shape,
/// fixture skeleton, case naming, and a deliberate
/// `SkipWithError("real-mode kernel boot pending")` body so the
/// build picks the cases up and `bench/comparison/runners/run_all.sh`
/// can include them in the report without producing garbage
/// numbers. The actual kernel-boot + plugin-load code is a
/// follow-up commit alongside `core/kernel/test_bench_helper.hpp`
/// (still to write) — see the TODO blocks in `setup` below.

#include "../bench_harness.hpp"

#include <benchmark/benchmark.h>

#include <cstdint>
#include <string>

namespace {

using namespace gn::bench;
using namespace std::chrono_literals;

/// Production-shape bench fixture. Each case spins a fresh kernel +
/// loaded plugins + a pair of peer handlers so the measurement
/// reflects steady-state operation against a warmed-up stack rather
/// than first-handshake cost.
///
/// TODO (A.2 follow-up):
/// - Embed a `gn::core::Kernel` instance and walk it through
///   `Init → Configured → Running` via `advance_to`.
/// - Load the three plugins as `OBJECT` libraries linked into the
///   bench binary (no `dlopen` — the same shape `tests/unit/` uses).
/// - Spin a loopback peer with its own identity + connection and
///   wire the `send/recv` echo loop through the kernel's
///   `host_api->send` slot.
/// - Pin RTT samples through `RoundTripMeter` and resource deltas
///   through `ResourceCounters` (the helpers in `bench_harness.hpp`).
struct RealFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State&) override {
        /// TODO: kernel boot. See file header.
    }
    void TearDown(::benchmark::State&) override {
        /// TODO: kernel shutdown.
    }
};

BENCHMARK_DEFINE_F(RealFixture, TcpEcho)(::benchmark::State& state) {
    /// Slice A.2 scaffold — every iteration short-circuits with an
    /// explicit error so a downstream report shows "real-mode case
    /// present but not yet implemented" instead of a fake zero.
    /// The aggregator's `## Real` section materialises on the first
    /// follow-up commit that completes the body below.
    state.SkipWithError("real-mode kernel boot pending (A.2 follow-up)");
    for (auto _ : state) {
        ::benchmark::DoNotOptimize(_);
    }
}

BENCHMARK_REGISTER_F(RealFixture, TcpEcho)
    ->Arg(64)
    ->Arg(1024)
    ->Arg(8192)
    ->Arg(65536)
    ->Unit(::benchmark::kMicrosecond)
    ->UseRealTime();

/// Mirror cases for the other transport families. They share the
/// same TODO once the kernel-boot helper exists; each gets its own
/// fixture in the follow-up so a single transport's regression
/// doesn't sink the rest of the matrix.
BENCHMARK_DEFINE_F(RealFixture, UdpEcho)(::benchmark::State& state) {
    state.SkipWithError("real-mode kernel boot pending (A.2 follow-up)");
    for (auto _ : state) { ::benchmark::DoNotOptimize(_); }
}
BENCHMARK_REGISTER_F(RealFixture, UdpEcho)
    ->Arg(64)->Arg(1024)->Arg(8192)
    ->Unit(::benchmark::kMicrosecond)->UseRealTime();

BENCHMARK_DEFINE_F(RealFixture, IpcEcho)(::benchmark::State& state) {
    state.SkipWithError("real-mode kernel boot pending (A.2 follow-up)");
    for (auto _ : state) { ::benchmark::DoNotOptimize(_); }
}
BENCHMARK_REGISTER_F(RealFixture, IpcEcho)
    ->Arg(64)->Arg(1024)->Arg(8192)->Arg(65536)
    ->Unit(::benchmark::kMicrosecond)->UseRealTime();

}  // namespace

BENCHMARK_MAIN();
