// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_sustained.cpp
/// @brief  Sustained-burn fixture — long-tail issues 0.3s benches hide.
///
/// Most bench fixtures run for 0.3 seconds. A burn of that length
/// cannot expose:
///
///   * thermal throttle (CPU frequency drops after ~20s of sustained
///     load on a typical laptop);
///   * allocator slowdown across many GC cycles
///     (`tcmalloc::CentralCache::Free` cost grows with arena age);
///   * connection-state leak under high churn (file descriptor /
///     socket-buffer accumulation invisible to the
///     `state.iterations()` accounting);
///   * long-tail GC / strand-hop pauses that a 0.3s window never
///     samples.
///
/// `TcpThroughput60s` runs the throughput body for ~60 seconds with
/// a windowed-average sampler at 5-second intervals. The fixture
/// reports the median window throughput plus the worst-case window's
/// deviation from median. If any window is >15% slower than the
/// median the bench flags the row through a counter that
/// `aggregate.py` surfaces in the report.

#include "../bench_harness.hpp"

#include <plugins/links/tcp/tcp.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include <algorithm>

namespace {

using namespace gn::bench;
using gn::link::tcp::TcpLink;
using namespace std::chrono_literals;

/// The shape of a single sampling window. Throughput is measured by
/// counting `send()` calls that returned GN_OK over the window's
/// wall-clock duration; the bench body uses google-benchmark for
/// reporting but the bench-internal windowing is independent.
struct WindowSample {
    std::uint64_t                          sends_ok          = 0;
    std::uint64_t                          sends_err         = 0;
    std::uint64_t                          sends_backpressure = 0;
    std::chrono::nanoseconds               duration{0};
    std::uint64_t                          bytes_sent        = 0;
};

struct SustainedFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State&) override {
        if (loopback_ready) return;
        link = std::make_shared<TcpLink>();
        link->set_host_api(&kernel.api);
        if (link->listen("tcp://127.0.0.1:0") != GN_OK) return;
        const auto port = link->listen_port();
        if (port == 0) return;
        const int connects_before = kernel.stub.connects.load();
        const std::size_t conns_before = [&] {
            std::lock_guard lk(kernel.stub.mu);
            return kernel.stub.conns.size();
        }();
        (void)link->connect("tcp://127.0.0.1:"
                              + std::to_string(port));
        if (!::gn::sdk::test::wait_for(
                [&] {
                    return kernel.stub.connects.load() - connects_before >= 2;
                }, 2s)) {
            return;
        }
        if (!::gn::sdk::test::wait_for(
                [&] {
                    return link->stats().active_connections >= 2;
                }, 1s)) {
            return;
        }
        {
            std::lock_guard lk(kernel.stub.mu);
            for (std::size_t i = conns_before;
                 i < kernel.stub.conns.size(); ++i) {
                if (kernel.stub.roles[i] == GN_ROLE_INITIATOR) {
                    initiator_conn = kernel.stub.conns[i];
                    break;
                }
            }
        }
        loopback_ready = (initiator_conn != GN_INVALID_ID);
    }
    void TearDown(::benchmark::State&) override {
        if (!loopback_ready && !link) return;
        if (link) link->shutdown();
        link.reset();
        loopback_ready = false;
        initiator_conn = GN_INVALID_ID;
    }

    BenchKernel              kernel;
    std::shared_ptr<TcpLink> link;
    gn_conn_id_t             initiator_conn = GN_INVALID_ID;
    bool                     loopback_ready = false;
};

BENCHMARK_DEFINE_F(SustainedFixture, TcpThroughput60s)
    (::benchmark::State& state) {
    constexpr std::size_t kPayloadBytes  = 1024;
    constexpr auto        kTotalDuration = 60s;
    constexpr auto        kWindowLength  = 5s;
    /// Threshold for flagging a window as "long-tail slow" relative
    /// to the run's median throughput.
    constexpr double      kDeviationFlag = 0.15;

    if (!loopback_ready) {
        state.SkipWithError("loopback setup failed");
        return;
    }
    const gn_conn_id_t client_conn = initiator_conn;
    const auto payload = make_payload(kPayloadBytes);

    ResourceCounters res;
    res.snapshot_start();
    std::vector<WindowSample> windows;
    windows.reserve(static_cast<std::size_t>(
        kTotalDuration / kWindowLength) + 1);

    const auto t_run_start = std::chrono::steady_clock::now();
    auto t_window_start    = t_run_start;
    WindowSample current{};

    /// The benchmark loop is driven by google-benchmark's
    /// `state.iterations()` machinery; we set `Iterations(1)` so the
    /// body runs once and the internal loop owns the 60s window.
    for ([[maybe_unused]] auto _ : state) {
        while (true) {
            const auto t_now = std::chrono::steady_clock::now();
            if (t_now - t_run_start >= kTotalDuration) break;
            const auto rc = link->send(client_conn,
                std::span<const std::uint8_t>(payload));
            if (rc == GN_OK) {
                ++current.sends_ok;
                current.bytes_sent += kPayloadBytes;
            } else if (rc == GN_ERR_LIMIT_REACHED) {
                ++current.sends_backpressure;
                std::this_thread::sleep_for(10us);
            } else {
                ++current.sends_err;
                std::this_thread::sleep_for(10us);
            }
            const auto t_window_end =
                std::chrono::steady_clock::now();
            if (t_window_end - t_window_start >= kWindowLength) {
                current.duration =
                    std::chrono::duration_cast<
                        std::chrono::nanoseconds>(
                            t_window_end - t_window_start);
                windows.push_back(current);
                current        = WindowSample{};
                t_window_start = t_window_end;
            }
        }
    }
    res.snapshot_end();
    /// Final partial window not counted toward median analysis —
    /// short final windows skew the median toward the run's tail.
    state.SetBytesProcessed(0);  // bytes counted via windows below

    /// Median + tail-deviation summary.
    std::vector<double> window_bps;
    window_bps.reserve(windows.size());
    std::uint64_t total_bytes = 0;
    std::uint64_t total_sends_ok = 0;
    std::uint64_t total_backpressure = 0;
    for (const auto& w : windows) {
        if (w.duration.count() > 0) {
            const double secs =
                static_cast<double>(w.duration.count()) / 1e9;
            window_bps.push_back(
                static_cast<double>(w.bytes_sent) / secs);
            total_bytes       += w.bytes_sent;
            total_sends_ok    += w.sends_ok;
            total_backpressure += w.sends_backpressure;
        }
    }
    std::size_t flagged_windows = 0;
    double median_bps = 0.0;
    double min_bps    = 0.0;
    double max_bps    = 0.0;
    if (!window_bps.empty()) {
        std::vector<double> sorted = window_bps;
        std::sort(sorted.begin(), sorted.end());
        median_bps = sorted[sorted.size() / 2];
        min_bps    = sorted.front();
        max_bps    = sorted.back();
        for (double bps : window_bps) {
            if (median_bps > 0
                && (median_bps - bps) / median_bps > kDeviationFlag) {
                ++flagged_windows;
            }
        }
    }
    state.counters["windows_count"] =
        static_cast<double>(window_bps.size());
    state.counters["window_bps_median"]  = median_bps;
    state.counters["window_bps_min"]     = min_bps;
    state.counters["window_bps_max"]     = max_bps;
    state.counters["windows_flagged_15pct_below_median"] =
        static_cast<double>(flagged_windows);
    state.counters["total_bytes"]       = static_cast<double>(total_bytes);
    state.counters["total_sends_ok"]    = static_cast<double>(total_sends_ok);
    state.counters["total_backpressure"]= static_cast<double>(total_backpressure);
    {
        const double denom =
            static_cast<double>(total_sends_ok + total_backpressure);
        state.counters["bp_ratio"] =
            denom > 0.0
                ? static_cast<double>(total_backpressure) / denom
                : 0.0;
    }
    if (median_bps > 0) {
        state.counters["bytes_per_second"] = median_bps;
    }
    report_resources(state, res);
}

BENCHMARK_REGISTER_F(SustainedFixture, TcpThroughput60s)
    ->Iterations(1)
    ->Unit(::benchmark::kSecond)
    ->UseRealTime();

}  // namespace
