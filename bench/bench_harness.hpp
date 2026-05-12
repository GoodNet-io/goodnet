// SPDX-License-Identifier: Apache-2.0
/// @file   bench/bench_harness.hpp
/// @brief  Common test infrastructure for GoodNet benchmarks.
///
/// Three pieces:
///
///   1. `BenchKernel` — minimal in-process stand-in for a kernel.
///      Plugins get a host_api_t that captures inbound / disconnect
///      callbacks (reusing `gn::sdk::test::LinkStub`); the bench
///      drives `send` directly against the plugin instance.
///
///   2. `RoundTripMeter` — request/response timing helper. Posts a
///      payload, waits for the echo, records the delta. Aggregates
///      P50 / P95 / P99 / P99.9 over the loop body.
///
///   3. `ResourceCounters` — wraps `getrusage(RUSAGE_SELF)` and
///      `/proc/self/statm` so each benchmark surfaces user / system
///      CPU time and peak RSS alongside the throughput / latency
///      numbers google-benchmark reports natively.
///
/// Benchmarks register through google-benchmark's BENCHMARK_F /
/// BENCHMARK_DEFINE_F macros. The fixture below holds the kernel +
/// plugin lifetime; tests configure throughput / latency by varying
/// the payload size + iteration count.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <vector>

#include <benchmark/benchmark.h>
#include <sdk/cpp/test/poll.hpp>
#include <sdk/cpp/test/stub_host.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

namespace gn::bench {

/// Test-fixture kernel: a `LinkStub` plus a `host_api_t` built from
/// the SDK test helper. Plugins (TcpLink, UdpLink, ...) get
/// `set_host_api(&api)` and run against the in-process stub.
struct BenchKernel {
    ::gn::sdk::test::LinkStub stub;
    host_api_t                api;
    BenchKernel() : api(::gn::sdk::test::make_link_host_api(stub)) {}
};

/// Round-trip timing collector. Latency samples are inserted via
/// `record(ns)`; quantiles are produced at finalise time.
class RoundTripMeter {
public:
    void record(std::uint64_t ns) {
        std::lock_guard lk(mu_);
        samples_.push_back(ns);
    }

    /// Compute quantile percentile (linear interpolation between
    /// adjacent sorted samples). Returns 0 on empty input rather
    /// than NaN so the benchmark report always has a number.
    std::uint64_t quantile(double p) const {
        std::lock_guard lk(mu_);
        if (samples_.empty()) return 0;
        std::vector<std::uint64_t> sorted = samples_;
        std::sort(sorted.begin(), sorted.end());
        const double rank = p * (static_cast<double>(sorted.size()) - 1.0);
        const std::size_t lo = static_cast<std::size_t>(rank);
        const std::size_t hi = std::min(lo + 1, sorted.size() - 1);
        const double frac    = rank - static_cast<double>(lo);
        return static_cast<std::uint64_t>(
            static_cast<double>(sorted[lo])
            + frac * (static_cast<double>(sorted[hi])
                      - static_cast<double>(sorted[lo])));
    }

    [[nodiscard]] std::size_t size() const noexcept {
        std::lock_guard lk(mu_);
        return samples_.size();
    }

    void clear() noexcept {
        std::lock_guard lk(mu_);
        samples_.clear();
    }

private:
    mutable std::mutex            mu_;
    std::vector<std::uint64_t>    samples_;
};

/// Resource sampler — read `getrusage` + `/proc/self/statm` deltas
/// across a benchmark body so the report can surface CPU time and
/// peak resident-set growth alongside throughput.
class ResourceCounters {
public:
    void snapshot_start() {
        getrusage(RUSAGE_SELF, &before_);
        rss_kb_start_ = current_rss_kb();
    }

    void snapshot_end() {
        getrusage(RUSAGE_SELF, &after_);
        rss_kb_end_ = current_rss_kb();
    }

    /// User CPU microseconds across the measurement window.
    [[nodiscard]] std::uint64_t user_us() const noexcept {
        return tv_delta_us(before_.ru_utime, after_.ru_utime);
    }

    /// System CPU microseconds across the measurement window.
    [[nodiscard]] std::uint64_t system_us() const noexcept {
        return tv_delta_us(before_.ru_stime, after_.ru_stime);
    }

    /// Peak RSS delta (KiB) — positive means the bench grew RSS,
    /// negative means it shrank (the kernel reclaimed pages during
    /// the window).
    [[nodiscard]] std::int64_t rss_kb_delta() const noexcept {
        return static_cast<std::int64_t>(rss_kb_end_)
             - static_cast<std::int64_t>(rss_kb_start_);
    }

private:
    static std::uint64_t tv_delta_us(const timeval& a, const timeval& b) {
        const std::uint64_t a_us =
            static_cast<std::uint64_t>(a.tv_sec) * 1'000'000ULL
            + static_cast<std::uint64_t>(a.tv_usec);
        const std::uint64_t b_us =
            static_cast<std::uint64_t>(b.tv_sec) * 1'000'000ULL
            + static_cast<std::uint64_t>(b.tv_usec);
        return b_us > a_us ? (b_us - a_us) : 0;
    }

    /// `/proc/self/statm`'s second field is resident set size in
    /// pages. Read it as a string so the bench's reported number
    /// matches what `top` would show.
    static std::uint64_t current_rss_kb() noexcept {
        FILE* f = std::fopen("/proc/self/statm", "r");
        if (!f) return 0;
        unsigned long size_pages = 0, rss_pages = 0;
        const int n = std::fscanf(f, "%lu %lu", &size_pages, &rss_pages);
        std::fclose(f);
        if (n < 2) return 0;
        return static_cast<std::uint64_t>(rss_pages)
             * static_cast<std::uint64_t>(::sysconf(_SC_PAGESIZE))
             / 1024ULL;
    }

    rusage         before_{};
    rusage         after_{};
    std::uint64_t  rss_kb_start_ = 0;
    std::uint64_t  rss_kb_end_   = 0;
};

/// Build a deterministic payload of `size` bytes.
[[nodiscard]] inline std::vector<std::uint8_t>
make_payload(std::size_t size) {
    std::vector<std::uint8_t> out(size);
    for (std::size_t i = 0; i < size; ++i) {
        out[i] = static_cast<std::uint8_t>(i & 0xFF);
    }
    return out;
}

/// Helper — google-benchmark `State` doesn't surface custom counters
/// without explicit `SetLabel` / `counters[]` calls. The fixture
/// wrappers below funnel quantile + resource numbers through this so
/// the per-bench code stays one-liners.
inline void report_latency(::benchmark::State& s, RoundTripMeter& m) {
    s.counters["lat_p50_ns"]  = static_cast<double>(m.quantile(0.50));
    s.counters["lat_p95_ns"]  = static_cast<double>(m.quantile(0.95));
    s.counters["lat_p99_ns"]  = static_cast<double>(m.quantile(0.99));
    s.counters["lat_p999_ns"] = static_cast<double>(m.quantile(0.999));
}

inline void report_resources(::benchmark::State& s, const ResourceCounters& r) {
    s.counters["cpu_user_us"]  = static_cast<double>(r.user_us());
    s.counters["cpu_sys_us"]   = static_cast<double>(r.system_us());
    s.counters["rss_kb_delta"] = static_cast<double>(r.rss_kb_delta());
}

}  // namespace gn::bench
