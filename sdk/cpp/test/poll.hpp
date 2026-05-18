// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/test/poll.hpp
/// @brief  Shared `wait_for` polling helper for plugin unit tests.
///
/// Every transport plugin's tests/ directory hand-rolls a copy of
///
/// @code
/// bool wait_for(auto&& pred, ms timeout = 1s, const char* what="") {
///     auto deadline = steady_clock::now() + timeout;
///     while (steady_clock::now() < deadline) {
///         if (pred()) return true;
///         sleep_for(5ms);
///     }
///     return pred();
/// }
/// @endcode
///
/// `gn::sdk::test::wait_for` is the canonical version. Defined
/// header-only because tests link gtest dynamically and a shared
/// translation unit would force gtest into the SDK target.

#pragma once

#include <chrono>
#include <string_view>
#include <thread>

namespace gn::sdk::test {

/// Spin-poll @p pred until it returns true OR @p timeout elapses.
/// Returns the predicate's final value. Sleeps @p tick between
/// evaluations to avoid burning the CPU on a tight loop.
///
/// Caller decides whether failure is fatal — use directly:
///
/// @code
/// EXPECT_TRUE(gn::sdk::test::wait_for([&] { return rec.count > 0; }));
/// ASSERT_TRUE(gn::sdk::test::wait_for(
///     [&] { return handshake_done.load(); },
///     std::chrono::seconds{5}, "handshake")) << "timed out";
/// @endcode
template <class Predicate>
[[nodiscard]] bool wait_for(
    Predicate&& pred,
    std::chrono::milliseconds timeout =
        std::chrono::milliseconds{1000},
    std::chrono::milliseconds tick =
        std::chrono::milliseconds{5},
    std::string_view /*label*/ = {}) {
    const auto deadline =
        std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(tick);
    }
    return pred();
}

/// Tight-poll variant — `std::this_thread::yield()` between
/// predicate evaluations instead of a millisecond-granularity
/// sleep. Resolution is OS scheduler quantum (~1-50µs) rather than
/// the default 5ms tick, so loopback round-trips and connection
/// setup latencies that complete in tens of microseconds are
/// measured at their real magnitude rather than rounded up to the
/// next poll boundary. Burns one core for the wait window — use
/// only in benchmarks / tests that need sub-millisecond resolution
/// (e.g. `bench/plugins/bench_tcp.cpp::LatencyRoundtrip`,
/// `HandshakeTime`).
template <class Predicate>
[[nodiscard]] bool wait_for_fast(
    Predicate&& pred,
    std::chrono::milliseconds timeout =
        std::chrono::milliseconds{1000}) {
    const auto deadline =
        std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::yield();
    }
    return pred();
}

}  // namespace gn::sdk::test
