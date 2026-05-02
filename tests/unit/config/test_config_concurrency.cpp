/// @file   tests/unit/config/test_config_concurrency.cpp
/// @brief  Concurrency stress for `gn::core::Config` shared-lock semantics.
///
/// Pins the read-side concurrency claim from `docs/contracts/config.md`
/// §2 ("kernel resolves the dotted path under a shared lock") and the
/// implementation note in `config.hpp` ("thread-safe for concurrent
/// reads; reload is exclusive"): many `get_int64` / `get_string`
/// readers must observe one of the published values atomically while
/// `load_json` writers swap `json_` / `limits_` in place. Drives TSan
/// at `core/config/config_.json_` and `config_.limits_`.

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <core/config/config.hpp>
#include <sdk/limits.h>
#include <sdk/types.h>

namespace gn::core {
namespace {

/// JSON document templated on `max_connections`. The other fields
/// stay at defaults so `validate()` remains satisfiable across every
/// reload — `max_outbound_connections` is the default 1024, so each
/// candidate value here is >= 1024 to keep §3's
/// `outbound <= total` invariant holding throughout the run.
std::string make_int_json(std::uint32_t max_connections) {
    return std::string(R"({"limits": {"max_connections": )") +
           std::to_string(max_connections) + R"(}})";
}

/// JSON document carrying a string at `identity.uri`. The path is a
/// two-segment dotted lookup, exercising the same `resolve()` walk as
/// real plugin reads but on a key independent of the `limits` block.
std::string make_uri_json(std::string_view uri) {
    return std::string(R"({"identity": {"uri": ")") +
           std::string{uri} + R"("}})";
}

// ── int64 read while reload swaps the limits block ───────────────────────

TEST(ConfigConcurrency, ReloadWhileReadersActive) {
    constexpr std::size_t kReaderThreads = 4;
    constexpr std::size_t kReadsPerThread = 10'000;
    constexpr std::size_t kWriterThreads = 2;
    constexpr std::size_t kWritesPerThread = 1'000;

    /// Three candidate values the writers cycle through. Each is
    /// >= the default outbound cap (1024) so the `validate()` call at
    /// the end is unconditional regardless of which one wins the last
    /// `load_json` race.
    constexpr std::array<std::uint32_t, 3> kCandidates{1024U, 2048U, 4096U};

    Config c;
    /// Seed with the first candidate so readers never see a missing
    /// key on entry — `get_int64` would return NOT_FOUND on a
    /// fresh default-constructed Config because the limits block is
    /// only populated through `load_json`, not through defaults.
    ASSERT_EQ(c.load_json(make_int_json(kCandidates[0])), GN_OK);

    /// Pre-build the JSON strings once; allocating inside the writer
    /// loop would dominate wall-clock and dilute the lock contention
    /// the test exists to catch.
    std::array<std::string, kCandidates.size()> docs;
    for (std::size_t i = 0; i < kCandidates.size(); ++i) {
        docs[i] = make_int_json(kCandidates[i]);
    }

    std::atomic<int> read_failures{0};
    std::atomic<int> write_failures{0};

    auto reader = [&] {
        for (std::size_t i = 0; i < kReadsPerThread; ++i) {
            std::int64_t v = -1;
            const auto rc = c.get_int64("limits.max_connections", v);
            if (rc != GN_OK) {
                ++read_failures;
                continue;
            }
            const bool valid = (v == kCandidates[0] ||
                                v == kCandidates[1] ||
                                v == kCandidates[2]);
            if (!valid) ++read_failures;
        }
    };

    auto writer = [&](std::size_t tid) {
        for (std::size_t i = 0; i < kWritesPerThread; ++i) {
            const auto& doc = docs[(tid + i) % docs.size()];
            if (c.load_json(doc) != GN_OK) ++write_failures;
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(kReaderThreads + kWriterThreads);
    const auto start = std::chrono::steady_clock::now();
    for (std::size_t t = 0; t < kReaderThreads; ++t) threads.emplace_back(reader);
    for (std::size_t t = 0; t < kWriterThreads; ++t) threads.emplace_back(writer, t);
    for (auto& th : threads) th.join();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_EQ(read_failures.load(), 0)
        << "readers must observe one of {1024, 2048, 4096} on every call";
    EXPECT_EQ(write_failures.load(), 0)
        << "every pre-built JSON document parses cleanly";
    EXPECT_LT(elapsed, std::chrono::seconds(30))
        << "concurrent stress took unexpectedly long; possible deadlock";

    /// Whatever value won the last reload, it must keep §3 satisfied.
    EXPECT_EQ(c.validate(), GN_OK);
}

// ── string read while reload swaps the json_ root ────────────────────────

TEST(ConfigConcurrency, ReloadDoesNotTearStringValues) {
    constexpr std::size_t kReaderThreads = 4;
    constexpr std::size_t kReadsPerThread = 10'000;
    constexpr std::size_t kWriterThreads = 2;
    constexpr std::size_t kWritesPerThread = 1'000;

    /// Three URIs of different lengths; a torn read of `std::string`
    /// inside `nlohmann::json` would surface as a value that is none
    /// of these (e.g. truncated, zero-length, or mixed bytes).
    constexpr std::array<std::string_view, 3> kUris{
        std::string_view{"gnet://alice.example:5000"},
        std::string_view{"gnet://bob:6"},
        std::string_view{"gnet://carol-with-a-rather-longer-host:65535"},
    };

    /// Build a hash set of the expected strings up front — the read
    /// loop is hot, and `unordered_set::count` is O(1) average vs.
    /// three branch comparisons that the optimiser may serialise.
    const std::unordered_set<std::string> expected{
        std::string{kUris[0]},
        std::string{kUris[1]},
        std::string{kUris[2]},
    };

    Config c;
    ASSERT_EQ(c.load_json(make_uri_json(kUris[0])), GN_OK);

    std::array<std::string, kUris.size()> docs;
    for (std::size_t i = 0; i < kUris.size(); ++i) {
        docs[i] = make_uri_json(kUris[i]);
    }

    std::atomic<int> read_failures{0};
    std::atomic<int> write_failures{0};

    auto reader = [&] {
        for (std::size_t i = 0; i < kReadsPerThread; ++i) {
            std::string out;  /// RAII: destructor releases on each iter.
            const auto rc = c.get_string("identity.uri", out);
            if (rc != GN_OK) {
                ++read_failures;
                continue;
            }
            if (expected.count(out) == 0) ++read_failures;
        }
    };

    auto writer = [&](std::size_t tid) {
        for (std::size_t i = 0; i < kWritesPerThread; ++i) {
            const auto& doc = docs[(tid + i) % docs.size()];
            if (c.load_json(doc) != GN_OK) ++write_failures;
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(kReaderThreads + kWriterThreads);
    const auto start = std::chrono::steady_clock::now();
    for (std::size_t t = 0; t < kReaderThreads; ++t) threads.emplace_back(reader);
    for (std::size_t t = 0; t < kWriterThreads; ++t) threads.emplace_back(writer, t);
    for (auto& th : threads) th.join();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_EQ(read_failures.load(), 0)
        << "readers must observe one of the three published URIs intact";
    EXPECT_EQ(write_failures.load(), 0);
    EXPECT_LT(elapsed, std::chrono::seconds(30))
        << "concurrent stress took unexpectedly long; possible deadlock";

    EXPECT_EQ(c.validate(), GN_OK);
}

}  // namespace
}  // namespace gn::core
