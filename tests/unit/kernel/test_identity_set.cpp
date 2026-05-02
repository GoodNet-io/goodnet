/// @file   tests/unit/kernel/test_identity_set.cpp
/// @brief  Tests for `gn::core::LocalIdentityRegistry`.
///
/// Pins multi-tenant routing: a kernel may host more than one node
/// identity in one process. The set is consulted on every inbound
/// envelope (router) and on every connection registration; concurrency
/// must be lock-correct.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#include <core/kernel/identity_set.hpp>
#include <sdk/cpp/types.hpp>

namespace gn::core {
namespace {

/// Build a deterministic, distinguishable public key from a single byte.
PublicKey pk_from_byte(std::uint8_t seed) noexcept {
    PublicKey pk{};
    for (std::size_t i = 0; i < pk.size(); ++i) {
        pk[i] = static_cast<std::uint8_t>(seed + i);
    }
    return pk;
}

/// Build a public key from a 32-bit seed by spreading the bytes across
/// the leading word so distinct seeds yield distinct keys. Used by the
/// concurrency stress where the simple `pk_from_byte` 8-bit space is
/// not enough.
PublicKey pk_from_u32(std::uint32_t seed) noexcept {
    PublicKey pk{};
    pk[0] = static_cast<std::uint8_t>(seed         & 0xFF);
    pk[1] = static_cast<std::uint8_t>((seed >> 8)  & 0xFF);
    pk[2] = static_cast<std::uint8_t>((seed >> 16) & 0xFF);
    pk[3] = static_cast<std::uint8_t>((seed >> 24) & 0xFF);
    /// Tail bytes deterministic from seed too — keeps the hash uniform.
    for (std::size_t i = 4; i < pk.size(); ++i) {
        pk[i] = static_cast<std::uint8_t>(seed + i);
    }
    return pk;
}

// ─── basic operations ───────────────────────────────────────────────

TEST(LocalIdentityRegistry_Basic, EmptyByDefault) {
    LocalIdentityRegistry set;
    EXPECT_EQ(set.size(), 0u);
    EXPECT_FALSE(set.contains(pk_from_byte(0x11)));
}

TEST(LocalIdentityRegistry_Basic, AddThenContainsThenRemove) {
    LocalIdentityRegistry set;
    const auto a = pk_from_byte(0x11);
    const auto b = pk_from_byte(0x22);

    set.add(a);
    EXPECT_TRUE(set.contains(a));
    EXPECT_FALSE(set.contains(b));
    EXPECT_EQ(set.size(), 1u);

    set.add(b);
    EXPECT_TRUE(set.contains(b));
    EXPECT_EQ(set.size(), 2u);

    set.remove(a);
    EXPECT_FALSE(set.contains(a));
    EXPECT_TRUE(set.contains(b));
    EXPECT_EQ(set.size(), 1u);

    set.remove(b);
    EXPECT_FALSE(set.contains(b));
    EXPECT_EQ(set.size(), 0u);
}

TEST(LocalIdentityRegistry_Basic, RemoveAbsentIsNoOp) {
    LocalIdentityRegistry set;
    set.remove(pk_from_byte(0x33));  // must not throw
    EXPECT_EQ(set.size(), 0u);
}

TEST(LocalIdentityRegistry_Basic, AddIsIdempotent) {
    LocalIdentityRegistry set;
    const auto a = pk_from_byte(0x44);

    set.add(a);
    set.add(a);
    set.add(a);

    EXPECT_TRUE(set.contains(a));
    EXPECT_EQ(set.size(), 1u);

    set.remove(a);
    EXPECT_EQ(set.size(), 0u);
}

TEST(LocalIdentityRegistry_Basic, BroadcastPkIsTreatedLikeAnyOther) {
    /// The broadcast marker (`kBroadcastPk`, all zeros) is a valid value
    /// the set may hold; the *router* is what assigns it broadcast
    /// semantics, not the set itself.
    LocalIdentityRegistry set;
    set.add(kBroadcastPk);
    EXPECT_TRUE(set.contains(kBroadcastPk));
    EXPECT_EQ(set.size(), 1u);
}

// ─── concurrency ────────────────────────────────────────────────────

TEST(LocalIdentityRegistry_Concurrency, FourThreadsAddAndContains) {
    /// Four writers + four readers race on the same shared set. The
    /// requirement is "no race, no deadlock" — final state must be
    /// fully populated and the run must finish in a bounded time.

    constexpr int kThreads   = 4;
    constexpr int kPerThread = 1024;
    LocalIdentityRegistry set;

    std::atomic<int> reader_observations{0};
    std::atomic<bool> stop_readers{false};

    auto writer = [&](int tid) {
        for (int i = 0; i < kPerThread; ++i) {
            /// Each thread owns a disjoint key space so adds are
            /// observable as net-new entries. The set must still
            /// serialise the writes correctly.
            const auto pk = pk_from_u32(
                static_cast<std::uint32_t>((tid << 16) | i));
            set.add(pk);
        }
    };

    auto reader = [&]() {
        /// Probe the same key space the writers populate so hits are
        /// plausible once writers progress.
        while (!stop_readers.load(std::memory_order_acquire)) {
            for (int tid = 0; tid < kThreads; ++tid) {
                for (int i = 0; i < 64; ++i) {
                    if (set.contains(pk_from_u32(
                            static_cast<std::uint32_t>((tid << 16) | i)))) {
                        reader_observations.fetch_add(1,
                            std::memory_order_relaxed);
                    }
                }
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(static_cast<std::size_t>(kThreads) * 2);

    const auto start = std::chrono::steady_clock::now();
    for (int t = 0; t < kThreads; ++t) threads.emplace_back(writer, t);
    for (int t = 0; t < kThreads; ++t) threads.emplace_back(reader);

    /// Join writers first.
    for (std::size_t t = 0; t < static_cast<std::size_t>(kThreads); ++t) {
        threads[t].join();
    }

    /// Stop readers and join them.
    stop_readers.store(true, std::memory_order_release);
    for (std::size_t t = static_cast<std::size_t>(kThreads);
         t < static_cast<std::size_t>(kThreads) * 2; ++t) {
        threads[t].join();
    }

    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(elapsed, std::chrono::seconds(30))
        << "concurrent stress took unexpectedly long; possible deadlock";

    /// All 4 * 1024 writes are on disjoint keys; the final set must
    /// hold exactly that many entries. (Threads cannot collide because
    /// the high `tid << 16` bits make every key unique across threads.)
    EXPECT_EQ(set.size(), static_cast<std::size_t>(kThreads * kPerThread));

    /// `reader_observations` is intentionally unchecked — its value is
    /// scheduler-dependent. A reader that joined cleanly is enough
    /// evidence the shared-lock path did not deadlock.
    (void)reader_observations.load(std::memory_order_relaxed);
}

TEST(LocalIdentityRegistry_Concurrency, AddRemoveContainsDoesNotDeadlock) {
    /// Mixed add/remove/contains across four threads. We don't assert
    /// final cardinality — adds and removes are racing — only that the
    /// loop terminates and `contains` survives without UB.

    constexpr int kThreads   = 4;
    constexpr int kPerThread = 512;
    LocalIdentityRegistry set;

    auto worker = [&](int tid) {
        for (int i = 0; i < kPerThread; ++i) {
            const auto pk = pk_from_u32(
                static_cast<std::uint32_t>((tid << 16) | i));
            switch (i % 3) {
                case 0: set.add(pk);            break;
                case 1: set.remove(pk);         break;
                case 2: (void)set.contains(pk); break;
                default: break;  /// unreachable; tidy hates open switches.
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    const auto start = std::chrono::steady_clock::now();
    for (int t = 0; t < kThreads; ++t) threads.emplace_back(worker, t);
    for (auto& th : threads) th.join();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_LT(elapsed, std::chrono::seconds(30))
        << "concurrent stress took unexpectedly long; possible deadlock";
}

}  // namespace
}  // namespace gn::core
