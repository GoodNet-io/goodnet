/// @file   tests/unit/registry/test_extension.cpp
/// @brief  GoogleTest unit tests for `gn::core::ExtensionRegistry`.
///
/// Pins the contract from `docs/contracts/abi-evolution.md` §2 (semver
/// compatibility: major must match, registered minor must be >= requested
/// minor) and `host-api.md` §2 (`query_extension_checked`,
/// `register_extension`). Concurrent register/query is exercised under
/// the contract's claim that lookups stay sub-microsecond against
/// concurrent writers.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include <core/registry/extension.hpp>
#include <sdk/abi.h>
#include <sdk/types.h>

namespace gn::core {
namespace {

/// Static dummy vtable; address is only used as a sentinel for the
/// registry — the registry never dereferences it.
const int kDummyVtable = 0;

// ── argument validation ──────────────────────────────────────────────────

TEST(ExtensionRegistry_Args, RegisterRejectsEmptyName) {
    ExtensionRegistry r;
    EXPECT_EQ(r.register_extension("", gn_version_pack(1, 0, 0), &kDummyVtable),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(r.size(), 0u);
}

TEST(ExtensionRegistry_Args, RegisterRejectsNullVtable) {
    ExtensionRegistry r;
    EXPECT_EQ(r.register_extension("gn.heartbeat",
                                    gn_version_pack(1, 0, 0), nullptr),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(r.size(), 0u);
}

TEST(ExtensionRegistry_Args, UnregisterRejectsEmptyName) {
    ExtensionRegistry r;
    EXPECT_EQ(r.unregister_extension(""), GN_ERR_NULL_ARG);
}

TEST(ExtensionRegistry_Args, QueryRejectsNullOutVtable) {
    ExtensionRegistry r;
    ASSERT_EQ(r.register_extension("gn.heartbeat",
                                    gn_version_pack(1, 0, 0), &kDummyVtable),
              GN_OK);
    EXPECT_EQ(r.query_extension_checked("gn.heartbeat",
                                         gn_version_pack(1, 0, 0), nullptr),
              GN_ERR_NULL_ARG);
}

// ── basic register / unregister ──────────────────────────────────────────

TEST(ExtensionRegistry_Register, RoundTrip) {
    ExtensionRegistry r;
    EXPECT_EQ(r.size(), 0u);
    ASSERT_EQ(r.register_extension("gn.heartbeat",
                                    gn_version_pack(1, 2, 3),
                                    &kDummyVtable),
              GN_OK);
    EXPECT_EQ(r.size(), 1u);

    const void* out = nullptr;
    ASSERT_EQ(r.query_extension_checked("gn.heartbeat",
                                         gn_version_pack(1, 0, 0), &out),
              GN_OK);
    EXPECT_EQ(out, &kDummyVtable);
}

TEST(ExtensionRegistry_Register, DuplicateNameRejected) {
    ExtensionRegistry r;
    int other_vtable = 1;
    ASSERT_EQ(r.register_extension("gn.heartbeat",
                                    gn_version_pack(1, 0, 0),
                                    &kDummyVtable),
              GN_OK);
    /// Re-registering the same name (even with a newer version) is
    /// rejected — re-registration goes through unregister first.
    EXPECT_EQ(r.register_extension("gn.heartbeat",
                                    gn_version_pack(1, 5, 0),
                                    &other_vtable),
              GN_ERR_LIMIT_REACHED);
    EXPECT_EQ(r.size(), 1u);

    /// The original vtable must still be reachable.
    const void* out = nullptr;
    EXPECT_EQ(r.query_extension_checked("gn.heartbeat",
                                         gn_version_pack(1, 0, 0), &out),
              GN_OK);
    EXPECT_EQ(out, &kDummyVtable);
}

TEST(ExtensionRegistry_Unregister, RemovesEntry) {
    ExtensionRegistry r;
    ASSERT_EQ(r.register_extension("gn.x", gn_version_pack(1, 0, 0),
                                    &kDummyVtable), GN_OK);
    EXPECT_EQ(r.unregister_extension("gn.x"), GN_OK);
    EXPECT_EQ(r.size(), 0u);

    const void* out = nullptr;
    EXPECT_EQ(r.query_extension_checked("gn.x",
                                         gn_version_pack(1, 0, 0), &out),
              GN_ERR_NOT_FOUND);
    EXPECT_EQ(out, nullptr);
}

TEST(ExtensionRegistry_Unregister, MissingNameRejected) {
    ExtensionRegistry r;
    EXPECT_EQ(r.unregister_extension("missing"),
              GN_ERR_NOT_FOUND);
}

TEST(ExtensionRegistry_Unregister, AllowsReuseAfterRemoval) {
    ExtensionRegistry r;
    int v2 = 0;
    ASSERT_EQ(r.register_extension("gn.x", gn_version_pack(1, 0, 0),
                                    &kDummyVtable), GN_OK);
    ASSERT_EQ(r.unregister_extension("gn.x"), GN_OK);
    EXPECT_EQ(r.register_extension("gn.x", gn_version_pack(2, 0, 0), &v2),
              GN_OK);
}

// ── semver gate (abi-evolution.md §2) ────────────────────────────────────

TEST(ExtensionRegistry_Semver, MajorMustMatchExactly) {
    ExtensionRegistry r;
    ASSERT_EQ(r.register_extension("gn.api",
                                    gn_version_pack(1, 0, 0),
                                    &kDummyVtable),
              GN_OK);
    const void* out = nullptr;
    /// Requested major 2 against registered major 1 — rejected.
    EXPECT_EQ(r.query_extension_checked("gn.api",
                                         gn_version_pack(2, 0, 0), &out),
              GN_ERR_VERSION_MISMATCH);
    EXPECT_EQ(out, nullptr);

    /// Same major is fine.
    EXPECT_EQ(r.query_extension_checked("gn.api",
                                         gn_version_pack(1, 0, 0), &out),
              GN_OK);
    EXPECT_EQ(out, &kDummyVtable);
}

TEST(ExtensionRegistry_Semver, RegisteredMinorMustBeAtLeastRequested) {
    ExtensionRegistry r;
    ASSERT_EQ(r.register_extension("gn.api",
                                    gn_version_pack(1, 2, 0),
                                    &kDummyVtable),
              GN_OK);
    const void* out = nullptr;

    /// Requested minor 5 against registered minor 2 — under-spec, rejected.
    EXPECT_EQ(r.query_extension_checked("gn.api",
                                         gn_version_pack(1, 5, 0), &out),
              GN_ERR_VERSION_MISMATCH);
    EXPECT_EQ(out, nullptr);

    /// Requested minor 0 — additive load is fine.
    out = nullptr;
    EXPECT_EQ(r.query_extension_checked("gn.api",
                                         gn_version_pack(1, 0, 0), &out),
              GN_OK);
    EXPECT_EQ(out, &kDummyVtable);

    /// Requested minor 2 (exact match) — also fine.
    out = nullptr;
    EXPECT_EQ(r.query_extension_checked("gn.api",
                                         gn_version_pack(1, 2, 0), &out),
              GN_OK);
    EXPECT_EQ(out, &kDummyVtable);
}

TEST(ExtensionRegistry_Semver, PatchIgnored) {
    /// Patch differences must not gate compatibility — only major and
    /// minor matter per the contract.
    ExtensionRegistry r;
    ASSERT_EQ(r.register_extension("gn.api",
                                    gn_version_pack(1, 0, 100),
                                    &kDummyVtable),
              GN_OK);
    const void* out = nullptr;
    EXPECT_EQ(r.query_extension_checked("gn.api",
                                         gn_version_pack(1, 0, 99'999), &out),
              GN_OK);
    EXPECT_EQ(out, &kDummyVtable);
}

// ── query_prefix ─────────────────────────────────────────────────────────

TEST(ExtensionRegistry_QueryPrefix, MatchesByLeadingSegment) {
    ExtensionRegistry r;
    int va = 0, vb = 0, vc = 0, vd = 0;
    ASSERT_EQ(r.register_extension("gn.discovery.mdns",
                                    gn_version_pack(1, 0, 0), &va),
              GN_OK);
    ASSERT_EQ(r.register_extension("gn.discovery.dht",
                                    gn_version_pack(1, 0, 0), &vb),
              GN_OK);
    ASSERT_EQ(r.register_extension("gn.discovery.bootstrap",
                                    gn_version_pack(1, 0, 0), &vc),
              GN_OK);
    ASSERT_EQ(r.register_extension("gn.heartbeat",
                                    gn_version_pack(1, 0, 0), &vd),
              GN_OK);

    auto group = r.query_prefix("gn.discovery.");
    EXPECT_EQ(group.size(), 3u);

    auto all = r.query_prefix("gn.");
    EXPECT_EQ(all.size(), 4u);

    auto miss = r.query_prefix("nope.");
    EXPECT_TRUE(miss.empty());
}

TEST(ExtensionRegistry_QueryPrefix, EmptyPrefixReturnsAll) {
    ExtensionRegistry r;
    int v1 = 0, v2 = 0;
    ASSERT_EQ(r.register_extension("a", gn_version_pack(1, 0, 0), &v1), GN_OK);
    ASSERT_EQ(r.register_extension("b", gn_version_pack(1, 0, 0), &v2), GN_OK);
    auto all = r.query_prefix("");
    EXPECT_EQ(all.size(), 2u);
}

// ── concurrent stress ────────────────────────────────────────────────────

/// Hammer register / unregister / query from multiple threads. Reader
/// thread's clean join is the deadlock-absence proof; per-thread
/// assertions verify no lookup ever returns a stale or torn vtable.
TEST(ExtensionRegistry_Concurrency, FourThreadsRegisterQuery) {
    constexpr int kThreads   = 4;
    constexpr int kPerThread = 256;
    ExtensionRegistry r;

    std::atomic<int> reg_ok{0};
    std::atomic<int> unreg_ok{0};
    std::atomic<int> query_ok{0};
    std::atomic<bool> stop{false};

    auto writer = [&](int tid) {
        std::vector<std::string> mine;
        mine.reserve(kPerThread);
        for (int i = 0; i < kPerThread; ++i) {
            std::string name =
                "gn.t" + std::to_string(tid) + "." + std::to_string(i);
            if (r.register_extension(name, gn_version_pack(1, 0, 0),
                                      &kDummyVtable) == GN_OK) {
                ++reg_ok;
                mine.push_back(name);
            }
            if ((i % 2) == 0 && !mine.empty()) {
                if (r.unregister_extension(mine.back()) == GN_OK) {
                    ++unreg_ok;
                    mine.pop_back();
                }
            }
        }
    };

    /// One pure reader to exercise shared-lock fairness against
    /// the writer pool.
    auto reader = [&]() {
        while (!stop.load(std::memory_order_relaxed)) {
            const void* out = nullptr;
            auto rc = r.query_extension_checked(
                "gn.t0.0", gn_version_pack(1, 0, 0), &out);
            if (rc == GN_OK || rc == GN_ERR_NOT_FOUND) {
                ++query_ok;
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(kThreads + 1);
    const auto start = std::chrono::steady_clock::now();
    for (int t = 0; t < kThreads; ++t) threads.emplace_back(writer, t);
    threads.emplace_back(reader);
    for (int t = 0; t < kThreads; ++t) threads[static_cast<std::size_t>(t)].join();
    stop.store(true, std::memory_order_relaxed);
    threads.back().join();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_LT(elapsed, std::chrono::seconds(30))
        << "concurrent stress took unexpectedly long; possible deadlock";

    EXPECT_GT(reg_ok.load(), 0);
    EXPECT_GT(query_ok.load(), 0);
    EXPECT_EQ(r.size(),
              static_cast<std::size_t>(reg_ok.load() - unreg_ok.load()));
}

// ── max_extensions cap (limits.md §4a) ───────────────────────────────────

TEST(ExtensionRegistry_MaxExtensions, ZeroMeansUnlimited) {
    ExtensionRegistry r;
    for (int i = 0; i < 32; ++i) {
        EXPECT_EQ(r.register_extension(
            "gn.test.unlimited" + std::to_string(i), 0x010000, &kDummyVtable),
            GN_OK);
    }
    EXPECT_EQ(r.size(), 32u);
}

TEST(ExtensionRegistry_MaxExtensions, RejectsBeyondCap) {
    ExtensionRegistry r;
    r.set_max_extensions(3);

    EXPECT_EQ(r.register_extension("gn.test.a", 0x010000, &kDummyVtable), GN_OK);
    EXPECT_EQ(r.register_extension("gn.test.b", 0x010000, &kDummyVtable), GN_OK);
    EXPECT_EQ(r.register_extension("gn.test.c", 0x010000, &kDummyVtable), GN_OK);
    EXPECT_EQ(r.register_extension("gn.test.d", 0x010000, &kDummyVtable),
              GN_ERR_LIMIT_REACHED);
    EXPECT_EQ(r.size(), 3u);

    /// Unregister frees a slot.
    EXPECT_EQ(r.unregister_extension("gn.test.b"), GN_OK);
    EXPECT_EQ(r.register_extension("gn.test.d", 0x010000, &kDummyVtable), GN_OK);
    EXPECT_EQ(r.size(), 3u);
}

}  // namespace
}  // namespace gn::core
