/// @file   tests/unit/registry/test_connection_stress.cpp
/// @brief  Many-thread stress for `gn::core::ConnectionRegistry`.
///
/// `test_connection.cpp` already exercises the two-thread race on
/// `snapshot_and_erase` and the cross-shard deadlock-free claim.
/// Realistic plugin fan-out, however, runs through dozens of
/// concurrent inserts and lookups while erases drain the registry —
/// the path on which the kernel's per-shard locking strategy from
/// `registry.md` §3 is load-bearing. The cases below pin the
/// invariants under that load:
///
///   - Every successful insert lands a unique `(id, pk, uri)`
///     triple. Concurrent insert from many threads MUST NOT collide.
///   - Concurrent insert and erase against the full id space MUST
///     never observe a torn record (find_by_id sees either the full
///     record or nothing).
///   - Lookup readers spinning during a write storm MUST NOT crash
///     and MUST eventually converge on the final state.
///
/// The bodies stay deterministic by keying every record on its
/// thread index; ASan / TSan in the CI matrix promote any actual
/// race into a fail.

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <core/registry/connection.hpp>
#include <sdk/cpp/types.hpp>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::core {
namespace {

PublicKey make_pk_stress(std::uint64_t seed) noexcept {
    PublicKey pk{};
    std::memcpy(pk.data(), &seed, sizeof(seed));
    return pk;
}

ConnectionRecord make_record_stress(gn_conn_id_t id,
                                     std::string  uri,
                                     PublicKey    pk) {
    ConnectionRecord r;
    r.id        = id;
    r.uri       = std::move(uri);
    r.remote_pk = pk;
    r.trust     = GN_TRUST_PEER;
    r.scheme    = "tcp";
    return r;
}

}  // namespace

TEST(ConnectionRegistry_Stress, ManyConcurrentInsertsAllSucceedDistinct) {
    /// 16 threads × 64 inserts each. The (uri, pk) keys are derived
    /// from `(thread, iteration)` so the sets are disjoint by
    /// construction; the only failure mode is a registry-side
    /// race that double-allocates an id or aborts an otherwise
    /// legal insert.
    constexpr int kThreads     = 16;
    constexpr int kPerThread   = 64;
    constexpr int kTotal       = kThreads * kPerThread;

    ConnectionRegistry reg;
    reg.set_max_connections(0);  /// unlimited

    std::vector<std::vector<gn_conn_id_t>> per_thread_ids(kThreads);
    std::vector<std::thread> workers;
    workers.reserve(kThreads);

    /// Seeds are biased away from zero so every record carries a
    /// non-zero `remote_pk` — `ConnectionRegistry::insert_with_index`
    /// intentionally skips indexing the all-zero placeholder per
    /// `registry.md`, and a dropped pk index would mask a real
    /// concurrency bug under this stress.
    constexpr std::uint64_t kSeedBase = 0x1ULL << 60;
    auto seed_for = [&](std::size_t idx, int i) {
        return kSeedBase |
               (static_cast<std::uint64_t>(idx) << 32) |
                static_cast<std::uint64_t>(i);
    };

    for (int p = 0; p < kThreads; ++p) {
        workers.emplace_back([&, idx = static_cast<std::size_t>(p)]() {
            auto& ids = per_thread_ids[idx];
            ids.reserve(kPerThread);
            for (int i = 0; i < kPerThread; ++i) {
                const gn_conn_id_t id = reg.alloc_id();
                const auto rec = make_record_stress(
                    id,
                    "tcp://t" + std::to_string(idx) + "-i" + std::to_string(i),
                    make_pk_stress(seed_for(idx, i)));
                EXPECT_EQ(reg.insert_with_index(rec), GN_OK);
                ids.push_back(id);
            }
        });
    }
    for (auto& w : workers) w.join();

    EXPECT_EQ(reg.size(), static_cast<std::size_t>(kTotal));

    /// Every issued id is unique across threads.
    std::set<gn_conn_id_t> seen;
    for (const auto& v : per_thread_ids) {
        for (auto id : v) {
            EXPECT_TRUE(seen.insert(id).second) << "duplicate id " << id;
        }
    }
    EXPECT_EQ(seen.size(), static_cast<std::size_t>(kTotal));

    /// Every record is reachable by id and by pk.
    for (int p = 0; p < kThreads; ++p) {
        for (int i = 0; i < kPerThread; ++i) {
            const auto pk = make_pk_stress(
                seed_for(static_cast<std::size_t>(p), i));
            EXPECT_NE(reg.find_by_pk(pk), nullptr);
        }
    }
}

TEST(ConnectionRegistry_Stress, ConcurrentInsertEraseDrainsRegistry) {
    /// Producer threads insert, consumer threads erase. Inserts and
    /// erases share an id queue: producers push every freshly inserted
    /// id, consumers pop and `snapshot_and_erase`. Final state — every
    /// inserted id consumed exactly once and the registry empty —
    /// holds the §4a atomicity guarantee under sustained churn.
    constexpr int kInsertersPerSide = 4;
    constexpr int kErasersPerSide   = 4;
    constexpr int kPerInserter      = 256;
    constexpr int kTotal            = kInsertersPerSide * kPerInserter;

    ConnectionRegistry reg;
    reg.set_max_connections(0);

    std::atomic<int> issued{0};
    std::atomic<int> erased{0};
    std::vector<std::atomic<gn_conn_id_t>> queue(kTotal);
    for (auto& slot : queue) slot.store(GN_INVALID_ID,
                                         std::memory_order_relaxed);

    std::atomic<int> producers_done{0};

    auto produce = [&](int side) {
        for (int i = 0; i < kPerInserter; ++i) {
            const gn_conn_id_t id = reg.alloc_id();
            const std::uint64_t seed =
                (static_cast<std::uint64_t>(side) << 40) |
                (static_cast<std::uint64_t>(i)    << 8)  |
                 static_cast<std::uint64_t>(id & 0xFFu);
            const auto rec = make_record_stress(
                id,
                "tcp://drain-" + std::to_string(side) + "-" +
                    std::to_string(i),
                make_pk_stress(seed));
            EXPECT_EQ(reg.insert_with_index(rec), GN_OK);
            const int slot = issued.fetch_add(1, std::memory_order_acq_rel);
            queue[static_cast<std::size_t>(slot)].store(
                id, std::memory_order_release);
        }
        producers_done.fetch_add(1, std::memory_order_acq_rel);
    };

    auto consume = [&]() {
        for (;;) {
            int idx;
            for (;;) {
                idx = erased.load(std::memory_order_acquire);
                if (idx >= kTotal) return;
                if (idx >= issued.load(std::memory_order_acquire)) {
                    /// Producers may not have run yet; back off but
                    /// keep looking.
                    if (producers_done.load(std::memory_order_acquire) ==
                        kInsertersPerSide &&
                        idx >= issued.load(std::memory_order_acquire)) {
                        return;
                    }
                    std::this_thread::yield();
                    continue;
                }
                if (erased.compare_exchange_weak(idx, idx + 1,
                        std::memory_order_acq_rel)) {
                    break;
                }
            }
            gn_conn_id_t id = GN_INVALID_ID;
            while (id == GN_INVALID_ID) {
                id = queue[static_cast<std::size_t>(idx)].load(
                    std::memory_order_acquire);
                if (id == GN_INVALID_ID) std::this_thread::yield();
            }
            EXPECT_TRUE(reg.snapshot_and_erase(id).has_value());
        }
    };

    std::vector<std::thread> producers;
    std::vector<std::thread> consumers;
    producers.reserve(kInsertersPerSide);
    consumers.reserve(kErasersPerSide);
    for (int p = 0; p < kInsertersPerSide; ++p) {
        producers.emplace_back(produce, p);
    }
    for (int c = 0; c < kErasersPerSide; ++c) {
        consumers.emplace_back(consume);
    }
    for (auto& p : producers) p.join();
    for (auto& c : consumers) c.join();

    EXPECT_EQ(issued.load(), kTotal);
    EXPECT_EQ(erased.load(), kTotal);
    EXPECT_EQ(reg.size(), 0u);
}

TEST(ConnectionRegistry_Stress, FindRunsConcurrentlyWithMutations) {
    /// Reader threads loop on `find_by_id` / `find_by_pk` while a
    /// writer thread inserts and erases. The readers' only invariant
    /// is "no crash, no torn record" — gtest's body MUST run to
    /// completion in bounded time. ASan/TSan promote any actual
    /// races into a fail; the pass criterion here is "alive".
    ConnectionRegistry reg;
    reg.set_max_connections(0);

    constexpr int kReaders = 4;
    constexpr int kRounds  = 512;

    std::atomic<bool> stop{false};
    std::atomic<std::uint64_t> read_hits{0};

    /// Pre-seed a stable record the readers can rely on.
    const auto stable_id  = reg.alloc_id();
    const auto stable_pk  = make_pk_stress(0xCAFEFEEDULL);
    EXPECT_EQ(reg.insert_with_index(make_record_stress(
                  stable_id, "tcp://stable", stable_pk)), GN_OK);

    std::vector<std::thread> readers;
    readers.reserve(kReaders);
    for (int r = 0; r < kReaders; ++r) {
        readers.emplace_back([&]() {
            while (!stop.load(std::memory_order_relaxed)) {
                const auto by_id = reg.find_by_id(stable_id);
                const auto by_pk = reg.find_by_pk(stable_pk);
                if (by_id != nullptr && by_pk != nullptr) {
                    read_hits.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    /// Writer churns ephemeral records.
    for (int i = 0; i < kRounds; ++i) {
        const gn_conn_id_t id = reg.alloc_id();
        const auto seed = static_cast<std::uint64_t>(i);
        const auto rec  = make_record_stress(
            id, "tcp://churn-" + std::to_string(i), make_pk_stress(seed));
        EXPECT_EQ(reg.insert_with_index(rec), GN_OK);
        EXPECT_TRUE(reg.snapshot_and_erase(id).has_value());
    }

    stop.store(true, std::memory_order_relaxed);
    for (auto& th : readers) th.join();

    /// The stable record survives the churn.
    EXPECT_NE(reg.find_by_id(stable_id), nullptr);
    /// The readers landed at least one observation while the storm
    /// was running. A zero count would mean the readers were starved
    /// out by the writer — itself worth flagging.
    EXPECT_GT(read_hits.load(), 0u);
}

}  // namespace gn::core
