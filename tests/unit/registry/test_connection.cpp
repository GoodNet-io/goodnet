/// @file   tests/unit/registry/test_connection.cpp
/// @brief  GoogleTest unit tests for `gn::core::ConnectionRegistry`.
///
/// Exercises the contract from `docs/contracts/registry.md`:
/// monotonic id allocation, atomic three-index insert/erase, snapshot
/// lookups by id / URI / pk, and the deadlock-free claim under
/// concurrent insert and erase from multiple threads.

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <random>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <core/registry/connection.hpp>
#include <sdk/cpp/types.hpp>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::core {
namespace {

/// Build a deterministic public key from a 64-bit seed; the first 8
/// bytes carry the seed, the rest are zero.
PublicKey make_pk(std::uint64_t seed) noexcept {
    PublicKey pk{};
    std::memcpy(pk.data(), &seed, sizeof(seed));
    return pk;
}

/// Construct a fully populated record with sane defaults for testing.
ConnectionRecord make_record(gn_conn_id_t id,
                             std::string  uri,
                             PublicKey    pk) {
    ConnectionRecord r;
    r.id               = id;
    r.uri              = std::move(uri);
    r.remote_pk        = pk;
    r.trust            = GN_TRUST_PEER;
    r.transport_scheme = "tcp";
    return r;
}

// ─── alloc_id ────────────────────────────────────────────────────────

TEST(ConnectionRegistry_AllocId, MonotonicNonZero) {
    ConnectionRegistry reg;
    const gn_conn_id_t a = reg.alloc_id();
    const gn_conn_id_t b = reg.alloc_id();
    const gn_conn_id_t c = reg.alloc_id();

    EXPECT_NE(a, GN_INVALID_ID);
    EXPECT_NE(b, GN_INVALID_ID);
    EXPECT_NE(c, GN_INVALID_ID);
    EXPECT_LT(a, b);
    EXPECT_LT(b, c);
}

TEST(ConnectionRegistry_AllocId, Unique1024) {
    ConnectionRegistry reg;
    std::unordered_set<gn_conn_id_t> seen;
    for (int i = 0; i < 1024; ++i) {
        const gn_conn_id_t id = reg.alloc_id();
        ASSERT_NE(id, GN_INVALID_ID);
        ASSERT_TRUE(seen.insert(id).second) << "duplicate id at iter " << i;
    }
}

// ─── insert / find round-trip ────────────────────────────────────────

TEST(ConnectionRegistry_Insert, IdRoundTrip) {
    ConnectionRegistry reg;
    const gn_conn_id_t id = reg.alloc_id();
    const PublicKey    pk = make_pk(0x42);
    auto rec = make_record(id, "tcp://10.0.0.1:5000", pk);

    ASSERT_EQ(reg.insert_with_index(rec), GN_OK);

    auto fetched = reg.find_by_id(id);
    ASSERT_TRUE(fetched.has_value());
    if (fetched.has_value()) {
        const auto& got = *fetched;
        EXPECT_EQ(got.id, id);
        EXPECT_EQ(got.uri, "tcp://10.0.0.1:5000");
        EXPECT_EQ(got.remote_pk, pk);
        EXPECT_EQ(got.trust, GN_TRUST_PEER);
        EXPECT_EQ(got.transport_scheme, "tcp");
    }
}

TEST(ConnectionRegistry_Insert, UriIndexRoundTrip) {
    ConnectionRegistry reg;
    const gn_conn_id_t id = reg.alloc_id();
    const PublicKey    pk = make_pk(0x123);
    ASSERT_EQ(reg.insert_with_index(
        make_record(id, "tcp://host:1", pk)), GN_OK);

    auto by_uri = reg.find_by_uri("tcp://host:1");
    ASSERT_TRUE(by_uri.has_value());
    auto by_id  = reg.find_by_id(id);
    ASSERT_TRUE(by_id.has_value());
    if (by_uri.has_value() && by_id.has_value()) {
        const auto& uri_rec = *by_uri;
        const auto& id_rec  = *by_id;
        EXPECT_EQ(uri_rec.id, id_rec.id);
        EXPECT_EQ(uri_rec.uri, id_rec.uri);
        EXPECT_EQ(uri_rec.remote_pk, id_rec.remote_pk);
    }
}

TEST(ConnectionRegistry_Insert, PkIndexRoundTrip) {
    ConnectionRegistry reg;
    const gn_conn_id_t id = reg.alloc_id();
    const PublicKey    pk = make_pk(0xDEAD'BEEF);
    ASSERT_EQ(reg.insert_with_index(
        make_record(id, "tcp://host:2", pk)), GN_OK);

    auto by_pk = reg.find_by_pk(pk);
    ASSERT_TRUE(by_pk.has_value());
    auto by_id = reg.find_by_id(id);
    ASSERT_TRUE(by_id.has_value());
    if (by_pk.has_value() && by_id.has_value()) {
        const auto& pk_rec = *by_pk;
        const auto& id_rec = *by_id;
        EXPECT_EQ(pk_rec.id, id_rec.id);
        EXPECT_EQ(pk_rec.uri, id_rec.uri);
        EXPECT_EQ(pk_rec.remote_pk, id_rec.remote_pk);
    }
}

// ─── duplicate rejection (atomicity) ────────────────────────────────

TEST(ConnectionRegistry_Duplicate, IdRejectedAndAtomic) {
    ConnectionRegistry reg;
    const gn_conn_id_t id = reg.alloc_id();
    const PublicKey    pk1 = make_pk(1);
    const PublicKey    pk2 = make_pk(2);

    ASSERT_EQ(reg.insert_with_index(make_record(id, "tcp://a", pk1)), GN_OK);

    /// Re-using the same id with otherwise distinct uri+pk must fail.
    EXPECT_EQ(reg.insert_with_index(make_record(id, "tcp://b", pk2)),
              GN_ERR_LIMIT_REACHED);

    /// Atomicity: pk2 / "tcp://b" must NOT be visible.
    EXPECT_FALSE(reg.find_by_uri("tcp://b").has_value());
    EXPECT_FALSE(reg.find_by_pk(pk2).has_value());
    EXPECT_EQ(reg.size(), 1u);
}

TEST(ConnectionRegistry_Duplicate, UriRejectedAndAtomic) {
    ConnectionRegistry reg;
    const gn_conn_id_t id1 = reg.alloc_id();
    const gn_conn_id_t id2 = reg.alloc_id();
    const PublicKey    pk1 = make_pk(10);
    const PublicKey    pk2 = make_pk(11);

    ASSERT_EQ(reg.insert_with_index(make_record(id1, "tcp://shared", pk1)), GN_OK);

    EXPECT_EQ(reg.insert_with_index(make_record(id2, "tcp://shared", pk2)),
              GN_ERR_LIMIT_REACHED);

    /// Atomicity: id2 / pk2 must NOT be visible.
    EXPECT_FALSE(reg.find_by_id(id2).has_value());
    EXPECT_FALSE(reg.find_by_pk(pk2).has_value());
    EXPECT_EQ(reg.size(), 1u);
}

TEST(ConnectionRegistry_Duplicate, PkRejectedAndAtomic) {
    ConnectionRegistry reg;
    const gn_conn_id_t id1 = reg.alloc_id();
    const gn_conn_id_t id2 = reg.alloc_id();
    const PublicKey    pk  = make_pk(0xFEED);

    ASSERT_EQ(reg.insert_with_index(make_record(id1, "tcp://a", pk)), GN_OK);

    EXPECT_EQ(reg.insert_with_index(make_record(id2, "tcp://b", pk)),
              GN_ERR_LIMIT_REACHED);

    /// Atomicity: id2 / "tcp://b" must NOT be visible.
    EXPECT_FALSE(reg.find_by_id(id2).has_value());
    EXPECT_FALSE(reg.find_by_uri("tcp://b").has_value());
    EXPECT_EQ(reg.size(), 1u);
}

// ─── erase ──────────────────────────────────────────────────────────

TEST(ConnectionRegistry_Erase, RemovesFromAllIndexes) {
    ConnectionRegistry reg;
    const gn_conn_id_t id = reg.alloc_id();
    const PublicKey    pk = make_pk(7);
    ASSERT_EQ(reg.insert_with_index(make_record(id, "tcp://x", pk)), GN_OK);

    EXPECT_TRUE(reg.find_by_id(id).has_value());
    EXPECT_TRUE(reg.find_by_uri("tcp://x").has_value());
    EXPECT_TRUE(reg.find_by_pk(pk).has_value());

    ASSERT_EQ(reg.erase_with_index(id), GN_OK);

    EXPECT_FALSE(reg.find_by_id(id).has_value());
    EXPECT_FALSE(reg.find_by_uri("tcp://x").has_value());
    EXPECT_FALSE(reg.find_by_pk(pk).has_value());
    EXPECT_EQ(reg.size(), 0u);
}

TEST(ConnectionRegistry_Erase, NonExistentReturnsUnknownReceiver) {
    ConnectionRegistry reg;
    const gn_conn_id_t id = reg.alloc_id();
    EXPECT_EQ(reg.erase_with_index(id), GN_ERR_UNKNOWN_RECEIVER);
}

TEST(ConnectionRegistry_Erase, FreesKeysForReuse) {
    ConnectionRegistry reg;
    const gn_conn_id_t id1 = reg.alloc_id();
    const PublicKey    pk1 = make_pk(0x55);
    ASSERT_EQ(reg.insert_with_index(make_record(id1, "tcp://reuse", pk1)), GN_OK);
    ASSERT_EQ(reg.erase_with_index(id1), GN_OK);

    const gn_conn_id_t id2 = reg.alloc_id();
    EXPECT_EQ(reg.insert_with_index(make_record(id2, "tcp://reuse", pk1)),
              GN_OK);
}

// ─── snapshot_and_erase ─────────────────────────────────────────────

TEST(ConnectionRegistry_SnapshotAndErase, MissingIdReturnsNullopt) {
    ConnectionRegistry reg;
    EXPECT_FALSE(reg.snapshot_and_erase(99999u).has_value());
}

TEST(ConnectionRegistry_SnapshotAndErase, InvalidIdReturnsNullopt) {
    ConnectionRegistry reg;
    EXPECT_FALSE(reg.snapshot_and_erase(GN_INVALID_ID).has_value());
}

TEST(ConnectionRegistry_SnapshotAndErase, ReturnsRecordAndDropsAllIndexes) {
    ConnectionRegistry reg;
    const gn_conn_id_t id = reg.alloc_id();
    const PublicKey    pk = make_pk(0xABCDEF);
    ASSERT_EQ(reg.insert_with_index(make_record(id, "tcp://snap", pk)), GN_OK);

    auto snap = reg.snapshot_and_erase(id);
    ASSERT_TRUE(snap.has_value());
    if (snap.has_value()) {
        const auto& s = *snap;
        EXPECT_EQ(s.id,        id);
        EXPECT_EQ(s.uri,       "tcp://snap");
        EXPECT_EQ(s.remote_pk, pk);
        EXPECT_EQ(s.trust,     GN_TRUST_PEER);
    }

    EXPECT_FALSE(reg.find_by_id(id).has_value());
    EXPECT_FALSE(reg.find_by_uri("tcp://snap").has_value());
    EXPECT_FALSE(reg.find_by_pk(pk).has_value());
    EXPECT_EQ(reg.size(), 0u);
    EXPECT_EQ(reg.erase_with_index(id), GN_ERR_UNKNOWN_RECEIVER);
}

TEST(ConnectionRegistry_SnapshotAndErase, FoldsPerConnectionCounters) {
    ConnectionRegistry reg;
    const gn_conn_id_t id = reg.alloc_id();
    ASSERT_EQ(reg.insert_with_index(
                  make_record(id, "tcp://ctrs", make_pk(1))), GN_OK);

    reg.add_inbound(id,  /*bytes=*/4096, /*frames=*/8);
    reg.add_outbound(id, /*bytes=*/2048, /*frames=*/4);
    reg.set_pending_bytes(id, 512);

    auto snap = reg.snapshot_and_erase(id);
    ASSERT_TRUE(snap.has_value());
    if (snap.has_value()) {
        const auto& s = *snap;
        EXPECT_EQ(s.bytes_in,            4096u);
        EXPECT_EQ(s.bytes_out,           2048u);
        EXPECT_EQ(s.frames_in,           8u);
        EXPECT_EQ(s.frames_out,          4u);
        EXPECT_EQ(s.pending_queue_bytes, 512u);
    }
}

/// Cross-shard non-deadlock under contention: two threads each hold
/// the snapshot+erase critical section on a different shard. The
/// `scoped_lock` deadlock-avoidance from `registry.md` §3 must hold
/// for the new path too.
TEST(ConnectionRegistry_SnapshotAndErase, ConcurrentCrossShardNoDeadlock) {
    constexpr int kRounds = 64;
    ConnectionRegistry reg;

    auto id_for_shard = [&](unsigned shard) {
        for (;;) {
            const gn_conn_id_t id = reg.alloc_id();
            if ((id % 16u) == shard) return id;
        }
    };

    for (int round = 0; round < kRounds; ++round) {
        const std::uint64_t r64  = static_cast<std::uint64_t>(round);
        const gn_conn_id_t  id_a = id_for_shard(3u);
        const gn_conn_id_t  id_b = id_for_shard(11u);
        ASSERT_EQ(reg.insert_with_index(make_record(
                      id_a, "tcp://a-" + std::to_string(round),
                      make_pk(0xA00000ULL | r64))), GN_OK);
        ASSERT_EQ(reg.insert_with_index(make_record(
                      id_b, "tcp://b-" + std::to_string(round),
                      make_pk(0xB00000ULL | r64))), GN_OK);

        std::atomic<bool> go{false};
        std::atomic<int>  ready{0};
        std::atomic<int>  done{0};

        auto worker = [&](gn_conn_id_t id) {
            ready.fetch_add(1, std::memory_order_release);
            while (!go.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            EXPECT_TRUE(reg.snapshot_and_erase(id).has_value());
            done.fetch_add(1, std::memory_order_release);
        };

        std::thread t1(worker, id_a);
        std::thread t2(worker, id_b);
        while (ready.load(std::memory_order_acquire) < 2) {
            std::this_thread::yield();
        }
        const auto start = std::chrono::steady_clock::now();
        go.store(true, std::memory_order_release);
        while (done.load(std::memory_order_acquire) < 2) {
            ASSERT_LT(std::chrono::steady_clock::now() - start,
                      std::chrono::seconds(5))
                << "round " << round << ": cross-shard deadlock suspected";
            std::this_thread::yield();
        }
        t1.join();
        t2.join();
    }

    EXPECT_EQ(reg.size(), 0u);
}

/// Two threads race snapshot+erase against the same id. Exactly
/// one observes the record; the other returns `nullopt`. Holds
/// the `registry.md` §4a atomicity guarantee under contention.
TEST(ConnectionRegistry_SnapshotAndErase, ConcurrentSameIdExactlyOneSucceeds) {
    constexpr int kRounds = 256;
    ConnectionRegistry reg;

    std::atomic<int> total_hits{0};
    std::atomic<int> total_miss{0};

    for (int round = 0; round < kRounds; ++round) {
        const gn_conn_id_t id = reg.alloc_id();
        ASSERT_EQ(reg.insert_with_index(make_record(
                      id, "tcp://race-" + std::to_string(round),
                      make_pk(static_cast<std::uint64_t>(round)))), GN_OK);

        std::atomic<int> ready{0};
        std::atomic<bool> go{false};
        std::atomic<int> hits{0};

        auto worker = [&] {
            ready.fetch_add(1, std::memory_order_release);
            while (!go.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            if (reg.snapshot_and_erase(id).has_value()) {
                hits.fetch_add(1, std::memory_order_relaxed);
            }
        };

        std::thread t1(worker);
        std::thread t2(worker);
        while (ready.load(std::memory_order_acquire) < 2) {
            std::this_thread::yield();
        }
        go.store(true, std::memory_order_release);
        t1.join();
        t2.join();

        const int h = hits.load(std::memory_order_relaxed);
        ASSERT_EQ(h, 1) << "round " << round
                        << ": expected exactly one snapshot winner";
        total_hits.fetch_add(h, std::memory_order_relaxed);
        total_miss.fetch_add(2 - h, std::memory_order_relaxed);
    }

    EXPECT_EQ(total_hits.load(), kRounds);
    EXPECT_EQ(total_miss.load(), kRounds);
    EXPECT_EQ(reg.size(), 0u);
}

// ─── size() ─────────────────────────────────────────────────────────

TEST(ConnectionRegistry_Size, ReflectsInsertEraseSequence) {
    ConnectionRegistry reg;
    EXPECT_EQ(reg.size(), 0u);

    std::vector<gn_conn_id_t> ids;
    for (int i = 0; i < 5; ++i) {
        const gn_conn_id_t id = reg.alloc_id();
        ASSERT_EQ(reg.insert_with_index(make_record(
            id, "tcp://h" + std::to_string(i),
            make_pk(static_cast<std::uint64_t>(i + 100)))), GN_OK);
        ids.push_back(id);
    }
    EXPECT_EQ(reg.size(), 5u);

    ASSERT_EQ(reg.erase_with_index(ids[2]), GN_OK);
    EXPECT_EQ(reg.size(), 4u);

    ASSERT_EQ(reg.erase_with_index(ids[0]), GN_OK);
    ASSERT_EQ(reg.erase_with_index(ids[4]), GN_OK);
    EXPECT_EQ(reg.size(), 2u);
}

// ─── concurrency ─────────────────────────────────────────────────────

/// Hammer the registry from multiple threads doing interleaved
/// insert+find+erase. Verifies registry.md §3 deadlock-free claim and
/// the all-or-nothing visibility under contention.
TEST(ConnectionRegistry_Concurrency, FourThreadsInsertEraseFind) {
    constexpr int kThreads        = 4;
    constexpr int kPerThread      = 256;
    ConnectionRegistry reg;

    std::atomic<int> insert_ok{0};
    std::atomic<int> erase_ok{0};

    auto worker = [&](int tid) {
        for (int i = 0; i < kPerThread; ++i) {
            const gn_conn_id_t id  = reg.alloc_id();
            const std::uint64_t seed = (static_cast<std::uint64_t>(tid) << 32) |
                                       static_cast<std::uint64_t>(i);
            const PublicKey pk = make_pk(seed);
            const std::string uri =
                "tcp://t" + std::to_string(tid) +
                "-" + std::to_string(i);

            if (reg.insert_with_index(make_record(id, uri, pk)) == GN_OK) {
                ++insert_ok;

                /// All three indexes return the same record without
                /// external synchronisation — `registry.md` §3
                /// invariant.
                auto by_id  = reg.find_by_id(id);
                auto by_uri = reg.find_by_uri(uri);
                auto by_pk  = reg.find_by_pk(pk);
                EXPECT_TRUE(by_id.has_value());
                EXPECT_TRUE(by_uri.has_value());
                EXPECT_TRUE(by_pk.has_value());
                if (by_id && by_uri && by_pk) {
                    EXPECT_EQ(by_id->id,  id);
                    EXPECT_EQ(by_uri->id, id);
                    EXPECT_EQ(by_pk->id,  id);
                }

                /// Erase half of the inserted records concurrently;
                /// `erase_with_index` and `insert_with_index` take the
                /// same scoped_lock.
                if ((i % 2) == 0) {
                    if (reg.erase_with_index(id) == GN_OK) ++erase_ok;
                }
            }
        }
    };

    /// Wall-clock guard converts a deadlock into a test failure
    /// rather than an infinite hang.
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    const auto start = std::chrono::steady_clock::now();
    for (int t = 0; t < kThreads; ++t) threads.emplace_back(worker, t);
    for (auto& th : threads) th.join();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_EQ(insert_ok.load(), kThreads * kPerThread)
        << "all inserts must succeed: keys are unique by construction";
    EXPECT_GT(erase_ok.load(), 0);
    EXPECT_EQ(reg.size(),
              static_cast<std::size_t>(insert_ok.load() - erase_ok.load()));

    EXPECT_LT(elapsed, std::chrono::seconds(30))
        << "concurrent stress exceeded budget; deadlock or contention suspected";
}

// ─── pk hashing distribution ────────────────────────────────────────

TEST(ConnectionRegistry_PkIndex, RandomKeysAllFindable) {
    constexpr std::size_t kCount = 1024;
    ConnectionRegistry reg;

    /// Deterministic seed: a hash failure on one specific key pattern
    /// reproduces under CI on every run.
    std::mt19937_64 rng(0xC0FFEE);  // NOLINT(cert-msc32-c,cert-msc51-cpp)
    std::vector<PublicKey> keys;
    keys.reserve(kCount);

    for (std::size_t i = 0; i < kCount; ++i) {
        PublicKey pk{};
        for (auto& b : pk) b = static_cast<std::uint8_t>(rng() & 0xFF);
        const gn_conn_id_t id = reg.alloc_id();
        const std::string  uri = "tcp://pkdist/" + std::to_string(i);
        ASSERT_EQ(reg.insert_with_index(make_record(id, uri, pk)), GN_OK)
            << "iter " << i;
        keys.push_back(pk);
    }

    EXPECT_EQ(reg.size(), kCount);

    /// Every randomly generated pk must round-trip through the index.
    for (std::size_t i = 0; i < kCount; ++i) {
        auto rec = reg.find_by_pk(keys[i]);
        ASSERT_TRUE(rec.has_value()) << "pk-lookup miss at iter " << i;
        if (rec.has_value()) {
            const auto& r = *rec;
            EXPECT_EQ(r.remote_pk, keys[i]);
        }
    }
}

// ─── upgrade_trust ──────────────────────────────────────────────────

TEST(ConnectionRegistry_UpgradeTrust, UnknownIdRejected) {
    ConnectionRegistry reg;
    EXPECT_EQ(reg.upgrade_trust(reg.alloc_id(), GN_TRUST_PEER),
              GN_ERR_UNKNOWN_RECEIVER);
    EXPECT_EQ(reg.upgrade_trust(GN_INVALID_ID, GN_TRUST_PEER),
              GN_ERR_NULL_ARG);
}

TEST(ConnectionRegistry_UpgradeTrust, UntrustedToPeerSucceeds) {
    ConnectionRegistry reg;
    const auto id = reg.alloc_id();
    auto rec = make_record(id, "tcp://1.2.3.4:9000", make_pk(0xAA));
    rec.trust = GN_TRUST_UNTRUSTED;
    ASSERT_EQ(reg.insert_with_index(rec), GN_OK);

    EXPECT_EQ(reg.upgrade_trust(id, GN_TRUST_PEER), GN_OK);
    auto fetched = reg.find_by_id(id);
    ASSERT_TRUE(fetched.has_value());
    if (fetched.has_value()) {
        EXPECT_EQ(fetched->trust, GN_TRUST_PEER);
    }
}

TEST(ConnectionRegistry_UpgradeTrust, IdentityIsNoOpSuccess) {
    ConnectionRegistry reg;
    const auto id = reg.alloc_id();
    auto rec = make_record(id, "tcp://h:1", make_pk(1));
    rec.trust = GN_TRUST_LOOPBACK;
    ASSERT_EQ(reg.insert_with_index(rec), GN_OK);

    EXPECT_EQ(reg.upgrade_trust(id, GN_TRUST_LOOPBACK), GN_OK);
    auto fetched = reg.find_by_id(id);
    ASSERT_TRUE(fetched.has_value());
    if (fetched.has_value()) {
        EXPECT_EQ(fetched->trust, GN_TRUST_LOOPBACK);
    }
}

TEST(ConnectionRegistry_UpgradeTrust, LoopbackToPeerRejected) {
    ConnectionRegistry reg;
    const auto id = reg.alloc_id();
    auto rec = make_record(id, "tcp://h:2", make_pk(2));
    rec.trust = GN_TRUST_LOOPBACK;
    ASSERT_EQ(reg.insert_with_index(rec), GN_OK);

    /// `gn_trust_can_upgrade(LOOPBACK, PEER) == 0` — registry leaves
    /// the record untouched.
    EXPECT_EQ(reg.upgrade_trust(id, GN_TRUST_PEER), GN_ERR_LIMIT_REACHED);
    auto fetched = reg.find_by_id(id);
    ASSERT_TRUE(fetched.has_value());
    if (fetched.has_value()) {
        EXPECT_EQ(fetched->trust, GN_TRUST_LOOPBACK);
    }
}

TEST(ConnectionRegistry_UpgradeTrust, PeerToUntrustedRejected) {
    ConnectionRegistry reg;
    const auto id = reg.alloc_id();
    auto rec = make_record(id, "tcp://h:3", make_pk(3));
    rec.trust = GN_TRUST_PEER;
    ASSERT_EQ(reg.insert_with_index(rec), GN_OK);

    /// Downgrade is forbidden by contract; security weakening is a
    /// closure event, never a registry mutation.
    EXPECT_EQ(reg.upgrade_trust(id, GN_TRUST_UNTRUSTED),
              GN_ERR_LIMIT_REACHED);
    auto fetched = reg.find_by_id(id);
    ASSERT_TRUE(fetched.has_value());
    if (fetched.has_value()) {
        EXPECT_EQ(fetched->trust, GN_TRUST_PEER);
    }
}

}  // namespace
}  // namespace gn::core
