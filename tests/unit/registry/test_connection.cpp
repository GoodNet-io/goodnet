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
    r.scheme = "tcp";
    return r;
}

// ── alloc_id ─────────────────────────────────────────────────────────────

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

// ── insert / find round-trip ─────────────────────────────────────────────

TEST(ConnectionRegistry_Insert, IdRoundTrip) {
    ConnectionRegistry reg;
    const gn_conn_id_t id = reg.alloc_id();
    const PublicKey    pk = make_pk(0x42);
    auto rec = make_record(id, "tcp://10.0.0.1:5000", pk);

    ASSERT_EQ(reg.insert_with_index(rec), GN_OK);

    auto fetched = reg.find_by_id(id);
    ASSERT_NE(fetched, nullptr);
    if (fetched != nullptr) {
        const auto& got = *fetched;
        EXPECT_EQ(got.id, id);
        EXPECT_EQ(got.uri, "tcp://10.0.0.1:5000");
        EXPECT_EQ(got.remote_pk, pk);
        EXPECT_EQ(got.trust, GN_TRUST_PEER);
        EXPECT_EQ(got.scheme, "tcp");
    }
}

TEST(ConnectionRegistry_Insert, UriIndexRoundTrip) {
    ConnectionRegistry reg;
    const gn_conn_id_t id = reg.alloc_id();
    const PublicKey    pk = make_pk(0x123);
    ASSERT_EQ(reg.insert_with_index(
        make_record(id, "tcp://host:1", pk)), GN_OK);

    auto by_uri = reg.find_by_uri("tcp://host:1");
    ASSERT_NE(by_uri, nullptr);
    auto by_id  = reg.find_by_id(id);
    ASSERT_NE(by_id, nullptr);
    if (by_uri != nullptr && by_id != nullptr) {
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
    ASSERT_NE(by_pk, nullptr);
    auto by_id = reg.find_by_id(id);
    ASSERT_NE(by_id, nullptr);
    if (by_pk != nullptr && by_id != nullptr) {
        const auto& pk_rec = *by_pk;
        const auto& id_rec = *by_id;
        EXPECT_EQ(pk_rec.id, id_rec.id);
        EXPECT_EQ(pk_rec.uri, id_rec.uri);
        EXPECT_EQ(pk_rec.remote_pk, id_rec.remote_pk);
    }
}

// ── duplicate rejection (atomicity) ──────────────────────────────────────

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
    EXPECT_EQ(reg.find_by_uri("tcp://b"), nullptr);
    EXPECT_EQ(reg.find_by_pk(pk2), nullptr);
    EXPECT_EQ(reg.size(), 1u);
}

TEST(ConnectionRegistry_Duplicate, UriAdmitsMultiConn) {
    /// Multi-conn-per-peer: kernel admits N records per URI per
    /// `multi-path.ru.md`. The URI index becomes last-writer-wins;
    /// both records remain findable through `find_by_id`.
    ConnectionRegistry reg;
    const gn_conn_id_t id1 = reg.alloc_id();
    const gn_conn_id_t id2 = reg.alloc_id();
    const PublicKey    pk1 = make_pk(10);
    const PublicKey    pk2 = make_pk(11);

    ASSERT_EQ(reg.insert_with_index(make_record(id1, "tcp://shared", pk1)), GN_OK);

    EXPECT_EQ(reg.insert_with_index(make_record(id2, "tcp://shared", pk2)),
              GN_OK);

    /// Both records observable through their own conn_ids.
    EXPECT_NE(reg.find_by_id(id1), nullptr);
    EXPECT_NE(reg.find_by_id(id2), nullptr);
    EXPECT_EQ(reg.size(), 2u);

    /// `find_by_uri` returns the most recently registered conn —
    /// strategy plugins with cross-conn discipline build their own
    /// peer-level lists.
    auto by_uri = reg.find_by_uri("tcp://shared");
    ASSERT_NE(by_uri, nullptr);
    EXPECT_EQ(by_uri->id, id2);
}

TEST(ConnectionRegistry_Duplicate, PkAdmitsMultiConn) {
    /// Multi-conn-per-peer: kernel admits N records per peer_pk.
    /// Cross-session identity protection lives in
    /// `attestation_dispatcher.peer_pin_map`, not in this index.
    ConnectionRegistry reg;
    const gn_conn_id_t id1 = reg.alloc_id();
    const gn_conn_id_t id2 = reg.alloc_id();
    const PublicKey    pk  = make_pk(0xFEED);

    ASSERT_EQ(reg.insert_with_index(make_record(id1, "tcp://a", pk)), GN_OK);

    EXPECT_EQ(reg.insert_with_index(make_record(id2, "tcp://b", pk)),
              GN_OK);

    /// Both records observable through their own conn_ids.
    EXPECT_NE(reg.find_by_id(id1), nullptr);
    EXPECT_NE(reg.find_by_id(id2), nullptr);
    EXPECT_NE(reg.find_by_uri("tcp://a"), nullptr);
    EXPECT_NE(reg.find_by_uri("tcp://b"), nullptr);
    EXPECT_EQ(reg.size(), 2u);

    /// `find_by_pk` returns the most recently registered conn for
    /// that peer.
    auto by_pk = reg.find_by_pk(pk);
    ASSERT_NE(by_pk, nullptr);
    EXPECT_EQ(by_pk->id, id2);
}

// ── erase ────────────────────────────────────────────────────────────────

TEST(ConnectionRegistry_Erase, RemovesFromAllIndexes) {
    ConnectionRegistry reg;
    const gn_conn_id_t id = reg.alloc_id();
    const PublicKey    pk = make_pk(7);
    ASSERT_EQ(reg.insert_with_index(make_record(id, "tcp://x", pk)), GN_OK);

    EXPECT_NE(reg.find_by_id(id), nullptr);
    EXPECT_NE(reg.find_by_uri("tcp://x"), nullptr);
    EXPECT_NE(reg.find_by_pk(pk), nullptr);

    ASSERT_EQ(reg.erase_with_index(id), GN_OK);

    EXPECT_EQ(reg.find_by_id(id), nullptr);
    EXPECT_EQ(reg.find_by_uri("tcp://x"), nullptr);
    EXPECT_EQ(reg.find_by_pk(pk), nullptr);
    EXPECT_EQ(reg.size(), 0u);
}

TEST(ConnectionRegistry_Erase, NonExistentReturnsNotFound) {
    ConnectionRegistry reg;
    const gn_conn_id_t id = reg.alloc_id();
    EXPECT_EQ(reg.erase_with_index(id), GN_ERR_NOT_FOUND);
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

// ── snapshot_and_erase ───────────────────────────────────────────────────

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

    EXPECT_EQ(reg.find_by_id(id), nullptr);
    EXPECT_EQ(reg.find_by_uri("tcp://snap"), nullptr);
    EXPECT_EQ(reg.find_by_pk(pk), nullptr);
    EXPECT_EQ(reg.size(), 0u);
    EXPECT_EQ(reg.erase_with_index(id), GN_ERR_NOT_FOUND);
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

// ── size() ───────────────────────────────────────────────────────────────

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

// ── max_connections cap ──────────────────────────────────────────────────

TEST(ConnectionRegistry_MaxConnections, ZeroMeansUnlimited) {
    ConnectionRegistry reg;
    /// Default cap is zero; insert beyond any small bound succeeds.
    for (int i = 0; i < 32; ++i) {
        const gn_conn_id_t id = reg.alloc_id();
        ASSERT_EQ(reg.insert_with_index(make_record(
            id, "tcp://nolimit-" + std::to_string(i),
            make_pk(static_cast<std::uint64_t>(i + 9000)))), GN_OK);
    }
    EXPECT_EQ(reg.size(), 32u);
}

TEST(ConnectionRegistry_MaxConnections, RejectsBeyondCap) {
    ConnectionRegistry reg;
    reg.set_max_connections(4);

    for (int i = 0; i < 4; ++i) {
        const gn_conn_id_t id = reg.alloc_id();
        ASSERT_EQ(reg.insert_with_index(make_record(
            id, "tcp://capped-" + std::to_string(i),
            make_pk(static_cast<std::uint64_t>(i + 8000)))), GN_OK);
    }
    EXPECT_EQ(reg.size(), 4u);

    /// Fifth insert exceeds cap → LIMIT_REACHED, no slot consumed.
    const gn_conn_id_t over_id = reg.alloc_id();
    EXPECT_EQ(reg.insert_with_index(make_record(
        over_id, "tcp://capped-overflow",
        make_pk(0xDEADBEEFull))), GN_ERR_LIMIT_REACHED);
    EXPECT_EQ(reg.size(), 4u);
    EXPECT_EQ(reg.find_by_uri("tcp://capped-overflow"), nullptr);
}

TEST(ConnectionRegistry_MaxConnections, ErasureFreesSlot) {
    ConnectionRegistry reg;
    reg.set_max_connections(2);

    const gn_conn_id_t id_a = reg.alloc_id();
    const gn_conn_id_t id_b = reg.alloc_id();
    ASSERT_EQ(reg.insert_with_index(make_record(id_a, "tcp://a", make_pk(0xAA))), GN_OK);
    ASSERT_EQ(reg.insert_with_index(make_record(id_b, "tcp://b", make_pk(0xBB))), GN_OK);

    const gn_conn_id_t id_c = reg.alloc_id();
    EXPECT_EQ(reg.insert_with_index(make_record(id_c, "tcp://c", make_pk(0xCC))),
              GN_ERR_LIMIT_REACHED);

    /// Erase one — next insert succeeds.
    ASSERT_EQ(reg.erase_with_index(id_a), GN_OK);
    EXPECT_EQ(reg.insert_with_index(make_record(id_c, "tcp://c", make_pk(0xCC))), GN_OK);
    EXPECT_EQ(reg.size(), 2u);

    /// snapshot_and_erase also frees a slot.
    auto snap = reg.snapshot_and_erase(id_b);
    ASSERT_TRUE(snap.has_value());
    const gn_conn_id_t id_d = reg.alloc_id();
    EXPECT_EQ(reg.insert_with_index(make_record(id_d, "tcp://d", make_pk(0xDD))), GN_OK);
}

// ── concurrency ──────────────────────────────────────────────────────────

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
            /// `+ 1` keeps tid=0,i=0 from producing a zero pk —
            /// `insert_with_index` skips zero pk on purpose
            /// (registry.md §7a) and `find_by_pk(zero)` would miss.
            const std::uint64_t seed = ((static_cast<std::uint64_t>(tid) << 32) |
                                        static_cast<std::uint64_t>(i)) + 1;
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
                EXPECT_NE(by_id, nullptr);
                EXPECT_NE(by_uri, nullptr);
                EXPECT_NE(by_pk, nullptr);
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

// ── pk hashing distribution ──────────────────────────────────────────────

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
        ASSERT_NE(rec, nullptr) << "pk-lookup miss at iter " << i;
        if (rec != nullptr) {
            const auto& r = *rec;
            EXPECT_EQ(r.remote_pk, keys[i]);
        }
    }
}

// ── upgrade_trust ────────────────────────────────────────────────────────

TEST(ConnectionRegistry_UpgradeTrust, UnknownIdRejected) {
    ConnectionRegistry reg;
    EXPECT_EQ(reg.upgrade_trust(reg.alloc_id(), GN_TRUST_PEER),
              GN_ERR_NOT_FOUND);
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
    ASSERT_NE(fetched, nullptr);
    if (fetched != nullptr) {
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
    ASSERT_NE(fetched, nullptr);
    if (fetched != nullptr) {
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
    ASSERT_NE(fetched, nullptr);
    if (fetched != nullptr) {
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
    ASSERT_NE(fetched, nullptr);
    if (fetched != nullptr) {
        EXPECT_EQ(fetched->trust, GN_TRUST_PEER);
    }
}

// ── update_remote_pk ─────────────────────────────────────────────────────

TEST(ConnectionRegistry_UpdateRemotePk, PlaceholderToReal) {
    /// Responder path: connection inserted with a placeholder
    /// remote_pk (zeros) before the handshake completes; once the
    /// security session exposes peer_static_pk, the kernel calls
    /// `update_remote_pk` so the pk index keys on the real peer key
    /// (registry.md §7a + §8a cross-session pin gate).
    ConnectionRegistry reg;
    const gn_conn_id_t id = reg.alloc_id();
    const PublicKey placeholder{};
    ASSERT_EQ(reg.insert_with_index(
        make_record(id, "tcp://h:1", placeholder)), GN_OK);

    /// Pre-update: insert_with_index skips zero pk on purpose, so the
    /// placeholder is *not* in the pk index — many concurrent
    /// pre-handshake responders coexist without index collisions.
    EXPECT_EQ(reg.find_by_pk(placeholder), nullptr);

    const auto real_pk = make_pk(0xCAFEBABE);
    ASSERT_EQ(reg.update_remote_pk(id, real_pk), GN_OK);

    /// Post-update: real_pk indexed, placeholder still absent (no
    /// index entry to displace), record carries new pk.
    EXPECT_NE(reg.find_by_pk(real_pk), nullptr);
    EXPECT_EQ(reg.find_by_pk(placeholder), nullptr);
    auto fetched = reg.find_by_id(id);
    ASSERT_NE(fetched, nullptr);
    if (fetched != nullptr) {
        EXPECT_EQ(fetched->remote_pk, real_pk);
    }
}

TEST(ConnectionRegistry_Insert, ZeroPkSkipsPkIndex) {
    /// Many responder-side connections start life with the placeholder
    /// zero pk (TCP / WS / TLS pass `remote_pk = {}` at notify_connect
    /// because the peer is not authenticated yet). The pk index would
    /// otherwise force them into a single-zero-key conflict and reject
    /// every responder past the first; instead `insert_with_index`
    /// skips zero pk so all coexist until `update_remote_pk` lands the
    /// authenticated key.
    ConnectionRegistry reg;
    const gn_conn_id_t id_a = reg.alloc_id();
    const gn_conn_id_t id_b = reg.alloc_id();
    const PublicKey zero{};
    ASSERT_EQ(reg.insert_with_index(
        make_record(id_a, "tcp://h:1", zero)), GN_OK);
    ASSERT_EQ(reg.insert_with_index(
        make_record(id_b, "tcp://h:2", zero)), GN_OK);
    EXPECT_EQ(reg.size(), 2u);
    /// pk_index_ stays empty; lookup by zero pk reports nothing.
    EXPECT_EQ(reg.find_by_pk(zero), nullptr);
}

TEST(ConnectionRegistry_UpdateRemotePk, IdempotentNoOp) {
    /// Initiator path: rec.remote_pk already equals the peer key
    /// before the handshake (IK preset / cached peer); the post-
    /// handshake update is a no-op success.
    ConnectionRegistry reg;
    const gn_conn_id_t id = reg.alloc_id();
    const auto pk = make_pk(0x1234);
    ASSERT_EQ(reg.insert_with_index(
        make_record(id, "tcp://h:1", pk)), GN_OK);

    EXPECT_EQ(reg.update_remote_pk(id, pk), GN_OK);
    auto fetched = reg.find_by_id(id);
    ASSERT_NE(fetched, nullptr);
    if (fetched != nullptr) {
        EXPECT_EQ(fetched->remote_pk, pk);
    }
}

TEST(ConnectionRegistry_UpdateRemotePk, MultiConnUnderSamePk) {
    /// Two connections claim the same peer_pk after handshake.
    /// Multi-conn-per-peer model accepts both — kernel tracks them
    /// independently by conn_id. `find_by_pk` returns the most
    /// recently published conn; strategy plugins maintain
    /// per-peer conn lists themselves. Cross-session identity
    /// protection lives in `attestation_dispatcher.peer_pin_map`.
    ConnectionRegistry reg;
    const auto pk_a = make_pk(0xAAAA);
    const auto pk_b = make_pk(0xBBBB);
    const gn_conn_id_t id_a = reg.alloc_id();
    const gn_conn_id_t id_b = reg.alloc_id();
    ASSERT_EQ(reg.insert_with_index(
        make_record(id_a, "tcp://h:1", pk_a)), GN_OK);
    ASSERT_EQ(reg.insert_with_index(
        make_record(id_b, "tcp://h:2", pk_b)), GN_OK);

    EXPECT_EQ(reg.update_remote_pk(id_a, pk_b), GN_OK);

    /// Both records still resolve by id; peer_pk index now points
    /// to the most recently updated conn (id_a in this case —
    /// last-writer-wins).
    auto fetched_a = reg.find_by_id(id_a);
    auto fetched_b = reg.find_by_id(id_b);
    ASSERT_NE(fetched_a, nullptr);
    ASSERT_NE(fetched_b, nullptr);
    EXPECT_EQ(fetched_a->remote_pk, pk_b);
    EXPECT_EQ(fetched_b->remote_pk, pk_b);

    auto by_pk = reg.find_by_pk(pk_b);
    ASSERT_NE(by_pk, nullptr);
    EXPECT_EQ(by_pk->id, id_a);
}

TEST(ConnectionRegistry_UpdateRemotePk, UnknownIdRejected) {
    ConnectionRegistry reg;
    const auto pk = make_pk(0xDEAD);
    EXPECT_EQ(reg.update_remote_pk(/*missing*/ 9999, pk), GN_ERR_NOT_FOUND);
    EXPECT_EQ(reg.update_remote_pk(GN_INVALID_ID, pk), GN_ERR_NULL_ARG);
}

// ── Per-peer device-key pinning ──────────────────────────────────────────

TEST(ConnectionRegistry_PinDevicePk, FirstPinAccepted) {
    ConnectionRegistry reg;
    const auto peer = make_pk(1);
    const auto device = make_pk(2);
    EXPECT_EQ(reg.get_pinned_device_pk(peer), std::nullopt);
    EXPECT_EQ(reg.pin_device_pk(peer, device), GN_OK);
    auto fetched = reg.get_pinned_device_pk(peer);
    ASSERT_TRUE(fetched.has_value());
    if (fetched.has_value()) {
        EXPECT_EQ(*fetched, device);
    }
    EXPECT_EQ(reg.pin_count(), 1u);
}

TEST(ConnectionRegistry_PinDevicePk, RepinSameDeviceIdempotent) {
    ConnectionRegistry reg;
    const auto peer = make_pk(1);
    const auto device = make_pk(2);
    ASSERT_EQ(reg.pin_device_pk(peer, device), GN_OK);
    /// Same peer+device pair: idempotent success, no map growth.
    EXPECT_EQ(reg.pin_device_pk(peer, device), GN_OK);
    EXPECT_EQ(reg.pin_count(), 1u);
}

TEST(ConnectionRegistry_PinDevicePk, RepinDifferentDeviceRejected) {
    ConnectionRegistry reg;
    const auto peer = make_pk(1);
    const auto device_a = make_pk(2);
    const auto device_b = make_pk(3);
    ASSERT_EQ(reg.pin_device_pk(peer, device_a), GN_OK);
    /// Cross-session identity-change attempt: same peer, different
    /// device_pk. The registry rejects with INVALID_ENVELOPE; the
    /// caller maps the rejection to a peer disconnect.
    EXPECT_EQ(reg.pin_device_pk(peer, device_b),
              GN_ERR_INVALID_ENVELOPE);
    /// The earlier pin survives.
    auto fetched = reg.get_pinned_device_pk(peer);
    ASSERT_TRUE(fetched.has_value());
    if (fetched.has_value()) {
        EXPECT_EQ(*fetched, device_a);
    }
}

TEST(ConnectionRegistry_PinDevicePk, PinSurvivesEraseWithIndex) {
    ConnectionRegistry reg;
    const auto peer = make_pk(1);
    const auto device = make_pk(2);
    const auto id = reg.alloc_id();
    auto rec = make_record(id, "tcp://h:1", peer);
    ASSERT_EQ(reg.insert_with_index(rec), GN_OK);
    ASSERT_EQ(reg.pin_device_pk(peer, device), GN_OK);

    /// Connection close removes the record; the per-peer pin is a
    /// separate map and outlives the connection.
    ASSERT_EQ(reg.erase_with_index(id), GN_OK);
    EXPECT_EQ(reg.size(), 0u);
    auto fetched = reg.get_pinned_device_pk(peer);
    ASSERT_TRUE(fetched.has_value());
    if (fetched.has_value()) {
        EXPECT_EQ(*fetched, device);
    }
}

TEST(ConnectionRegistry_PinDevicePk, ConcurrentDifferentDeviceLeavesOneWinner) {
    /// Two threads pin the same `peer_pk` with different
    /// `device_pk` values simultaneously. Exactly one returns
    /// `GN_OK`; the other must receive `GN_ERR_INVALID_ENVELOPE`,
    /// which the dispatcher treats as an identity-change attempt
    /// and translates into a peer disconnect.
    ConnectionRegistry reg;
    const auto peer = make_pk(42);
    const auto dev_a = make_pk(1);
    const auto dev_b = make_pk(2);

    constexpr int rounds = 64;
    for (int round = 0; round < rounds; ++round) {
        ConnectionRegistry r;
        std::atomic<int> ok_count{0};
        std::atomic<int> reject_count{0};
        auto worker = [&](const PublicKey& dev) {
            const auto rc = r.pin_device_pk(peer, dev);
            if (rc == GN_OK) ok_count.fetch_add(1);
            else if (rc == GN_ERR_INVALID_ENVELOPE) reject_count.fetch_add(1);
        };
        std::thread t1([&] { worker(dev_a); });
        std::thread t2([&] { worker(dev_b); });
        t1.join();
        t2.join();
        EXPECT_EQ(ok_count.load(), 1) << "round " << round;
        EXPECT_EQ(reject_count.load(), 1) << "round " << round;
    }
    (void)reg;
}

TEST(ConnectionRegistry_PinDevicePk, ClearRemovesPin) {
    ConnectionRegistry reg;
    const auto peer = make_pk(1);
    ASSERT_EQ(reg.pin_device_pk(peer, make_pk(2)), GN_OK);
    EXPECT_EQ(reg.pin_count(), 1u);
    reg.clear_pinned_device_pk(peer);
    EXPECT_EQ(reg.get_pinned_device_pk(peer), std::nullopt);
    EXPECT_EQ(reg.pin_count(), 0u);
}

}  // namespace
}  // namespace gn::core
