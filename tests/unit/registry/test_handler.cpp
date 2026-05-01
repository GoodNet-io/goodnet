/// @file   tests/unit/registry/test_handler.cpp
/// @brief  GoogleTest unit tests for `gn::core::HandlerRegistry`.
///
/// Exercises the contract from `docs/contracts/handler-registration.md`:
/// rejection of malformed registrations, priority chain ordering with
/// insertion-order tie-breaking, per-protocol namespace isolation,
/// generation counter advancement, max-chain-length cap, and the
/// concurrent register/unregister stress claim.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <vector>

#include <core/registry/handler.hpp>
#include <sdk/handler.h>
#include <sdk/types.h>

namespace gn::core {
namespace {

/// Construct a vtable with all entries set to safe no-ops. Every test
/// uses the same singleton via `dummy_vtable()`; the registry never
/// invokes through it.
const gn_handler_vtable_t* dummy_vtable() {
    static const gn_handler_vtable_t vt = []() {
        gn_handler_vtable_t v{};
        v.api_size = sizeof(gn_handler_vtable_t);
        return v;
    }();
    return &vt;
}

/// Wrapper that returns the new id in a value rather than via out-pointer.
gn_handler_id_t reg_or_die(HandlerRegistry& r,
                           std::string_view protocol,
                           std::uint32_t    msg_id,
                           std::uint8_t     priority) {
    gn_handler_id_t id = GN_INVALID_ID;
    EXPECT_EQ(r.register_handler(protocol, msg_id, priority,
                                 dummy_vtable(), nullptr, &id),
              GN_OK);
    EXPECT_NE(id, GN_INVALID_ID);
    return id;
}

// ─── argument validation ────────────────────────────────────────────

TEST(HandlerRegistry_Args, RejectsNullVtable) {
    HandlerRegistry reg;
    gn_handler_id_t id = GN_INVALID_ID;
    EXPECT_EQ(reg.register_handler("gnet-v1", 1, 128, nullptr, nullptr, &id),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(id, GN_INVALID_ID);
    EXPECT_EQ(reg.size(), 0u);
}

TEST(HandlerRegistry_Args, RejectsNullOutId) {
    HandlerRegistry reg;
    EXPECT_EQ(reg.register_handler("gnet-v1", 1, 128,
                                   dummy_vtable(), nullptr, nullptr),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(reg.size(), 0u);
}

TEST(HandlerRegistry_Args, RejectsEmptyProtocolId) {
    HandlerRegistry reg;
    gn_handler_id_t id = GN_INVALID_ID;
    EXPECT_EQ(reg.register_handler("", 1, 128,
                                   dummy_vtable(), nullptr, &id),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(id, GN_INVALID_ID);
    EXPECT_EQ(reg.size(), 0u);
}

TEST(HandlerRegistry_Args, RejectsVtableWithSmallerApiSize) {
    /// `abi-evolution.md` §3a: a producer-declared `api_size` smaller
    /// than the kernel's struct minimum is rejected before any slot
    /// lookup. Mirrors the `register_transport` and
    /// `register_provider` defensive size-prefix check.
    HandlerRegistry reg;
    gn_handler_vtable_t shrunk{};
    shrunk.api_size = 0;
    gn_handler_id_t id = GN_INVALID_ID;
    EXPECT_EQ(reg.register_handler("gnet-v1", 1, 128,
                                   &shrunk, nullptr, &id),
              GN_ERR_VERSION_MISMATCH);
    EXPECT_EQ(id, GN_INVALID_ID);
    EXPECT_EQ(reg.size(), 0u);
}

TEST(HandlerRegistry_Args, RejectsZeroMsgId) {
    HandlerRegistry reg;
    gn_handler_id_t id = GN_INVALID_ID;
    EXPECT_EQ(reg.register_handler("gnet-v1", 0, 128,
                                   dummy_vtable(), nullptr, &id),
              GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(id, GN_INVALID_ID);
    EXPECT_EQ(reg.size(), 0u);
}

TEST(HandlerRegistry_Args, RejectsReservedAttestationMsgId) {
    /// Per `handler-registration.md` §2a — `0x11` is reserved for
    /// the kernel-internal attestation dispatcher
    /// (`attestation.md` §3). Plugin registration must be rejected
    /// regardless of `protocol_id`.
    HandlerRegistry reg;
    gn_handler_id_t id = GN_INVALID_ID;
    EXPECT_EQ(reg.register_handler("gnet-v1", 0x11, 128,
                                   dummy_vtable(), nullptr, &id),
              GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(id, GN_INVALID_ID);
    EXPECT_EQ(reg.register_handler("any-other-proto", 0x11, 200,
                                   dummy_vtable(), nullptr, &id),
              GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(reg.size(), 0u);
}

// ─── register / lookup ──────────────────────────────────────────────

TEST(HandlerRegistry_Lookup, RegistersAndLooksUp) {
    HandlerRegistry reg;
    const gn_handler_id_t id = reg_or_die(reg, "gnet-v1", 0x42, 128);

    auto chain = reg.lookup("gnet-v1", 0x42);
    ASSERT_EQ(chain.size(), 1u);
    EXPECT_EQ(chain[0].id,          id);
    EXPECT_EQ(chain[0].protocol_id, "gnet-v1");
    EXPECT_EQ(chain[0].msg_id,      0x42u);
    EXPECT_EQ(chain[0].priority,    128);
    EXPECT_EQ(chain[0].vtable,      dummy_vtable());
    EXPECT_EQ(reg.size(), 1u);
}

TEST(HandlerRegistry_Lookup, MissReturnsEmpty) {
    HandlerRegistry reg;
    EXPECT_TRUE(reg.lookup("nope", 1).empty());
    reg_or_die(reg, "gnet-v1", 1, 128);
    EXPECT_TRUE(reg.lookup("gnet-v1", 2).empty());
    EXPECT_TRUE(reg.lookup("mesh-v2", 1).empty());
}

// ─── priority + insertion-order ─────────────────────────────────────

TEST(HandlerRegistry_Priority, HigherPriorityFirst) {
    HandlerRegistry reg;
    const gn_handler_id_t low  = reg_or_die(reg, "gnet-v1", 5, 64);
    const gn_handler_id_t high = reg_or_die(reg, "gnet-v1", 5, 200);
    const gn_handler_id_t mid  = reg_or_die(reg, "gnet-v1", 5, 128);

    auto chain = reg.lookup("gnet-v1", 5);
    ASSERT_EQ(chain.size(), 3u);
    EXPECT_EQ(chain[0].id, high);
    EXPECT_EQ(chain[1].id, mid);
    EXPECT_EQ(chain[2].id, low);
}

TEST(HandlerRegistry_Priority, EqualPrioritySortedByInsertion) {
    HandlerRegistry reg;
    const gn_handler_id_t a = reg_or_die(reg, "gnet-v1", 7, 128);
    const gn_handler_id_t b = reg_or_die(reg, "gnet-v1", 7, 128);
    const gn_handler_id_t c = reg_or_die(reg, "gnet-v1", 7, 128);

    auto chain = reg.lookup("gnet-v1", 7);
    ASSERT_EQ(chain.size(), 3u);
    EXPECT_EQ(chain[0].id, a);
    EXPECT_EQ(chain[1].id, b);
    EXPECT_EQ(chain[2].id, c);

    /// Insertion-seq must be strictly increasing.
    EXPECT_LT(chain[0].insertion_seq, chain[1].insertion_seq);
    EXPECT_LT(chain[1].insertion_seq, chain[2].insertion_seq);
}

TEST(HandlerRegistry_Priority, HighPriorityLateOvertakesEqualEarlier) {
    HandlerRegistry reg;
    const gn_handler_id_t a = reg_or_die(reg, "gnet-v1", 3, 128);
    const gn_handler_id_t b = reg_or_die(reg, "gnet-v1", 3, 128);
    const gn_handler_id_t hi = reg_or_die(reg, "gnet-v1", 3, 200);

    auto chain = reg.lookup("gnet-v1", 3);
    ASSERT_EQ(chain.size(), 3u);
    EXPECT_EQ(chain[0].id, hi);
    EXPECT_EQ(chain[1].id, a);
    EXPECT_EQ(chain[2].id, b);
}

// ─── per-protocol namespace isolation ───────────────────────────────

TEST(HandlerRegistry_Namespace, ProtocolsAreIsolated) {
    HandlerRegistry reg;
    const gn_handler_id_t gnet_id = reg_or_die(reg, "gnet-v1", 0x42, 128);
    const gn_handler_id_t mesh_id = reg_or_die(reg, "mesh-v2", 0x42, 128);

    auto gnet_chain = reg.lookup("gnet-v1", 0x42);
    auto mesh_chain = reg.lookup("mesh-v2", 0x42);

    ASSERT_EQ(gnet_chain.size(), 1u);
    ASSERT_EQ(mesh_chain.size(), 1u);
    EXPECT_EQ(gnet_chain[0].id, gnet_id);
    EXPECT_EQ(mesh_chain[0].id, mesh_id);
    EXPECT_NE(gnet_id, mesh_id);
}

TEST(HandlerRegistry_Namespace, MsgIdsAreIsolated) {
    HandlerRegistry reg;
    reg_or_die(reg, "gnet-v1", 1, 128);
    reg_or_die(reg, "gnet-v1", 1, 200);
    reg_or_die(reg, "gnet-v1", 2, 128);

    EXPECT_EQ(reg.lookup("gnet-v1", 1).size(), 2u);
    EXPECT_EQ(reg.lookup("gnet-v1", 2).size(), 1u);
    EXPECT_EQ(reg.lookup("gnet-v1", 3).size(), 0u);
}

// ─── unregister ─────────────────────────────────────────────────────

TEST(HandlerRegistry_Unregister, RemovesEntry) {
    HandlerRegistry reg;
    const gn_handler_id_t a = reg_or_die(reg, "gnet-v1", 9, 128);
    const gn_handler_id_t b = reg_or_die(reg, "gnet-v1", 9, 200);

    EXPECT_EQ(reg.lookup("gnet-v1", 9).size(), 2u);
    EXPECT_EQ(reg.unregister_handler(a), GN_OK);

    auto chain = reg.lookup("gnet-v1", 9);
    ASSERT_EQ(chain.size(), 1u);
    EXPECT_EQ(chain[0].id, b);
    EXPECT_EQ(reg.size(), 1u);
}

TEST(HandlerRegistry_Unregister, NonExistentReturnsNotFound) {
    HandlerRegistry reg;
    EXPECT_EQ(reg.unregister_handler(424242), GN_ERR_NOT_FOUND);

    const gn_handler_id_t id = reg_or_die(reg, "gnet-v1", 1, 128);
    ASSERT_EQ(reg.unregister_handler(id), GN_OK);
    /// Second unregister on the now-stale id must also fail.
    EXPECT_EQ(reg.unregister_handler(id), GN_ERR_NOT_FOUND);
}

TEST(HandlerRegistry_Unregister, RejectsInvalidId) {
    HandlerRegistry reg;
    EXPECT_EQ(reg.unregister_handler(GN_INVALID_ID),
              GN_ERR_INVALID_ENVELOPE);
}

TEST(HandlerRegistry_Unregister, EmptiesChainAndAllowsReuse) {
    HandlerRegistry reg;
    const gn_handler_id_t a = reg_or_die(reg, "gnet-v1", 11, 128);
    ASSERT_EQ(reg.unregister_handler(a), GN_OK);
    EXPECT_TRUE(reg.lookup("gnet-v1", 11).empty());

    /// Re-registering on the same key after a chain has been emptied
    /// must succeed and produce a fresh dispatch chain.
    const gn_handler_id_t b = reg_or_die(reg, "gnet-v1", 11, 128);
    auto chain = reg.lookup("gnet-v1", 11);
    ASSERT_EQ(chain.size(), 1u);
    EXPECT_EQ(chain[0].id, b);
}

// ─── generation counter ─────────────────────────────────────────────

TEST(HandlerRegistry_Generation, IncrementsOnRegisterAndUnregister) {
    HandlerRegistry reg;
    const std::uint64_t g0 = reg.generation();

    const gn_handler_id_t id = reg_or_die(reg, "gnet-v1", 1, 128);
    const std::uint64_t g1 = reg.generation();
    EXPECT_GT(g1, g0);

    reg_or_die(reg, "gnet-v1", 1, 128);
    const std::uint64_t g2 = reg.generation();
    EXPECT_GT(g2, g1);

    ASSERT_EQ(reg.unregister_handler(id), GN_OK);
    const std::uint64_t g3 = reg.generation();
    EXPECT_GT(g3, g2);
}

TEST(HandlerRegistry_Generation, FailedRegisterKeepsGeneration) {
    HandlerRegistry reg;
    reg.set_max_chain_length(1);
    reg_or_die(reg, "gnet-v1", 1, 128);
    const std::uint64_t before = reg.generation();

    /// Cap-violating register must not change the generation; cached
    /// chain snapshots in dispatchers stay valid.
    gn_handler_id_t id = GN_INVALID_ID;
    EXPECT_EQ(reg.register_handler("gnet-v1", 1, 128,
                                   dummy_vtable(), nullptr, &id),
              GN_ERR_LIMIT_REACHED);
    EXPECT_EQ(reg.generation(), before);
}

TEST(HandlerRegistry_Generation, LookupWithGenerationReturnsAtomicPair) {
    HandlerRegistry reg;
    reg_or_die(reg, "gnet-v1", 7, 128);

    const auto snap = reg.lookup_with_generation("gnet-v1", 7);
    EXPECT_EQ(snap.chain.size(), 1u);
    EXPECT_EQ(snap.generation, reg.generation())
        << "atomic pair: generation captured at lookup must match the "
           "live counter while no concurrent mutation has run";
}

TEST(HandlerRegistry_Generation, GenerationStaleAfterConcurrentMutation) {
    /// `lookup_with_generation` returns a snapshot of the chain
    /// alongside the generation counter inside the same shared
    /// lock; after another writer lands, `r.generation()` exceeds
    /// the recorded value. A future hot-reload dispatcher uses
    /// that gap to decide whether to re-fetch the chain.
    HandlerRegistry reg;
    reg_or_die(reg, "gnet-v1", 9, 128);

    const auto snap = reg.lookup_with_generation("gnet-v1", 9);
    const std::uint64_t recorded = snap.generation;

    /// Land a second registration on the same key.
    reg_or_die(reg, "gnet-v1", 9, 64);

    EXPECT_GT(reg.generation(), recorded)
        << "post-mutation live generation must exceed the snapshot's";
    /// The snapshot's chain still reflects the pre-mutation state —
    /// the dispatcher walks a consistent view even though the
    /// registry has moved on.
    EXPECT_EQ(snap.chain.size(), 1u);
}

TEST(HandlerRegistry_Generation, EmptyChainStillCarriesGeneration) {
    HandlerRegistry reg;
    /// Even a lookup that hits no chain returns the live generation
    /// counter so a dispatcher's first call after startup gets a
    /// reference value to compare against.
    const auto snap = reg.lookup_with_generation("never-registered", 42);
    EXPECT_TRUE(snap.chain.empty());
    EXPECT_EQ(snap.generation, reg.generation());
}

// ─── max_chain_length cap ───────────────────────────────────────────

TEST(HandlerRegistry_Cap, ThirdRegistrationRejectedAtCap2) {
    HandlerRegistry reg;
    reg.set_max_chain_length(2);
    EXPECT_EQ(reg.max_chain_length(), 2u);

    const gn_handler_id_t a = reg_or_die(reg, "gnet-v1", 1, 128);
    const gn_handler_id_t b = reg_or_die(reg, "gnet-v1", 1, 128);

    gn_handler_id_t c = GN_INVALID_ID;
    EXPECT_EQ(reg.register_handler("gnet-v1", 1, 128,
                                   dummy_vtable(), nullptr, &c),
              GN_ERR_LIMIT_REACHED);

    /// First two remain registered, c is unset.
    auto chain = reg.lookup("gnet-v1", 1);
    ASSERT_EQ(chain.size(), 2u);
    EXPECT_EQ(chain[0].id, a);
    EXPECT_EQ(chain[1].id, b);
    EXPECT_EQ(c, GN_INVALID_ID);
    EXPECT_EQ(reg.size(), 2u);
}

TEST(HandlerRegistry_Cap, ZeroDisablesEnforcement) {
    /// Per `limits.md §4a`: a cap of zero disables the check.
    HandlerRegistry reg;
    reg.set_max_chain_length(0);
    EXPECT_EQ(reg.max_chain_length(), 0u);

    /// Register sixteen handlers on the same key. None should
    /// be rejected when the cap is disabled.
    for (int i = 0; i < 16; ++i) {
        gn_handler_id_t id = GN_INVALID_ID;
        ASSERT_EQ(reg.register_handler("gnet-v1", 1, 128,
                                       dummy_vtable(), nullptr, &id),
                  GN_OK)
            << "registration #" << i << " rejected with cap=0";
        EXPECT_NE(id, GN_INVALID_ID);
    }
    EXPECT_EQ(reg.lookup("gnet-v1", 1).size(), 16u);
}

TEST(HandlerRegistry_Cap, IsPerKeyNotGlobal) {
    HandlerRegistry reg;
    reg.set_max_chain_length(1);

    /// One handler on (gnet-v1, 1).
    reg_or_die(reg, "gnet-v1", 1, 128);
    /// Different key must still admit a registration.
    const gn_handler_id_t other = reg_or_die(reg, "gnet-v1", 2, 128);
    EXPECT_NE(other, GN_INVALID_ID);

    /// And the original key blocks further registrations.
    gn_handler_id_t blocked = GN_INVALID_ID;
    EXPECT_EQ(reg.register_handler("gnet-v1", 1, 128,
                                   dummy_vtable(), nullptr, &blocked),
              GN_ERR_LIMIT_REACHED);
}

// ─── concurrent register / unregister ───────────────────────────────

TEST(HandlerRegistry_Concurrency, FourThreadsRegisterUnregister) {
    constexpr int kThreads   = 4;
    constexpr int kPerThread = 256;
    HandlerRegistry reg;
    reg.set_max_chain_length(1024);  // generous: avoid spurious cap rejections

    std::atomic<int>  reg_ok{0};
    std::atomic<int>  unreg_ok{0};
    std::mutex        ids_mu;
    std::vector<gn_handler_id_t> all_ids;
    all_ids.reserve(static_cast<std::size_t>(kThreads) *
                    static_cast<std::size_t>(kPerThread));

    auto worker = [&](int tid) {
        std::vector<gn_handler_id_t> mine;
        mine.reserve(kPerThread);

        for (int i = 0; i < kPerThread; ++i) {
            gn_handler_id_t id = GN_INVALID_ID;
            const std::uint32_t msg_id =
                static_cast<std::uint32_t>((tid << 16) | (i + 1));
            const std::uint8_t prio =
                static_cast<std::uint8_t>(
                    (static_cast<unsigned>(i) * 17u) & 0xFFu);

            if (reg.register_handler("gnet-v1", msg_id, prio,
                                     dummy_vtable(), nullptr, &id) == GN_OK) {
                ++reg_ok;
                mine.push_back(id);
            }

            /// Unregister every other to interleave register and unregister
            /// against the registry-wide mutex.
            if ((i % 2) == 0 && !mine.empty()) {
                if (reg.unregister_handler(mine.back()) == GN_OK) {
                    ++unreg_ok;
                    mine.pop_back();
                }
            }
        }

        std::lock_guard lock{ids_mu};
        all_ids.insert(all_ids.end(), mine.begin(), mine.end());
    };

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    const auto start = std::chrono::steady_clock::now();
    for (int t = 0; t < kThreads; ++t) threads.emplace_back(worker, t);
    for (auto& th : threads) th.join();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    /// Every accepted id must be unique. The id allocator is the
    /// observable consistency check the contract exposes.
    std::unordered_set<gn_handler_id_t> uniq(all_ids.begin(), all_ids.end());
    EXPECT_EQ(uniq.size(), all_ids.size())
        << "duplicate handler ids returned across threads";

    EXPECT_EQ(static_cast<std::size_t>(reg_ok.load() - unreg_ok.load()),
              all_ids.size());
    EXPECT_EQ(reg.size(), all_ids.size());

    EXPECT_LT(elapsed, std::chrono::seconds(30))
        << "concurrent stress took unexpectedly long; possible deadlock";
}

}  // namespace
}  // namespace gn::core
