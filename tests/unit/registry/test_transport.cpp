/// @file   tests/unit/registry/test_transport.cpp
/// @brief  GoogleTest unit tests for `gn::core::TransportRegistry`.
///
/// Pins the contract from `docs/contracts/host-api.md` §6 (scheme is
/// unique across loaded transports; lookups are O(1) under a shared
/// mutex) and `transport.md` §4 (id is allocated by the kernel, never
/// by transports themselves).

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <core/registry/transport.hpp>
#include <sdk/transport.h>
#include <sdk/types.h>

namespace gn::core {
namespace {

const gn_transport_vtable_t* make_dummy_vtable() {
    static const gn_transport_vtable_t vt = []() {
        gn_transport_vtable_t v{};
        v.api_size = sizeof(gn_transport_vtable_t);
        return v;
    }();
    return &vt;
}

// ─── argument validation ────────────────────────────────────────────

TEST(TransportRegistry_Args, RejectsEmptyScheme) {
    TransportRegistry r;
    gn_transport_id_t id = GN_INVALID_ID;
    EXPECT_EQ(r.register_transport("",
                                    make_dummy_vtable(),
                                    nullptr, &id),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(id, GN_INVALID_ID);
    EXPECT_EQ(r.size(), 0u);
}

TEST(TransportRegistry_Args, RejectsNullVtable) {
    TransportRegistry r;
    gn_transport_id_t id = GN_INVALID_ID;
    EXPECT_EQ(r.register_transport("tcp", nullptr, nullptr, &id),
              GN_ERR_NULL_ARG);
}

TEST(TransportRegistry_Args, RejectsNullOutId) {
    TransportRegistry r;
    EXPECT_EQ(r.register_transport("tcp", make_dummy_vtable(),
                                    nullptr, nullptr),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(r.size(), 0u);
}

TEST(TransportRegistry_Args, UnregisterInvalidIdRejected) {
    TransportRegistry r;
    EXPECT_EQ(r.unregister_transport(GN_INVALID_ID),
              GN_ERR_INVALID_ENVELOPE);
}

// ─── register / find round-trip ─────────────────────────────────────

TEST(TransportRegistry_Register, RoundTripById) {
    TransportRegistry r;
    int dummy_self = 0;
    gn_transport_id_t id = GN_INVALID_ID;
    ASSERT_EQ(r.register_transport("tcp",
                                    make_dummy_vtable(),
                                    &dummy_self, &id),
              GN_OK);
    EXPECT_NE(id, GN_INVALID_ID);
    EXPECT_EQ(r.size(), 1u);

    auto by_id = r.find_by_id(id);
    ASSERT_TRUE(by_id.has_value());
    if (by_id.has_value()) {
        EXPECT_EQ(by_id->id,     id);
        EXPECT_EQ(by_id->scheme, "tcp");
        EXPECT_EQ(by_id->vtable, make_dummy_vtable());
        EXPECT_EQ(by_id->self,   &dummy_self);
    }
}

TEST(TransportRegistry_Register, RoundTripByScheme) {
    TransportRegistry r;
    gn_transport_id_t id = GN_INVALID_ID;
    ASSERT_EQ(r.register_transport("udp",
                                    make_dummy_vtable(),
                                    nullptr, &id),
              GN_OK);
    auto by_scheme = r.find_by_scheme("udp");
    ASSERT_TRUE(by_scheme.has_value());
    if (by_scheme.has_value()) {
        EXPECT_EQ(by_scheme->id, id);
        EXPECT_EQ(by_scheme->scheme, "udp");
    }
}

TEST(TransportRegistry_Register, DuplicateSchemeRejected) {
    TransportRegistry r;
    gn_transport_id_t id1 = GN_INVALID_ID;
    gn_transport_id_t id2 = GN_INVALID_ID;
    int va = 0, vb = 0;
    ASSERT_EQ(r.register_transport("tcp", make_dummy_vtable(), &va, &id1),
              GN_OK);
    EXPECT_EQ(r.register_transport("tcp", make_dummy_vtable(), &vb, &id2),
              GN_ERR_LIMIT_REACHED);

    /// Atomicity: id2 must remain unset and registry size unchanged.
    EXPECT_EQ(id2, GN_INVALID_ID);
    EXPECT_EQ(r.size(), 1u);

    /// Original entry untouched.
    auto found = r.find_by_id(id1);
    ASSERT_TRUE(found.has_value());
    if (found.has_value()) {
        EXPECT_EQ(found->self, &va);
    }
}

TEST(TransportRegistry_Register, DistinctSchemesGetDistinctIds) {
    TransportRegistry r;
    gn_transport_id_t id1 = GN_INVALID_ID;
    gn_transport_id_t id2 = GN_INVALID_ID;
    ASSERT_EQ(r.register_transport("tcp", make_dummy_vtable(),
                                    nullptr, &id1), GN_OK);
    ASSERT_EQ(r.register_transport("udp", make_dummy_vtable(),
                                    nullptr, &id2), GN_OK);
    EXPECT_NE(id1, id2);
    EXPECT_EQ(r.size(), 2u);
}

// ─── miss paths ─────────────────────────────────────────────────────

TEST(TransportRegistry_Find, MissReturnsNullopt) {
    TransportRegistry r;
    EXPECT_FALSE(r.find_by_scheme("tcp").has_value());
    EXPECT_FALSE(r.find_by_id(static_cast<gn_transport_id_t>(42)).has_value());
}

// ─── unregister ─────────────────────────────────────────────────────

TEST(TransportRegistry_Unregister, RemovesEntry) {
    TransportRegistry r;
    gn_transport_id_t id = GN_INVALID_ID;
    ASSERT_EQ(r.register_transport("tcp", make_dummy_vtable(),
                                    nullptr, &id), GN_OK);
    ASSERT_EQ(r.unregister_transport(id), GN_OK);
    EXPECT_EQ(r.size(), 0u);
    EXPECT_FALSE(r.find_by_id(id).has_value());
    EXPECT_FALSE(r.find_by_scheme("tcp").has_value());
}

TEST(TransportRegistry_Unregister, NonExistentReturnsUnknownReceiver) {
    TransportRegistry r;
    /// Some random plausible id with a non-zero pattern.
    EXPECT_EQ(r.unregister_transport(static_cast<gn_transport_id_t>(99)),
              GN_ERR_UNKNOWN_RECEIVER);
}

TEST(TransportRegistry_Unregister, FreesSchemeForReuse) {
    TransportRegistry r;
    gn_transport_id_t id1 = GN_INVALID_ID;
    gn_transport_id_t id2 = GN_INVALID_ID;
    ASSERT_EQ(r.register_transport("tcp", make_dummy_vtable(),
                                    nullptr, &id1), GN_OK);
    ASSERT_EQ(r.unregister_transport(id1), GN_OK);
    EXPECT_EQ(r.register_transport("tcp", make_dummy_vtable(),
                                    nullptr, &id2), GN_OK);
}

// ─── concurrent register stress ─────────────────────────────────────

/// Hammer the registry from multiple threads doing distinct-scheme
/// register + unregister + find. Verifies deadlock-free claim and the
/// scheme-uniqueness rule under contention.
TEST(TransportRegistry_Concurrency, FourThreadsRegisterUnregister) {
    constexpr int kThreads   = 4;
    constexpr int kPerThread = 128;
    TransportRegistry r;

    std::atomic<int> reg_ok{0};
    std::atomic<int> unreg_ok{0};
    std::vector<gn_transport_id_t> ids;
    std::mutex ids_mu;

    auto worker = [&](int tid) {
        for (int i = 0; i < kPerThread; ++i) {
            std::string scheme =
                "scheme-t" + std::to_string(tid) + "-" + std::to_string(i);
            gn_transport_id_t id = GN_INVALID_ID;
            if (r.register_transport(scheme, make_dummy_vtable(),
                                      nullptr, &id) == GN_OK) {
                ++reg_ok;
                {
                    std::lock_guard lock{ids_mu};
                    ids.push_back(id);
                }
                /// Round-trip: id must resolve back to the same scheme.
                auto by_id = r.find_by_id(id);
                EXPECT_TRUE(by_id.has_value());
                if (by_id) {
                    EXPECT_EQ(by_id->scheme, scheme);
                }

                /// Erase half to interleave unregister against
                /// concurrent inserts.
                if ((i % 2) == 0) {
                    if (r.unregister_transport(id) == GN_OK) {
                        ++unreg_ok;
                    }
                }
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

    EXPECT_EQ(reg_ok.load(), kThreads * kPerThread)
        << "every scheme is unique by construction; all inserts must succeed";

    /// Issued ids must be unique.
    std::unordered_set<gn_transport_id_t> uniq(ids.begin(), ids.end());
    EXPECT_EQ(uniq.size(), ids.size());
    EXPECT_GT(unreg_ok.load(), 0);
    EXPECT_EQ(r.size(),
              static_cast<std::size_t>(reg_ok.load() - unreg_ok.load()));
}

// ─── §3a vtable api_size validation ─────────────────────────────────

TEST(TransportRegistry_VtableApiSize, RejectsZeroApiSize) {
    /// `abi-evolution.md` §3a: a vtable that declares an api_size
    /// smaller than the kernel's known minimum is from an SDK older
    /// than the slots the kernel intends to call. Reject before any
    /// slot lookup.
    TransportRegistry r;
    gn_transport_vtable_t vt{};  /// api_size left at zero
    gn_transport_id_t id = GN_INVALID_ID;
    EXPECT_EQ(r.register_transport("tcp", &vt, nullptr, &id),
              GN_ERR_VERSION_MISMATCH);
    EXPECT_EQ(id, GN_INVALID_ID);
    EXPECT_EQ(r.size(), 0u);
}

TEST(TransportRegistry_VtableApiSize, RejectsTruncatedVtable) {
    TransportRegistry r;
    gn_transport_vtable_t vt{};
    /// Producer claims it is older than even the minimum kernel
    /// build; one byte short is enough to fail the §3a check.
    vt.api_size = static_cast<std::uint32_t>(
        sizeof(gn_transport_vtable_t) - 1);
    gn_transport_id_t id = GN_INVALID_ID;
    EXPECT_EQ(r.register_transport("tcp", &vt, nullptr, &id),
              GN_ERR_VERSION_MISMATCH);
    EXPECT_EQ(id, GN_INVALID_ID);
}

TEST(TransportRegistry_VtableApiSize, AcceptsExactlyMinimumApiSize) {
    TransportRegistry r;
    gn_transport_vtable_t vt{};
    vt.api_size = sizeof(gn_transport_vtable_t);
    gn_transport_id_t id = GN_INVALID_ID;
    EXPECT_EQ(r.register_transport("tcp", &vt, nullptr, &id), GN_OK);
    EXPECT_NE(id, GN_INVALID_ID);
}

}  // namespace
}  // namespace gn::core
