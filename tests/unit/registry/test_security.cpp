/// @file   tests/unit/registry/test_security.cpp
/// @brief  GoogleTest unit tests for `gn::core::SecurityRegistry`.
///
/// Pins the StackRegistry contract from
/// `docs/contracts/security-trust.md` §5: a kernel admits N security
/// providers concurrently, each declaring `allowed_trust_mask`. The
/// registry rejects a duplicate `provider_id`, but distinct ids
/// (e.g. `gn.security.null` + `gn.security.noise`) coexist so the
/// `notify_connect` path can route by trust class.

#include <gtest/gtest.h>

#include <core/registry/security.hpp>
#include <sdk/security.h>
#include <sdk/types.h>

namespace gn::core {
namespace {

/// Build a no-op vtable. Registry never invokes through it; the
/// pointer identity is the only observable property.
const gn_security_provider_vtable_t* make_dummy_vtable() {
    static const gn_security_provider_vtable_t vt = []() {
        gn_security_provider_vtable_t v{};
        v.api_size = sizeof(gn_security_provider_vtable_t);
        return v;
    }();
    return &vt;
}

// ── argument validation ──────────────────────────────────────────────────

TEST(SecurityRegistry_Args, RegisterRejectsEmptyId) {
    SecurityRegistry r;
    EXPECT_EQ(r.register_provider("", make_dummy_vtable(), nullptr),
              GN_ERR_NULL_ARG);
    EXPECT_FALSE(r.is_active());
}

TEST(SecurityRegistry_Args, RegisterRejectsNullVtable) {
    SecurityRegistry r;
    EXPECT_EQ(r.register_provider("noise", nullptr, nullptr),
              GN_ERR_NULL_ARG);
    EXPECT_FALSE(r.is_active());
}

// ── single-active rule ───────────────────────────────────────────────────

TEST(SecurityRegistry_SingleActive, FirstRegisterSucceeds) {
    SecurityRegistry r;
    int dummy_self = 0;
    EXPECT_FALSE(r.is_active());
    ASSERT_EQ(r.register_provider("noise",
                                   make_dummy_vtable(),
                                   &dummy_self),
              GN_OK);
    EXPECT_TRUE(r.is_active());

    auto cur = r.current();
    EXPECT_EQ(cur.provider_id, "noise");
    EXPECT_EQ(cur.vtable, make_dummy_vtable());
    EXPECT_EQ(cur.self, &dummy_self);
}

TEST(SecurityRegistry_SingleActive, DistinctIdsCoexist) {
    SecurityRegistry r;
    int self_a = 0, self_b = 0;
    ASSERT_EQ(r.register_provider("noise",
                                   make_dummy_vtable(), &self_a),
              GN_OK);

    /// StackRegistry contract: registering a SECOND provider with a
    /// DISTINCT id (`null` alongside `noise`) succeeds — that is the
    /// canonical "null on loopback + noise on peer" stack the v1.x
    /// design promised.
    EXPECT_EQ(r.register_provider("null",
                                   make_dummy_vtable(), &self_b),
              GN_OK);
    EXPECT_TRUE(r.is_active());

    /// First-registered is what `current()` returns for the back-
    /// compat callers.
    auto cur = r.current();
    EXPECT_EQ(cur.provider_id, "noise");
    EXPECT_EQ(cur.self, &self_a);
}

TEST(SecurityRegistry_SingleActive, DuplicateIdRejected) {
    SecurityRegistry r;
    int self_a = 0, self_b = 0;
    ASSERT_EQ(r.register_provider("noise",
                                   make_dummy_vtable(), &self_a),
              GN_OK);
    /// Same provider_id → reject. The kernel admits one entry per
    /// name regardless of registration multiplicity.
    EXPECT_EQ(r.register_provider("noise",
                                   make_dummy_vtable(), &self_b),
              GN_ERR_LIMIT_REACHED);

    auto cur = r.current();
    EXPECT_EQ(cur.provider_id, "noise");
    EXPECT_EQ(cur.self, &self_a);
}

// ── unregister ───────────────────────────────────────────────────────────

TEST(SecurityRegistry_Unregister, RemovesActive) {
    SecurityRegistry r;
    ASSERT_EQ(r.register_provider("noise",
                                   make_dummy_vtable(), nullptr),
              GN_OK);
    ASSERT_TRUE(r.is_active());
    ASSERT_EQ(r.unregister_provider("noise"), GN_OK);
    EXPECT_FALSE(r.is_active());
    EXPECT_EQ(r.current().provider_id, "");
}

TEST(SecurityRegistry_Unregister, WrongIdRejected) {
    SecurityRegistry r;
    ASSERT_EQ(r.register_provider("noise",
                                   make_dummy_vtable(), nullptr),
              GN_OK);

    /// Unregister with the wrong id must fail.
    EXPECT_EQ(r.unregister_provider("null"), GN_ERR_NOT_FOUND);
    /// Active entry untouched.
    EXPECT_TRUE(r.is_active());
    EXPECT_EQ(r.current().provider_id, "noise");
}

TEST(SecurityRegistry_Unregister, EmptyRegistryRejected) {
    SecurityRegistry r;
    EXPECT_EQ(r.unregister_provider("noise"), GN_ERR_NOT_FOUND);
}

TEST(SecurityRegistry_Unregister, AllowsReregisterAfterRemoval) {
    SecurityRegistry r;
    int self_a = 0, self_b = 0;
    ASSERT_EQ(r.register_provider("noise",
                                   make_dummy_vtable(), &self_a),
              GN_OK);
    ASSERT_EQ(r.unregister_provider("noise"), GN_OK);

    /// After removal, registering a fresh provider succeeds.
    ASSERT_EQ(r.register_provider("null",
                                   make_dummy_vtable(), &self_b),
              GN_OK);
    EXPECT_EQ(r.current().provider_id, "null");
    EXPECT_EQ(r.current().self, &self_b);
}

// ── current() / is_active() ──────────────────────────────────────────────

// ── find_for_trust (StackRegistry v1.x preview) ──────────────────────────

namespace {

/// Build a vtable whose `allowed_trust_mask` thunk returns @p mask.
/// The static lambda-captured-int trick gives us a per-test static
/// storage slot; safe because tests run single-threaded.
template <std::uint32_t Mask>
const gn_security_provider_vtable_t* make_vtable_with_mask() {
    static const gn_security_provider_vtable_t vt = []() {
        gn_security_provider_vtable_t v{};
        v.api_size = sizeof(gn_security_provider_vtable_t);
        v.allowed_trust_mask = [](void*) -> std::uint32_t { return Mask; };
        return v;
    }();
    return &vt;
}

constexpr std::uint32_t kMaskLoopbackIntra =
    (1u << GN_TRUST_LOOPBACK) | (1u << GN_TRUST_INTRA_NODE);
constexpr std::uint32_t kMaskAllFour =
    (1u << GN_TRUST_UNTRUSTED) | (1u << GN_TRUST_PEER) |
    (1u << GN_TRUST_LOOPBACK) | (1u << GN_TRUST_INTRA_NODE);

}  // namespace

TEST(SecurityRegistry_FindForTrust, NullProviderWinsLoopback) {
    SecurityRegistry r;
    int null_self = 0, noise_self = 0;
    ASSERT_EQ(r.register_provider("null",
        make_vtable_with_mask<kMaskLoopbackIntra>(), &null_self), GN_OK);
    ASSERT_EQ(r.register_provider("noise",
        make_vtable_with_mask<kMaskAllFour>(), &noise_self), GN_OK);

    /// Both providers admit Loopback — first-registered wins, so
    /// the kernel routes loopback through `null` for the fast
    /// plaintext path.
    auto picked = r.find_for_trust(GN_TRUST_LOOPBACK);
    EXPECT_EQ(picked.provider_id, "null");
    EXPECT_EQ(picked.self, &null_self);
}

TEST(SecurityRegistry_FindForTrust, NoiseWinsUntrustedWhenNullCannotServe) {
    SecurityRegistry r;
    int null_self = 0, noise_self = 0;
    ASSERT_EQ(r.register_provider("null",
        make_vtable_with_mask<kMaskLoopbackIntra>(), &null_self), GN_OK);
    ASSERT_EQ(r.register_provider("noise",
        make_vtable_with_mask<kMaskAllFour>(), &noise_self), GN_OK);

    /// Untrusted is outside `null`'s mask, so the search falls
    /// through to noise.
    auto picked = r.find_for_trust(GN_TRUST_UNTRUSTED);
    EXPECT_EQ(picked.provider_id, "noise");
    EXPECT_EQ(picked.self, &noise_self);
}

TEST(SecurityRegistry_FindForTrust, NoProviderAdmitsClass) {
    SecurityRegistry r;
    int null_self = 0;
    ASSERT_EQ(r.register_provider("null",
        make_vtable_with_mask<kMaskLoopbackIntra>(), &null_self), GN_OK);

    /// `null` doesn't admit Peer; no other provider registered →
    /// empty entry.
    auto picked = r.find_for_trust(GN_TRUST_PEER);
    EXPECT_EQ(picked.provider_id, "");
    EXPECT_EQ(picked.vtable, nullptr);
}

TEST(SecurityRegistry_FindForTrust, EmptyRegistryReturnsEmpty) {
    SecurityRegistry r;
    auto picked = r.find_for_trust(GN_TRUST_LOOPBACK);
    EXPECT_EQ(picked.provider_id, "");
}

TEST(SecurityRegistry_Current, EmptyOnFreshInstance) {
    SecurityRegistry r;
    EXPECT_FALSE(r.is_active());
    auto cur = r.current();
    EXPECT_EQ(cur.provider_id, "");
    EXPECT_EQ(cur.vtable, nullptr);
    EXPECT_EQ(cur.self, nullptr);
}

// ── §3a vtable api_size validation ───────────────────────────────────────

TEST(SecurityRegistry_VtableApiSize, RejectsZeroApiSize) {
    /// `abi-evolution.md` §3a: zero-init vtable carries an api_size
    /// of zero, smaller than the kernel's minimum; reject before
    /// activation.
    SecurityRegistry r;
    gn_security_provider_vtable_t vt{};
    EXPECT_EQ(r.register_provider("noise", &vt, nullptr),
              GN_ERR_VERSION_MISMATCH);
    EXPECT_FALSE(r.is_active());
}

TEST(SecurityRegistry_VtableApiSize, AcceptsExactlyMinimumApiSize) {
    SecurityRegistry r;
    gn_security_provider_vtable_t vt{};
    vt.api_size = sizeof(gn_security_provider_vtable_t);
    EXPECT_EQ(r.register_provider("noise", &vt, nullptr), GN_OK);
    EXPECT_TRUE(r.is_active());
}

}  // namespace
}  // namespace gn::core
