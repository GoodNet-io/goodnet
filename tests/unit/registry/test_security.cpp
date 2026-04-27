/// @file   tests/unit/registry/test_security.cpp
/// @brief  GoogleTest unit tests for `gn::core::SecurityRegistry`.
///
/// Pins the contract from `docs/contracts/security-trust.md` §4: a node
/// uses one default security provider per trust class. v1 simplification
/// in `core/registry/security.hpp`: a single active provider total. The
/// registry rejects a second registration loudly and only accepts an
/// unregister against the matching provider id.

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

// ─── argument validation ────────────────────────────────────────────

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

// ─── single-active rule ─────────────────────────────────────────────

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

TEST(SecurityRegistry_SingleActive, SecondRegisterRejected) {
    SecurityRegistry r;
    int self_a = 0, self_b = 0;
    ASSERT_EQ(r.register_provider("noise",
                                   make_dummy_vtable(), &self_a),
              GN_OK);

    /// Second register — even with a different id — must fail with
    /// GN_ERR_LIMIT_REACHED per the security registry contract.
    EXPECT_EQ(r.register_provider("null",
                                   make_dummy_vtable(), &self_b),
              GN_ERR_LIMIT_REACHED);

    /// First entry remains the active one.
    auto cur = r.current();
    EXPECT_EQ(cur.provider_id, "noise");
    EXPECT_EQ(cur.self, &self_a);
}

// ─── unregister ─────────────────────────────────────────────────────

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
    EXPECT_EQ(r.unregister_provider("null"), GN_ERR_UNKNOWN_RECEIVER);
    /// Active entry untouched.
    EXPECT_TRUE(r.is_active());
    EXPECT_EQ(r.current().provider_id, "noise");
}

TEST(SecurityRegistry_Unregister, EmptyRegistryRejected) {
    SecurityRegistry r;
    EXPECT_EQ(r.unregister_provider("noise"), GN_ERR_UNKNOWN_RECEIVER);
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

// ─── current() / is_active() ────────────────────────────────────────

TEST(SecurityRegistry_Current, EmptyOnFreshInstance) {
    SecurityRegistry r;
    EXPECT_FALSE(r.is_active());
    auto cur = r.current();
    EXPECT_EQ(cur.provider_id, "");
    EXPECT_EQ(cur.vtable, nullptr);
    EXPECT_EQ(cur.self, nullptr);
}

}  // namespace
}  // namespace gn::core
