/// @file   tests/unit/registry/test_handler_namespaces.cpp
/// @brief  Pins the namespace axis of `HandlerRegistry`.
///
/// Per `handler-registration.md` §2 a handler registration scopes
/// to a tenant `namespace_id`; two handlers under the same
/// `(protocol_id, msg_id)` pair but different namespaces coexist;
/// `drain_by_namespace` removes every chain in one namespace
/// without touching others; backward-compat overload defaults the
/// namespace to "default".

#include <gtest/gtest.h>

#include <memory>
#include <vector>

#include <core/registry/handler.hpp>
#include <sdk/handler.h>
#include <sdk/types.h>

namespace gn::core {
namespace {

const gn_handler_vtable_t* make_dummy_vtable() {
    static const gn_handler_vtable_t vt = []() {
        gn_handler_vtable_t v{};
        v.api_size = sizeof(gn_handler_vtable_t);
        return v;
    }();
    return &vt;
}

// ── coexistence ──────────────────────────────────────────────────────────

TEST(HandlerRegistry_Namespaces, TwoNamespacesSamePairCoexist) {
    HandlerRegistry r;
    gn_handler_id_t id_a = GN_INVALID_ID;
    gn_handler_id_t id_b = GN_INVALID_ID;
    int self_a = 1;
    int self_b = 2;

    EXPECT_EQ(r.register_handler("tenant-a", "gnet-v1", /*msg_id*/ 0xCAFE,
                                  /*priority*/ 128,
                                  make_dummy_vtable(), &self_a, &id_a),
              GN_OK);
    EXPECT_EQ(r.register_handler("tenant-b", "gnet-v1", /*msg_id*/ 0xCAFE,
                                  /*priority*/ 128,
                                  make_dummy_vtable(), &self_b, &id_b),
              GN_OK);
    EXPECT_NE(id_a, id_b);
    EXPECT_EQ(r.size(), 2u);

    /// Lookup fans out across both tenants.
    auto chain = r.lookup("gnet-v1", 0xCAFE);
    ASSERT_EQ(chain.size(), 2u);
    /// Both tenants' entries land in the merged chain. Namespace
    /// is preserved on each entry so a router that wants to
    /// observe per-tenant attribution can.
    bool seen_a = false;
    bool seen_b = false;
    for (const auto& e : chain) {
        if (e.namespace_id == "tenant-a") seen_a = true;
        if (e.namespace_id == "tenant-b") seen_b = true;
    }
    EXPECT_TRUE(seen_a);
    EXPECT_TRUE(seen_b);
}

TEST(HandlerRegistry_Namespaces, NullNamespaceMapsToDefault) {
    HandlerRegistry r;
    gn_handler_id_t id = GN_INVALID_ID;
    int self = 0;

    /// Backward-compat overload (no namespace arg) goes through the
    /// default-namespace path; explicit empty string does the same.
    EXPECT_EQ(r.register_handler("gnet-v1", /*msg_id*/ 0xBEEF,
                                  /*priority*/ 128,
                                  make_dummy_vtable(), &self, &id),
              GN_OK);
    auto chain = r.lookup("gnet-v1", 0xBEEF);
    ASSERT_EQ(chain.size(), 1u);
    if (!chain.empty()) {
        EXPECT_EQ(chain.front().namespace_id, kDefaultHandlerNamespace);
    }
}

TEST(HandlerRegistry_Namespaces, ExplicitDefaultMatchesBackwardCompat) {
    HandlerRegistry r;
    gn_handler_id_t id_default_overload = GN_INVALID_ID;
    gn_handler_id_t id_explicit_default = GN_INVALID_ID;
    int self_a = 1;
    int self_b = 2;

    EXPECT_EQ(r.register_handler("gnet-v1", /*msg_id*/ 0x1, /*pri*/ 128,
                                  make_dummy_vtable(),
                                  &self_a, &id_default_overload),
              GN_OK);
    EXPECT_EQ(r.register_handler("default", "gnet-v1",
                                  /*msg_id*/ 0x1, /*pri*/ 128,
                                  make_dummy_vtable(),
                                  &self_b, &id_explicit_default),
              GN_OK);

    /// Both end up in the same default-namespace chain.
    auto chain = r.lookup("gnet-v1", 0x1);
    EXPECT_EQ(chain.size(), 2u);
    for (const auto& e : chain) {
        EXPECT_EQ(e.namespace_id, kDefaultHandlerNamespace);
    }
}

// ── drain_by_namespace ───────────────────────────────────────────────────

TEST(HandlerRegistry_Namespaces, DrainErasesOnlyMatchingNamespace) {
    HandlerRegistry r;
    gn_handler_id_t id_a = GN_INVALID_ID;
    gn_handler_id_t id_b = GN_INVALID_ID;
    int self_a = 1;
    int self_b = 2;

    ASSERT_EQ(r.register_handler("tenant-a", "gnet-v1", /*msg_id*/ 0xCAFE,
                                  128, make_dummy_vtable(), &self_a, &id_a),
              GN_OK);
    ASSERT_EQ(r.register_handler("tenant-b", "gnet-v1", /*msg_id*/ 0xCAFE,
                                  128, make_dummy_vtable(), &self_b, &id_b),
              GN_OK);

    EXPECT_EQ(r.drain_by_namespace("tenant-a"), 1u);
    EXPECT_EQ(r.size(), 1u);

    auto chain = r.lookup("gnet-v1", 0xCAFE);
    ASSERT_EQ(chain.size(), 1u);
    if (!chain.empty()) {
        EXPECT_EQ(chain.front().namespace_id, "tenant-b");
    }
}

TEST(HandlerRegistry_Namespaces, DrainGenerationBumpsPerRow) {
    HandlerRegistry r;
    gn_handler_id_t id_a = GN_INVALID_ID;
    gn_handler_id_t id_b = GN_INVALID_ID;
    int self_a = 1;
    int self_b = 2;

    ASSERT_EQ(r.register_handler("ns", "gnet-v1", /*msg_id*/ 0x1, 128,
                                  make_dummy_vtable(), &self_a, &id_a),
              GN_OK);
    ASSERT_EQ(r.register_handler("ns", "gnet-v1", /*msg_id*/ 0x2, 128,
                                  make_dummy_vtable(), &self_b, &id_b),
              GN_OK);

    const auto gen_before = r.generation();
    EXPECT_EQ(r.drain_by_namespace("ns"), 2u);
    /// Generation bumps once per removed entry; the cached-chain
    /// invalidation contract relies on the counter moving for every
    /// observable change.
    EXPECT_GE(r.generation(), gen_before + 2);
}

TEST(HandlerRegistry_Namespaces, DrainUnknownNamespaceIsNoOp) {
    HandlerRegistry r;
    gn_handler_id_t id = GN_INVALID_ID;
    int self = 0;
    ASSERT_EQ(r.register_handler("ns", "gnet-v1", 0x1, 128,
                                  make_dummy_vtable(), &self, &id),
              GN_OK);

    EXPECT_EQ(r.drain_by_namespace("does-not-exist"), 0u);
    EXPECT_EQ(r.size(), 1u);
}

// ── lifetime anchors ─────────────────────────────────────────────────────

TEST(HandlerRegistry_Namespaces, CollectAnchorsByNamespace) {
    HandlerRegistry r;
    auto anchor_a = std::make_shared<int>(1);
    auto anchor_b = std::make_shared<int>(2);
    int self = 0;
    gn_handler_id_t id_a = GN_INVALID_ID;
    gn_handler_id_t id_b = GN_INVALID_ID;

    ASSERT_EQ(r.register_handler("tenant-a", "gnet-v1", 0x1, 128,
                                  make_dummy_vtable(), &self, &id_a,
                                  anchor_a),
              GN_OK);
    ASSERT_EQ(r.register_handler("tenant-b", "gnet-v1", 0x1, 128,
                                  make_dummy_vtable(), &self, &id_b,
                                  anchor_b),
              GN_OK);

    auto anchors_a = r.collect_anchors_by_namespace("tenant-a");
    ASSERT_EQ(anchors_a.size(), 1u);
    EXPECT_FALSE(anchors_a.front().expired());

    /// The collected anchor extends past registry mutation: drain
    /// returns, but the snapshot still holds the lifetime ref.
    EXPECT_EQ(r.drain_by_namespace("tenant-a"), 1u);
    EXPECT_FALSE(anchors_a.front().expired());

    /// Drop the strong ref on the calling side; the collected
    /// weak_ptr expires when the last shared_ptr copy goes away.
    anchor_a.reset();
    EXPECT_TRUE(anchors_a.front().expired());
}

}  // namespace
}  // namespace gn::core
