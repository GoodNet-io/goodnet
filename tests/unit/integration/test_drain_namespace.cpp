/// @file   tests/unit/integration/test_drain_namespace.cpp
/// @brief  End-to-end coverage of `Kernel::drain_namespace`.
///
/// Pins the operator-driven graceful tenant teardown shape from
/// `handler-registration.md` §2:
///
/// 1. drain returns the count of erased registrations.
/// 2. The drained namespace's chains are gone immediately; other
///    namespaces remain intact.
/// 3. Captured `lifetime_anchor` weak refs drop when the kernel's
///    strong refs go away — the deadline-bounded spin-wait passes
///    because no plugin holds the anchor past quiescence.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <memory>

#include <core/kernel/kernel.hpp>
#include <core/registry/handler.hpp>
#include <sdk/handler.h>
#include <sdk/types.h>

namespace gn::core {
namespace {

const gn_handler_vtable_t* dummy_vtable() {
    static const gn_handler_vtable_t vt = []() {
        gn_handler_vtable_t v{};
        v.api_size = sizeof(gn_handler_vtable_t);
        return v;
    }();
    return &vt;
}

TEST(Kernel_DrainNamespace, RemovesOnlyMatchingNamespace) {
    Kernel kernel;
    int self_a = 1, self_b = 2;
    gn_handler_id_t id_a = GN_INVALID_ID;
    gn_handler_id_t id_b = GN_INVALID_ID;

    ASSERT_EQ(kernel.handlers().register_handler(
                  "tenant-a", "gnet-v1", /*msg_id*/ 0xCAFE,
                  /*priority*/ 128, dummy_vtable(), &self_a, &id_a),
              GN_OK);
    ASSERT_EQ(kernel.handlers().register_handler(
                  "tenant-b", "gnet-v1", /*msg_id*/ 0xCAFE,
                  /*priority*/ 128, dummy_vtable(), &self_b, &id_b),
              GN_OK);
    ASSERT_EQ(kernel.handlers().size(), 2u);

    const auto removed = kernel.drain_namespace(
        "tenant-a", std::chrono::milliseconds{100});
    EXPECT_EQ(removed, 1u);
    EXPECT_EQ(kernel.handlers().size(), 1u);

    auto chain = kernel.handlers().lookup("gnet-v1", 0xCAFE);
    ASSERT_EQ(chain.size(), 1u);
    if (!chain.empty()) {
        EXPECT_EQ(chain.front().namespace_id, "tenant-b");
    }
}

TEST(Kernel_DrainNamespace, AnchorsExpireAfterDrain) {
    Kernel kernel;
    int self = 0;
    gn_handler_id_t id = GN_INVALID_ID;

    auto anchor = std::make_shared<int>(42);
    std::weak_ptr<int> watch = anchor;

    ASSERT_EQ(kernel.handlers().register_handler(
                  "tenant-x", "gnet-v1", /*msg_id*/ 0x1, /*pri*/ 128,
                  dummy_vtable(), &self, &id, anchor),
              GN_OK);

    /// Drop the test-side strong ref so the only remaining copy is
    /// the one the registry holds. drain unregisters the entry;
    /// the kernel's spin-wait observes the weak_ptr expire and
    /// returns within the deadline.
    anchor.reset();

    const auto removed = kernel.drain_namespace(
        "tenant-x", std::chrono::milliseconds{200});
    EXPECT_EQ(removed, 1u);
    EXPECT_TRUE(watch.expired());
}

TEST(Kernel_DrainNamespace, DeadlineRespectedOnHeldAnchor) {
    Kernel kernel;
    int self = 0;
    gn_handler_id_t id = GN_INVALID_ID;

    /// Keep a strong ref so the anchor *stays alive* throughout the
    /// drain — the kernel's spin-wait then must respect the
    /// deadline cap and return without blocking forever.
    auto anchor = std::make_shared<int>(42);

    ASSERT_EQ(kernel.handlers().register_handler(
                  "tenant-stuck", "gnet-v1", /*msg_id*/ 0x1, /*pri*/ 128,
                  dummy_vtable(), &self, &id, anchor),
              GN_OK);

    const auto t0 = std::chrono::steady_clock::now();
    const auto removed = kernel.drain_namespace(
        "tenant-stuck", std::chrono::milliseconds{30});
    const auto t1 = std::chrono::steady_clock::now();
    /// The entry was unregistered immediately; only the spin-wait
    /// hit the deadline.
    EXPECT_EQ(removed, 1u);
    EXPECT_GE(t1 - t0, std::chrono::milliseconds{25});
    EXPECT_LE(t1 - t0, std::chrono::milliseconds{200});
}

TEST(Kernel_DrainNamespace, UnknownNamespaceIsNoOp) {
    Kernel kernel;
    int self = 0;
    gn_handler_id_t id = GN_INVALID_ID;
    ASSERT_EQ(kernel.handlers().register_handler(
                  "tenant-z", "gnet-v1", 0x1, 128,
                  dummy_vtable(), &self, &id),
              GN_OK);

    const auto removed = kernel.drain_namespace(
        "no-such-tenant", std::chrono::milliseconds{50});
    EXPECT_EQ(removed, 0u);
    EXPECT_EQ(kernel.handlers().size(), 1u);
}

}  // namespace
}  // namespace gn::core
