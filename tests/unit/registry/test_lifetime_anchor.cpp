/// @file   tests/unit/registry/test_lifetime_anchor.cpp
/// @brief  Plugin-quiescence anchor flows through every registry.
///
/// `plugin-lifetime.md` §4 mandates that registry entries hold a
/// reference-counted handle on the plugin's quiescence sentinel and
/// that dispatch-time snapshots inherit the handle by value-copy so
/// the underlying shared object cannot be unmapped while a snapshot
/// is in flight. The tests here pin the anchor's flow through each
/// of the four registries and verify the drain-wait observable
/// (`weak_ptr::expired()`) behaves the way `PluginManager` relies on.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>

#include <core/registry/extension.hpp>
#include <core/registry/handler.hpp>
#include <core/registry/security.hpp>
#include <core/registry/link.hpp>

#include <sdk/handler.h>
#include <sdk/security.h>
#include <sdk/link.h>
#include <sdk/types.h>

namespace {

const gn_handler_vtable_t* dummy_handler_vtable() {
    static const gn_handler_vtable_t vt = []() {
        gn_handler_vtable_t v{};
        v.api_size = sizeof(gn_handler_vtable_t);
        return v;
    }();
    return &vt;
}

const gn_link_vtable_t* dummy_transport_vtable() {
    static const gn_link_vtable_t vt = []() {
        gn_link_vtable_t v{};
        v.api_size = sizeof(gn_link_vtable_t);
        return v;
    }();
    return &vt;
}

const gn_security_provider_vtable_t* dummy_security_vtable() {
    static const gn_security_provider_vtable_t vt = []() {
        gn_security_provider_vtable_t v{};
        v.api_size = sizeof(gn_security_provider_vtable_t);
        return v;
    }();
    return &vt;
}

} // namespace

using namespace gn::core;

// ─── HandlerRegistry: anchor copies into entry, snapshot inherits ───

TEST(HandlerAnchor, RegistryEntryHoldsAnchor) {
    HandlerRegistry reg;

    auto anchor = std::make_shared<int>(0);
    std::weak_ptr<int> watch = anchor;

    gn_handler_id_t id = GN_INVALID_ID;
    ASSERT_EQ(reg.register_handler("gnet-v1", 1, 128,
                                   dummy_handler_vtable(), nullptr,
                                   &id, anchor),
              GN_OK);

    /// Now drop the local strong ref; only the registry's copy
    /// remains. The control block must still be alive.
    anchor.reset();
    EXPECT_FALSE(watch.expired())
        << "registry must hold its own strong ref to the anchor";

    /// Unregister releases the registry's copy.
    ASSERT_EQ(reg.unregister_handler(id), GN_OK);
    EXPECT_TRUE(watch.expired())
        << "anchor must release once the entry is removed";
}

TEST(HandlerAnchor, LookupSnapshotInheritsAnchor) {
    HandlerRegistry reg;

    auto anchor = std::make_shared<int>(0);
    std::weak_ptr<int> watch = anchor;

    gn_handler_id_t id = GN_INVALID_ID;
    ASSERT_EQ(reg.register_handler("gnet-v1", 7, 128,
                                   dummy_handler_vtable(), nullptr,
                                   &id, anchor),
              GN_OK);

    /// Take a dispatch-time snapshot. This is the moment that the
    /// quiescence pattern protects: the snapshot vector lives until
    /// the dispatch loop ends, and during that window the registered
    /// vtable pointer is dereferenced. Any concurrent unload must
    /// see the anchor still alive.
    auto snapshot = reg.lookup("gnet-v1", 7);
    ASSERT_EQ(snapshot.size(), 1u);

    /// Drop both the registry entry and the local strong ref.
    /// Only the snapshot's anchor copy remains.
    ASSERT_EQ(reg.unregister_handler(id), GN_OK);
    anchor.reset();

    EXPECT_FALSE(watch.expired())
        << "snapshot inherited anchor must keep the plugin alive";

    /// Once the snapshot dies, the last reference goes with it.
    snapshot.clear();
    EXPECT_TRUE(watch.expired());
}

// ─── LinkRegistry: same shape ──────────────────────────────────

TEST(LinkAnchor, EntryHoldsAnchorThroughLookup) {
    LinkRegistry reg;

    auto anchor = std::make_shared<int>(0);
    std::weak_ptr<int> watch = anchor;

    gn_link_id_t id = GN_INVALID_ID;
    ASSERT_EQ(reg.register_link("test-scheme",
                                     dummy_transport_vtable(),
                                     nullptr, &id, anchor),
              GN_OK);

    auto snapshot = reg.find_by_scheme("test-scheme");
    ASSERT_TRUE(snapshot.has_value());

    anchor.reset();
    ASSERT_EQ(reg.unregister_link(id), GN_OK);
    EXPECT_FALSE(watch.expired())
        << "transport snapshot must keep the .so mapped via the anchor";

    snapshot.reset();
    EXPECT_TRUE(watch.expired());
}

// ─── ExtensionRegistry: prefix snapshot inherits anchor ─────────────

TEST(ExtensionAnchor, PrefixSnapshotInheritsAnchor) {
    ExtensionRegistry reg;

    auto anchor = std::make_shared<int>(0);
    std::weak_ptr<int> watch = anchor;

    /// vtable pointer is opaque to the registry; any non-null
    /// address works as a marker.
    int marker = 0;
    ASSERT_EQ(reg.register_extension("gn.heartbeat", 0x01000000u,
                                     &marker, anchor),
              GN_OK);

    auto matches = reg.query_prefix("gn.");
    ASSERT_EQ(matches.size(), 1u);

    anchor.reset();
    ASSERT_EQ(reg.unregister_extension("gn.heartbeat"), GN_OK);
    EXPECT_FALSE(watch.expired())
        << "extension prefix snapshot must keep the producing plugin alive";

    matches.clear();
    EXPECT_TRUE(watch.expired());
}

// ─── SecurityRegistry: current() snapshot inherits anchor ───────────

TEST(SecurityAnchor, CurrentSnapshotInheritsAnchor) {
    SecurityRegistry reg;

    auto anchor = std::make_shared<int>(0);
    std::weak_ptr<int> watch = anchor;

    ASSERT_EQ(reg.register_provider("test-provider",
                                    dummy_security_vtable(), nullptr,
                                    anchor),
              GN_OK);

    auto snapshot = reg.current();
    EXPECT_EQ(snapshot.provider_id, "test-provider");

    anchor.reset();
    ASSERT_EQ(reg.unregister_provider("test-provider"), GN_OK);
    EXPECT_FALSE(watch.expired())
        << "security current() snapshot must keep the provider alive";

    snapshot = SecurityEntry{};
    EXPECT_TRUE(watch.expired());
}

// ─── Drain primitive: weak_ptr.expired() polling models PluginManager
// ─── unload semantics. The kernel-side "drain" is a wait on this
// ─── observable; the test spins it up against a real concurrent
// ─── snapshot to verify the timing assumption.

TEST(QuiescenceDrain, WaitObservesSnapshotRelease) {
    HandlerRegistry reg;

    auto anchor = std::make_shared<int>(0);
    std::weak_ptr<int> watch = anchor;

    gn_handler_id_t id = GN_INVALID_ID;
    ASSERT_EQ(reg.register_handler("gnet-v1", 11, 128,
                                   dummy_handler_vtable(), nullptr,
                                   &id, anchor),
              GN_OK);

    /// Worker takes a snapshot, pretends to dispatch for 30ms,
    /// then releases.
    std::atomic<bool> snapshot_taken{false};
    std::thread worker([&] {
        auto snap = reg.lookup("gnet-v1", 11);
        ASSERT_EQ(snap.size(), 1u);
        snapshot_taken.store(true, std::memory_order_release);
        std::this_thread::sleep_for(std::chrono::milliseconds{30});
        /// snap goes out of scope here, releasing its anchor copy.
    });

    /// Wait until the worker has the snapshot.
    while (!snapshot_taken.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::microseconds{100});
    }

    /// Simulate the unload: unregister, drop the local strong ref.
    ASSERT_EQ(reg.unregister_handler(id), GN_OK);
    anchor.reset();

    /// At this instant, only the worker's snapshot holds the anchor.
    /// `expired()` must be false until the worker returns.
    EXPECT_FALSE(watch.expired())
        << "worker still has a snapshot; anchor must be alive";

    /// Drain loop, mirroring PluginManager::drain_anchor logic.
    using clock = std::chrono::steady_clock;
    const auto deadline = clock::now() + std::chrono::seconds{1};
    auto interval = std::chrono::microseconds{100};
    while (!watch.expired()) {
        ASSERT_LT(clock::now(), deadline)
            << "anchor failed to drain within 1s; likely a leak";
        std::this_thread::sleep_for(interval);
        if (interval < std::chrono::milliseconds{1}) interval *= 2;
    }

    worker.join();
    EXPECT_TRUE(watch.expired());
}

TEST(QuiescenceDrain, EmptyAnchorIsImmediate) {
    /// Tests/in-tree code that doesn't load through PluginManager
    /// passes a default-empty anchor. The registries must accept
    /// it without surprise; the resulting weak_ptr is immediately
    /// expired, modelling "no quiescence wait needed".
    HandlerRegistry reg;
    gn_handler_id_t id = GN_INVALID_ID;
    ASSERT_EQ(reg.register_handler("gnet-v1", 1, 128,
                                   dummy_handler_vtable(), nullptr,
                                   &id),
              GN_OK);

    auto snap = reg.lookup("gnet-v1", 1);
    ASSERT_EQ(snap.size(), 1u);

    /// Empty shared_ptr → empty weak_ptr → expired().
    std::weak_ptr<void> watch = snap[0].lifetime_anchor;
    EXPECT_TRUE(watch.expired());

    ASSERT_EQ(reg.unregister_handler(id), GN_OK);
}
