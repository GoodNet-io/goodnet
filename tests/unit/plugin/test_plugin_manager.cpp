/// @file   tests/unit/plugin/test_plugin_manager.cpp
/// @brief  PluginManager: load → register → quiescence drain → dlclose.
///
/// Uses the real `null` security provider .so to drive the manager
/// end-to-end, so the test exercises every step from `dlopen` to the
/// reference-counted ownership drain wait that gates `dlclose`. The
/// path to the .so is injected via the build-system define
/// `GOODNET_NULL_PLUGIN_PATH` (mirrors `tests/unit/plugins/security/test_null.cpp`).

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <core/kernel/kernel.hpp>
#include <core/plugin/plugin_manager.hpp>
#include <core/registry/security.hpp>

#ifndef GOODNET_NULL_PLUGIN_PATH
#error "GOODNET_NULL_PLUGIN_PATH must be defined by the build system"
#endif

using namespace gn::core;

namespace {

std::vector<std::string> just_null_plugin() {
    return {GOODNET_NULL_PLUGIN_PATH};
}

} // namespace

TEST(PluginManager_LoadShutdown, RoundTrips) {
    Kernel k;
    PluginManager pm(k);

    std::string diag;
    ASSERT_EQ(pm.load(just_null_plugin(), &diag), GN_OK)
        << "diag: " << diag;
    EXPECT_EQ(pm.size(), 1u);
    EXPECT_TRUE(k.security().is_active())
        << "null provider must register itself with the security registry";

    pm.shutdown();
    EXPECT_EQ(pm.size(), 0u);
    EXPECT_FALSE(k.security().is_active())
        << "shutdown must roll back every plugin's registrations";
}

TEST(PluginManager_LoadShutdown, IdempotentShutdown) {
    Kernel k;
    PluginManager pm(k);

    ASSERT_EQ(pm.load(just_null_plugin()), GN_OK);
    pm.shutdown();
    pm.shutdown();  // second call must no-op without crashing
    EXPECT_EQ(pm.size(), 0u);
    EXPECT_EQ(pm.leaked_handles(), 0u);
}

TEST(PluginManager_Quiescence, DrainsCleanlyWithNoSnapshots) {
    /// Steady-state shutdown: no snapshots are alive, so the drain
    /// completes on the first poll and `leaked_handles()` stays zero.
    Kernel k;
    PluginManager pm(k);
    ASSERT_EQ(pm.load(just_null_plugin()), GN_OK);

    pm.shutdown();
    EXPECT_EQ(pm.leaked_handles(), 0u);
}

TEST(PluginManager_Quiescence, WaitsForOutstandingSnapshot) {
    /// Hold a security `current()` snapshot across the shutdown call.
    /// The snapshot's `lifetime_anchor` keeps the plugin's reference
    /// count above zero; the manager's drain loop must observe the
    /// release as soon as the snapshot is dropped on this thread.
    Kernel k;
    PluginManager pm(k);
    ASSERT_EQ(pm.load(just_null_plugin()), GN_OK);

    SecurityEntry snap = k.security().current();
    EXPECT_NE(snap.vtable, nullptr);
    EXPECT_NE(snap.lifetime_anchor.get(), nullptr)
        << "register through host_api must thread the anchor onto the entry";

    /// Worker drops the snapshot after a short delay so the manager
    /// observes the drain completing rather than timing out.
    std::thread worker([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
        snap = SecurityEntry{};  // releases the anchor
    });

    /// Use a 1s timeout — plenty of head-room for the 20ms worker.
    pm.set_quiescence_timeout(std::chrono::seconds{1});
    pm.shutdown();
    worker.join();

    EXPECT_EQ(pm.leaked_handles(), 0u)
        << "snapshot was released before timeout; no leak expected";
}

TEST(PluginManager_Quiescence, TimeoutLeaksHandleSafely) {
    /// Force a timeout by holding a snapshot longer than the timeout.
    /// The manager must not block forever; it must instead leak the
    /// dlclose handle (count it for visibility) so async callbacks
    /// remain safe.
    Kernel k;
    PluginManager pm(k);
    ASSERT_EQ(pm.load(just_null_plugin()), GN_OK);

    SecurityEntry snap = k.security().current();
    ASSERT_NE(snap.lifetime_anchor.get(), nullptr);

    pm.set_quiescence_timeout(std::chrono::milliseconds{50});
    const auto t0 = std::chrono::steady_clock::now();
    pm.shutdown();
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);

    EXPECT_GE(elapsed.count(), 40)
        << "shutdown returned suspiciously early; drain may not have waited";
    EXPECT_LT(elapsed.count(), 1000)
        << "timeout was 50ms; shutdown must not block past it";
    EXPECT_EQ(pm.leaked_handles(), 1u)
        << "one plugin's dlclose must be leaked when the snapshot is held";

    /// Releasing the snapshot now (after dlclose was skipped) is the
    /// last reference; the control block disappears cleanly. The
    /// .so stays mapped — that's the safe-leak property.
    snap = SecurityEntry{};
}
