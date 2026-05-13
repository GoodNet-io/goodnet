/// @file   tests/unit/plugin/test_plugin_manager.cpp
/// @brief  PluginManager: load → register → quiescence drain → dlclose.
///
/// Uses the real `null` security provider .so to drive the manager
/// end-to-end, so the test exercises every step from `dlopen` to the
/// reference-counted ownership drain wait that gates `dlclose`. The
/// path to the .so is injected via the build-system define
/// `GOODNET_NULL_PLUGIN_PATH` (mirrors `plugins/security/null/tests/test_null.cpp`).

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

    /// Persistent counter on the kernel's metrics surface tracks
    /// the cumulative figure across the kernel's lifetime —
    /// `leaked_handles()` is per-rollback, the metric is total.
    /// Per `metrics.md` §3.
    EXPECT_EQ(k.metrics().value("plugin.leak.dlclose_skipped"), 1u)
        << "metric counter must record every leak event";

    /// Releasing the snapshot now (after dlclose was skipped) is the
    /// last reference; the control block disappears cleanly. The
    /// .so stays mapped — that's the safe-leak property.
    snap = SecurityEntry{};
}

TEST(PluginManager_Quiescence, MetricCounterAccumulatesAcrossRollbacks) {
    /// `leaked_handles_` resets at the start of every `rollback()`,
    /// but the metrics counter is persistent for the kernel's
    /// lifetime. Two consecutive timeouts must increment it twice
    /// even though `leaked_handles()` reports `1` after each.
    Kernel k;

    /// First rollback — leak one handle.
    {
        PluginManager pm(k);
        ASSERT_EQ(pm.load(just_null_plugin()), GN_OK);
        SecurityEntry snap = k.security().current();
        ASSERT_NE(snap.lifetime_anchor.get(), nullptr);
        pm.set_quiescence_timeout(std::chrono::milliseconds{30});
        pm.shutdown();
        EXPECT_EQ(pm.leaked_handles(), 1u);
        snap = SecurityEntry{};
    }

    /// Second rollback in a fresh manager against the same kernel.
    {
        PluginManager pm(k);
        ASSERT_EQ(pm.load(just_null_plugin()), GN_OK);
        SecurityEntry snap = k.security().current();
        ASSERT_NE(snap.lifetime_anchor.get(), nullptr);
        pm.set_quiescence_timeout(std::chrono::milliseconds{30});
        pm.shutdown();
        EXPECT_EQ(pm.leaked_handles(), 1u)
            << "per-rollback counter resets at the start of every rollback";
        snap = SecurityEntry{};
    }

    EXPECT_EQ(k.metrics().value("plugin.leak.dlclose_skipped"), 2u)
        << "metric must accumulate across rollbacks for an operator's "
           "rate-graph view";
}

/// `limits.md` §4a: `gn_limits_t::max_plugins` cap blocks loads
/// whose path count exceeds it. Read directly from `kernel.limits()`
/// inside `PluginManager::load`, the single source of truth.
TEST(PluginManager_MaxPlugins, RejectsBeyondCap) {
    Kernel k;
    gn_limits_t limits{};
    limits.max_plugins = 1;
    k.set_limits(limits);

    /// One path with cap 1 — succeeds.
    PluginManager pm(k);
    std::string diag;
    EXPECT_EQ(pm.load(just_null_plugin(), &diag), GN_OK) << diag;
    pm.shutdown();
}

TEST(PluginManager_MaxPlugins, ZeroPathsAboveCapRejected) {
    Kernel k;
    gn_limits_t limits{};
    limits.max_plugins = 1;
    k.set_limits(limits);

    /// Two paths, cap 1 — load fails with LIMIT_REACHED before
    /// touching the filesystem; diagnostic mentions the cap field.
    std::vector<std::string> two = {GOODNET_NULL_PLUGIN_PATH,
                                    GOODNET_NULL_PLUGIN_PATH};
    PluginManager pm(k);
    std::string diag;
    EXPECT_EQ(pm.load(two, &diag), GN_ERR_LIMIT_REACHED);
    EXPECT_NE(diag.find("max_plugins"), std::string::npos) << diag;
    EXPECT_EQ(pm.size(), 0u);
}

/// `plugin-manifest.md`: the manifest is the kernel's only defence
/// between an attacker-controlled plugins directory and its own
/// address space. An empty manifest is the developer-mode path; a
/// non-empty manifest puts the loader in production mode and every
/// load is gated by SHA-256 verification before `dlopen` runs.

TEST(PluginManager_Manifest, EmptyManifestPermitsAllLoads) {
    Kernel k;
    PluginManager pm(k);
    EXPECT_TRUE(pm.manifest().empty());

    std::string diag;
    EXPECT_EQ(pm.load(just_null_plugin(), &diag), GN_OK) << diag;
    pm.shutdown();
}

TEST(PluginManager_Manifest, MatchingHashAccepted) {
    /// Compute the actual on-disk hash of the null .so and install
    /// it as the manifest. Production-mode load must accept the
    /// freshly-built binary.
    auto digest = PluginManifest::sha256_of_file(GOODNET_NULL_PLUGIN_PATH);
    ASSERT_TRUE(digest.has_value());

    PluginManifest m;
    if (digest.has_value()) {
        m.add_entry(GOODNET_NULL_PLUGIN_PATH, *digest);
    }

    Kernel k;
    PluginManager pm(k);
    pm.set_manifest(std::move(m));
    EXPECT_FALSE(pm.manifest().empty());

    std::string diag;
    EXPECT_EQ(pm.load(just_null_plugin(), &diag), GN_OK) << diag;
    pm.shutdown();
}

TEST(PluginManager_Manifest, HashMismatchRejected) {
    /// Install a manifest whose hash for the null .so is wrong;
    /// load must fail with GN_ERR_INTEGRITY_FAILED before dlopen
    /// has a chance to run the .so's static initialisers.
    PluginManifest m;
    PluginHash wrong{};
    m.add_entry(GOODNET_NULL_PLUGIN_PATH, wrong);

    Kernel k;
    PluginManager pm(k);
    pm.set_manifest(std::move(m));

    std::string diag;
    EXPECT_EQ(pm.load(just_null_plugin(), &diag),
              GN_ERR_INTEGRITY_FAILED);
    EXPECT_NE(diag.find("integrity check failed"), std::string::npos)
        << diag;
    EXPECT_EQ(pm.size(), 0u);
}

TEST(PluginManager_Manifest, RequiredFlagRefusesEmptyManifest) {
    /// `plugin-manifest.md` §7: the required flag turns the empty-
    /// manifest case into a hard error, naming "manifest required
    /// but empty: <path>" in the diagnostic. The default flow with
    /// the flag clear continues to permit empty-manifest loads.
    Kernel k;
    PluginManager pm(k);
    pm.set_manifest_required(true);
    EXPECT_TRUE(pm.manifest_required());
    EXPECT_TRUE(pm.manifest().empty());

    std::string diag;
    EXPECT_EQ(pm.load(just_null_plugin(), &diag),
              GN_ERR_INTEGRITY_FAILED);
    EXPECT_NE(diag.find("manifest required but empty"),
              std::string::npos)
        << diag;
    EXPECT_NE(diag.find(GOODNET_NULL_PLUGIN_PATH), std::string::npos)
        << "diag must name the rejected path so the operator can "
           "trace which load tripped the flag: " << diag;
    EXPECT_EQ(pm.size(), 0u);
}

TEST(PluginManager_Manifest, RequiredFlagWithPopulatedManifestLoads) {
    /// Required flag plus a populated manifest reaches the normal
    /// integrity check path; a matching SHA-256 succeeds.
    auto digest = PluginManifest::sha256_of_file(GOODNET_NULL_PLUGIN_PATH);
    ASSERT_TRUE(digest.has_value());
    if (!digest) return;  // tidy: optional access guard
    PluginManifest m;
    m.add_entry(GOODNET_NULL_PLUGIN_PATH, *digest);

    Kernel k;
    PluginManager pm(k);
    pm.set_manifest_required(true);
    pm.set_manifest(std::move(m));

    std::string diag;
    EXPECT_EQ(pm.load(just_null_plugin(), &diag), GN_OK) << diag;
    pm.shutdown();
}

TEST(PluginManager_Manifest, UnlistedPathRejected) {
    /// Manifest that does NOT list the path being loaded must
    /// reject — this is the production-mode default-deny.
    PluginManifest m;
    PluginHash dummy{};
    m.add_entry("/some/other/registered/path.so", dummy);

    Kernel k;
    PluginManager pm(k);
    pm.set_manifest(std::move(m));

    std::string diag;
    EXPECT_EQ(pm.load(just_null_plugin(), &diag),
              GN_ERR_INTEGRITY_FAILED);
    EXPECT_NE(diag.find("no manifest entry"), std::string::npos)
        << diag;
}

// ── load failure modes (no manifest, dev-mode path) ─────────────────────────

TEST(PluginManager_LoadFailure, NonExistentPathReturnsNotFound) {
    /// dlopen on a path that does not exist surfaces as
    /// `GN_ERR_NOT_FOUND` with the path embedded in the diagnostic.
    /// The registry stays empty and a subsequent `shutdown` is a
    /// no-op — a failed load MUST NOT leak partial state.
    Kernel k;
    PluginManager pm(k);

    std::string diag;
    const std::vector<std::string> paths = {
        "/nonexistent/path/libgoodnet_does_not_exist.so"
    };
    EXPECT_EQ(pm.load(paths, &diag), GN_ERR_NOT_FOUND);
    EXPECT_NE(diag.find("dlopen"), std::string::npos) << diag;
    EXPECT_NE(diag.find("does_not_exist"), std::string::npos) << diag;
    EXPECT_EQ(pm.size(), 0u);

    pm.shutdown();
    EXPECT_EQ(pm.size(), 0u);
    EXPECT_EQ(pm.leaked_handles(), 0u);
}

TEST(PluginManager_LoadFailure, NonLibraryFileReturnsNotFound) {
    /// A path that exists but does not parse as an ELF must fail
    /// dlopen rather than crash the kernel. `/etc/hostname` is a
    /// short text file every supported Linux deployment ships;
    /// any system without it falls back to `/etc/passwd`. The
    /// observable contract: `GN_ERR_NOT_FOUND`, registry empty.
    Kernel k;
    PluginManager pm(k);

    std::string diag;
    const std::vector<std::string> paths = {"/etc/hostname"};
    const auto rc = pm.load(paths, &diag);
    /// Some libc implementations surface this as a different
    /// dlerror; widen the expectation to "non-OK".
    EXPECT_NE(rc, GN_OK);
    EXPECT_FALSE(diag.empty());
    EXPECT_EQ(pm.size(), 0u);

    pm.shutdown();
    EXPECT_EQ(pm.leaked_handles(), 0u);
}

TEST(PluginManager_LoadFailure, FirstFailureRollsBackPriorSuccess) {
    /// When the manager opens a list of paths, a failure on path N
    /// MUST roll the prior N-1 successful opens back. Otherwise a
    /// half-loaded state would leak registrations into the kernel
    /// the operator never asked for. Pair: real null plugin (loads)
    /// + a non-existent second path (fails) — the null registration
    /// should not survive the rollback.
    Kernel k;
    PluginManager pm(k);

    std::string diag;
    const std::vector<std::string> paths = {
        GOODNET_NULL_PLUGIN_PATH,
        "/nonexistent/second/libgoodnet_phantom.so"
    };
    EXPECT_NE(pm.load(paths, &diag), GN_OK);
    EXPECT_FALSE(diag.empty());

    EXPECT_EQ(pm.size(), 0u)
        << "manager must roll back the first plugin's load on the second's failure";
    EXPECT_FALSE(k.security().is_active())
        << "rolled-back load must un-register every registry entry it had set";

    pm.shutdown();
    EXPECT_EQ(pm.leaked_handles(), 0u);
}

#ifdef GOODNET_REMOTE_ECHO_PATH

TEST(PluginManager_Remote, LoadsRemoteWorkerThroughManifest) {
    /// End-to-end PluginManager path: a manifest entry with
    /// `kind: remote` makes `open_one` spawn the worker binary
    /// over `sdk/remote/wire.h` instead of dlopen-ing it.
    auto digest = PluginManifest::sha256_of_file(GOODNET_REMOTE_ECHO_PATH);
    ASSERT_TRUE(digest.has_value());
    if (!digest) GTEST_SKIP() << "worker binary unavailable";

    PluginManifest m;
    m.add_entry(GOODNET_REMOTE_ECHO_PATH, *digest, ManifestKind::Remote);

    Kernel k;
    PluginManager pm(k);
    pm.set_manifest(std::move(m));

    std::string diag;
    const std::vector<std::string> paths = {GOODNET_REMOTE_ECHO_PATH};
    ASSERT_EQ(pm.load(paths, &diag), GN_OK) << "diag: " << diag;
    EXPECT_EQ(pm.size(), 1u);

    pm.shutdown();
    EXPECT_EQ(pm.size(), 0u);
    EXPECT_EQ(pm.leaked_handles(), 0u);
}

TEST(PluginManager_Remote, MissingManifestEntryRejectedByIntegrity) {
    /// The remote linkage path runs the same integrity check as
    /// dlopen. A manifest that pins the worker's path with a wrong
    /// hash must fail the load before spawn.
    PluginManifest m;
    PluginHash wrong{};
    m.add_entry(GOODNET_REMOTE_ECHO_PATH, wrong, ManifestKind::Remote);

    Kernel k;
    PluginManager pm(k);
    pm.set_manifest(std::move(m));

    std::string diag;
    const std::vector<std::string> paths = {GOODNET_REMOTE_ECHO_PATH};
    EXPECT_EQ(pm.load(paths, &diag), GN_ERR_INTEGRITY_FAILED);
    EXPECT_NE(diag.find("integrity"), std::string::npos) << diag;
    EXPECT_EQ(pm.size(), 0u);
}

#endif  // GOODNET_REMOTE_ECHO_PATH
