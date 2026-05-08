/// @file   tests/abi/test_cross_version.cpp
/// @brief  Cross-version compatibility pin per `abi-evolution.md` §7.
///
/// The kernel admits a plugin when:
///   - `plugin_major == kernel_major` (exact match)
///   - `kernel_minor >= plugin_minor` (kernel forward-compatible)
///
/// Anything else returns `GN_ERR_VERSION_MISMATCH` from the load
/// path. This file pins the rule at the helper level
/// (`gn_version_compatible` in `sdk/abi.h`) so a future patch that
/// silently changes the predicate fires a test failure rather than
/// rejecting plugins in the field.

#include <gtest/gtest.h>

#include <sdk/abi.h>
#include <sdk/types.h>

namespace {

// ── Same major, same minor — admit ───────────────────────────────────────

TEST(AbiCrossVersion, ExactMatchAccepted) {
    EXPECT_NE(gn_version_compatible(1, 0, 1, 0), 0);
    EXPECT_NE(gn_version_compatible(1, 7, 1, 7), 0);
}

// ── Plugin older minor than kernel — admit ───────────────────────────────

TEST(AbiCrossVersion, OlderPluginAcceptedAgainstNewerKernel) {
    /// Plugin built against MINOR=0 must load against any v1.x
    /// kernel — the size-prefix vtables and `_reserved` slots are
    /// the mechanism that lets v1.0 plugins keep working when the
    /// kernel grows v1.5 slots.
    EXPECT_NE(gn_version_compatible(1, 0, 1, 5), 0);
    EXPECT_NE(gn_version_compatible(1, 1, 1, 9), 0);
}

// ── Plugin newer minor than kernel — reject ──────────────────────────────

TEST(AbiCrossVersion, NewerPluginRejectedAgainstOlderKernel) {
    /// A plugin built against the v1.5 SDK that calls v1.5-only
    /// host_api slots must not load on a v1.0 kernel — the slots
    /// would be NULL. Rejection at load is preferable to
    /// segfault at first invocation.
    EXPECT_EQ(gn_version_compatible(1, 5, 1, 0), 0);
    EXPECT_EQ(gn_version_compatible(1, 9, 1, 1), 0);
}

// ── Major mismatch — reject either direction ─────────────────────────────

TEST(AbiCrossVersion, MajorMismatchRejected) {
    EXPECT_EQ(gn_version_compatible(2, 0, 1, 0), 0);
    EXPECT_EQ(gn_version_compatible(1, 0, 2, 0), 0);
    EXPECT_EQ(gn_version_compatible(0, 0, 1, 0), 0);
}

// ── Patch ignored across the predicate ───────────────────────────────────

TEST(AbiCrossVersion, PatchVersionIgnored) {
    /// The compatibility helper takes (major, minor) only — patch
    /// is always observable but never reason to refuse a load.
    /// `gn_version_pack` reflects patch but the compatibility
    /// rule does not consult it.
    const std::uint32_t v1_0_0 = gn_version_pack(1, 0, 0);
    const std::uint32_t v1_0_9 = gn_version_pack(1, 0, 9);
    EXPECT_LT(v1_0_0, v1_0_9);  /// pack puts patch in low bits
    EXPECT_NE(gn_version_compatible(1, 0, 1, 0), 0);  /// patch ignored
}

// ── Current SDK version self-consistency ─────────────────────────────────

TEST(AbiCrossVersion, CurrentSdkSelfCompatible) {
    /// The kernel must always admit a plugin built from the same
    /// SDK tree it shipped with — otherwise `nix run .#test`
    /// could not load any in-tree plugin.
    EXPECT_NE(gn_version_compatible(GN_SDK_VERSION_MAJOR,
                                     GN_SDK_VERSION_MINOR,
                                     GN_SDK_VERSION_MAJOR,
                                     GN_SDK_VERSION_MINOR),
              0);
}

}  // namespace
