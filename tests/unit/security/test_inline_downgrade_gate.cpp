// SPDX-License-Identifier: Apache-2.0
/// @file   tests/unit/security/test_inline_downgrade_gate.cpp
/// @brief  Compile-time gate on `SecuritySession::_test_clear_inline_crypto`.
///
/// The bench-showcase §B.3 uses an inline-crypto bypass to
/// emulate post-handshake Noise→Null handoff. The hook lives in the
/// kernel under a compile-time gate (`GOODNET_BENCH_SHOWCASE`).
/// Default builds drop the symbol entirely — production binaries
/// cannot link a caller and so cannot reach the inline-crypto wipe.
///
/// This test pins the phase-guard side of the contract under the
/// bench build: the method MUST refuse to mutate session state on
/// a session that never finished the handshake. The compile-time
/// gate itself is checked by the build system — without the macro
/// the test file produces an empty translation unit, and the
/// kernel header refuses to declare the method, so any stale
/// caller fails the build instead of silently linking.
///
/// The test does NOT exercise the actual cryptographic effect of
/// the clear (that lives in `bench_showcase`); it checks only the
/// kernel-side phase guard.

#include <gtest/gtest.h>

#ifdef GOODNET_BENCH_SHOWCASE

#include <core/security/session.hpp>
#include <sdk/security.h>
#include <sdk/types.h>

namespace {

using gn::core::SecuritySession;

TEST(InlineDowngradeGate, RefusesOutsideTransportPhase) {
    SecuritySession s;
    /// Default-constructed session sits in `Closed` phase. The
    /// phase guard prevents bench code from clearing inline crypto
    /// on a session that never finished handshake — a subsequent
    /// encrypt cycle would then race the wipe and panic-cascade
    /// through the kernel.
    EXPECT_EQ(s._test_clear_inline_crypto(), GN_ERR_INVALID_STATE);
}

}  // namespace

#endif  // GOODNET_BENCH_SHOWCASE
