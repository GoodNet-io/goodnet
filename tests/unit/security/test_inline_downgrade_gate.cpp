// SPDX-License-Identifier: Apache-2.0
/// @file   tests/unit/security/test_inline_downgrade_gate.cpp
/// @brief  Env-var gate on `SecuritySession::_test_clear_inline_crypto`.
///
/// The bench-showcase track Б §B.3 uses an inline-crypto bypass to
/// emulate post-handshake Noise→Null handoff. The hook lives in
/// production code (`session.cpp`), guarded by the env var
/// `GN_SHOWCASE_ALLOW_INLINE_DOWNGRADE=1`. This test pins the gate:
/// the method MUST fail closed without the env var, succeed with it.
/// If the gate ever weakens, the production binary becomes one
/// `_test_clear_inline_crypto` call away from a silent security
/// session corruption — the test is the trip wire.
///
/// The test does NOT exercise the actual cryptographic effect of the
/// clear (that lives in `bench_showcase` once it lands). It checks
/// only the env-gate contract.

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstring>

#include <core/security/session.hpp>
#include <sdk/security.h>
#include <sdk/types.h>

namespace {

using gn::core::SecuritySession;

/// RAII wrapper around the env var so each test starts with a
/// known unsetenv state regardless of the harness env. Avoids
/// cross-test bleed.
class EnvVarScope {
public:
    explicit EnvVarScope(const char* name, const char* value) : name_(name) {
        const char* prev = std::getenv(name);
        if (prev) {
            had_prev_ = true;
            prev_value_.assign(prev);
        }
        if (value) {
            ::setenv(name_, value, /*overwrite*/1);
        } else {
            ::unsetenv(name_);
        }
    }
    ~EnvVarScope() {
        if (had_prev_) {
            ::setenv(name_, prev_value_.c_str(), /*overwrite*/1);
        } else {
            ::unsetenv(name_);
        }
    }
    EnvVarScope(const EnvVarScope&) = delete;
    EnvVarScope& operator=(const EnvVarScope&) = delete;

private:
    const char* name_;
    bool        had_prev_ = false;
    std::string prev_value_;
};

constexpr const char* kEnvVar = "GN_SHOWCASE_ALLOW_INLINE_DOWNGRADE";

TEST(InlineDowngradeGate, RefusesWithoutEnvVar) {
    EnvVarScope guard{kEnvVar, nullptr};
    SecuritySession s;
    /// Session phase doesn't matter for this branch — env-gate
    /// rejects before the phase check. Default-constructed session
    /// sits in `Closed`.
    EXPECT_EQ(s._test_clear_inline_crypto(), GN_ERR_INVALID_STATE);
}

TEST(InlineDowngradeGate, RefusesWithEmptyEnvVar) {
    EnvVarScope guard{kEnvVar, ""};
    SecuritySession s;
    EXPECT_EQ(s._test_clear_inline_crypto(), GN_ERR_INVALID_STATE);
}

TEST(InlineDowngradeGate, RefusesWithWrongValue) {
    EnvVarScope guard{kEnvVar, "yes"};
    SecuritySession s;
    /// Only the literal string "1" passes the gate. Truthy-ish
    /// values like "yes"/"true" are refused — operators have to
    /// know they're opting in to bench-only behaviour.
    EXPECT_EQ(s._test_clear_inline_crypto(), GN_ERR_INVALID_STATE);
}

TEST(InlineDowngradeGate, RefusesOutsideTransportPhase) {
    EnvVarScope guard{kEnvVar, "1"};
    SecuritySession s;
    /// Env var present but session in `Closed` phase. Second
    /// guard prevents bench from clearing inline crypto on a
    /// session that never finished handshake — encrypt would
    /// then panic-cascade through the kernel.
    EXPECT_EQ(s._test_clear_inline_crypto(), GN_ERR_INVALID_STATE);
}

}  // namespace
