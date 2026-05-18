// SPDX-License-Identifier: Apache-2.0
/// @file   tests/unit/sdk/test_link_plugin_macro.cpp
/// @brief  Coverage for the `GN_LINK_PLUGIN_EX` helpers in
///         `sdk/cpp/link_plugin.hpp`.
///
/// The `GN_LINK_PLUGIN[_EX]` macros expand at file scope, emitting
/// `gn_plugin_*` extern "C" symbols. Following the
/// `test_strategy_plugin_macro.cpp` convention, the macro itself is
/// NOT invoked here — real-world coverage comes from every link
/// plugin that calls the macro (tcp, udp, ws, tls, quic, ipc,
/// raw_inject). What this file covers:
///
///   1. `default_trust_class_dispatch` forwards the supplied trust
///      class to a link class that exposes
///      `set_default_trust_class` — proving the EX variant's
///      trust-class hint reaches the impl.
///   2. The same helper is a silent no-op for link classes that
///      omit the slot — proving the existing `GN_LINK_PLUGIN`
///      desugar stays a structural identity for every link plugin
///      that has not opted in to the EX surface.

#include <gtest/gtest.h>

#include <sdk/cpp/link_plugin.hpp>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace {

struct LinkWithTrust {
    gn_trust_class_t observed = GN_TRUST_UNTRUSTED;
    int              calls    = 0;
    void set_default_trust_class(gn_trust_class_t t) noexcept {
        observed = t;
        ++calls;
    }
};

struct LinkWithoutTrust {
    int touched = 0;
};

}  // namespace

TEST(LinkPluginMacro, DefaultTrustClassDispatchForwardsWhenPresent) {
    LinkWithTrust link;
    ::gn::sdk::detail::default_trust_class_dispatch(
        link, GN_TRUST_ANONYMOUS_LOOPBACK);
    EXPECT_EQ(link.calls, 1);
    EXPECT_EQ(link.observed, GN_TRUST_ANONYMOUS_LOOPBACK);

    ::gn::sdk::detail::default_trust_class_dispatch(
        link, GN_TRUST_INTRA_NODE);
    EXPECT_EQ(link.calls, 2);
    EXPECT_EQ(link.observed, GN_TRUST_INTRA_NODE);
}

TEST(LinkPluginMacro, DefaultTrustClassDispatchNoopWhenAbsent) {
    LinkWithoutTrust link;
    ::gn::sdk::detail::default_trust_class_dispatch(
        link, GN_TRUST_ANONYMOUS_LOOPBACK);
    EXPECT_EQ(link.touched, 0);
}
