/// @file   core/kernel/link_capability.hpp
/// @brief  Host-side link capability probe — caches whether the
///         current host can bind UDP / TCP on IPv4 and IPv6.
///
/// Link plugins (UDP, DTLS, QUIC, ICE) and strategy plugins consult
/// the cached `LinkCapability` to skip candidate emission and bind
/// attempts that would fail anyway on the current network
/// environment (corporate firewall, mobile carrier with UDP blocked,
/// container without IPv6).
///
/// The first call probes once and caches the result for the rest of
/// the process lifetime. `refresh_host_link_capability` invalidates
/// the cache and re-probes; the netlink interface-change watcher and
/// the unit-test suite drive it.

#pragma once

#include <cstdint>

namespace gn {

/// Result of the host-side link capability probe. POD; C-ABI safe so
/// the `gn.link.capability` extension surface can hand it back to
/// plugins without translation.
struct LinkCapability {
    bool can_bind_udp_v4 = false;
    bool can_bind_udp_v6 = false;
    bool can_bind_tcp_v4 = false;
    bool can_bind_tcp_v6 = false;
};

/// Probe-on-first-call accessor. Returns a reference to the cached
/// snapshot. Thread-safe: the probe runs once under a guard; later
/// callers see the cached value without locking. Logs the result at
/// INFO level on the first call.
[[nodiscard]] const LinkCapability& host_link_capability();

/// Force-refresh the cache. Re-runs the probe on the next call to
/// `host_link_capability` and re-emits the INFO log line. Used by
/// the netlink interface-change watcher and by unit tests that
/// install a synthetic probe seam.
void refresh_host_link_capability() noexcept;

/// Test-only probe seam. When set, the next probe round uses the
/// supplied function instead of the real socket-bind probe. Pass
/// `nullptr` to clear. The callable is invoked once per probe round
/// and must populate the four boolean fields; it runs under the same
/// internal guard the real probe does, so the caller does not need
/// its own synchronisation. Surface exists only so tests can drive
/// the cache without binding real sockets.
using LinkCapabilityProbeFn = void(*)(LinkCapability& out) noexcept;
void set_link_capability_probe_for_testing(LinkCapabilityProbeFn fn) noexcept;

}  // namespace gn
