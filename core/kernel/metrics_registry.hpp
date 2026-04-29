/// @file   core/kernel/metrics_registry.hpp
/// @brief  Named-counter store the kernel maintains for built-in
///         observability and that plugins can extend through the
///         `host_api->emit_counter` slot.
///
/// Per `metrics.md` the kernel's counter surface is intentionally
/// minimal: monotonic 64-bit counters keyed by a UTF-8 name. No
/// labels, no gauges, no histograms — those compose out of an
/// exporter plugin sitting on top of `iterate`. Keeping the
/// kernel's surface small leaves the kernel agnostic of any wire
/// format (Prometheus, OpenMetrics, statsd, ...) — that is policy
/// and lives in plugins.
///
/// Two write paths share the same map:
///   * `increment_route_outcome` / `increment_drop_reason` —
///     kernel-side enums emitted at known dispatch sites; the
///     name-mapping helpers stay inside the registry so the call
///     sites do not have to remember the canonical strings;
///   * `increment` — generic by-name path that backs the SDK
///     `host_api->emit_counter` slot for plugin-side counters.
///
/// Reads happen through `iterate` (visitor-form) and `value`
/// (single counter, mainly for tests). Both take a shared lock
/// only briefly and never block writes for non-trivial duration.

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include <core/kernel/router.hpp>

#include <sdk/metrics.h>
#include <sdk/types.h>

namespace gn::core {

/// Thread-safe map of named monotonic counters.
class MetricsRegistry {
public:
    MetricsRegistry()                                  = default;
    MetricsRegistry(const MetricsRegistry&)            = delete;
    MetricsRegistry& operator=(const MetricsRegistry&) = delete;

    /// Bump the counter at @p name by one. Lazily creates the entry
    /// on first hit; subsequent hits go through the shared-lock
    /// fast path that never blocks a concurrent reader.
    void increment(std::string_view name);

    /// Bump a built-in `RouteOutcome` counter. The mapping from
    /// enum → metric name lives inside this registry so the hot
    /// dispatch path stays free of string-handling boilerplate.
    void increment_route_outcome(RouteOutcome outcome);

    /// Bump a built-in `gn_drop_reason_t` counter. Mirrors
    /// `increment_route_outcome` for the drop-reason enum exported
    /// to plugins through `sdk/types.h`.
    void increment_drop_reason(gn_drop_reason_t reason);

    /// Read a single counter. Returns 0 when @p name has no entry —
    /// the kernel never auto-creates on read.
    [[nodiscard]] std::uint64_t value(std::string_view name) const;

    /// Walk every counter. The visitor receives `(name, value)`
    /// pairs under a shared lock; the lock is held for the
    /// duration of the call so the visitor must not re-enter the
    /// registry.
    void for_each(const std::function<void(std::string_view,
                                            std::uint64_t)>& visitor) const;

    /// C-ABI variant for the `host_api->iterate_counters` slot.
    /// Returns the number of counters visited; stops early when the
    /// visitor returns non-zero.
    [[nodiscard]] std::size_t iterate(gn_counter_visitor_t visitor,
                                       void* user_data) const;

private:
    using Slot = std::unique_ptr<std::atomic<std::uint64_t>>;
    using Map  = std::unordered_map<std::string, Slot, std::hash<std::string>,
                                     std::equal_to<>>;

    /// `transparent` lookup keyed on `string_view` so the
    /// shared-lock fast path stops one allocation short — the
    /// caller's view does not have to widen into a `std::string`
    /// just to perform a `find`.
    [[nodiscard]] Map::const_iterator find(std::string_view name) const;

    mutable std::shared_mutex mu_;
    Map                       counters_;
};

}  // namespace gn::core
