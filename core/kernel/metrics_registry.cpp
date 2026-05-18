/// @file   core/kernel/metrics_registry.cpp
/// @brief  Implementation of the kernel's named-counter store.

#include "metrics_registry.hpp"

#include <array>
#include <cstddef>
#include <utility>

#include "safe_invoke.hpp"

namespace gn::core {

namespace {

/// Stable name per `RouteOutcome` value. Kept inside the registry
/// implementation so call sites never have to remember the canonical
/// string. New `RouteOutcome` values land here in one place — the
/// table is indexed by the enum's underlying value, so a new outcome
/// is a single new array entry (plus the `static_assert` size bump).
constexpr std::array<const char*, 8> kRouteOutcomeMetricNames = {
    "route.outcome.dispatched_local",
    "route.outcome.dispatched_broadcast",
    "route.outcome.deferred_relay",
    "route.outcome.dropped_zero_sender",
    "route.outcome.dropped_invalid_msg_id",
    "route.outcome.dropped_unknown_receiver",
    "route.outcome.dropped_no_handler",
    "route.outcome.rejected",
};

static_assert(static_cast<std::size_t>(RouteOutcome::Rejected) + 1
                  == kRouteOutcomeMetricNames.size(),
              "kRouteOutcomeMetricNames must stay aligned with the "
              "RouteOutcome enum.");

[[nodiscard]] const char* route_outcome_metric_name(RouteOutcome o) noexcept {
    const auto idx = static_cast<std::size_t>(o);
    return idx < kRouteOutcomeMetricNames.size()
               ? kRouteOutcomeMetricNames[idx]
               : "route.outcome.unknown";
}

/// Stable name per `gn_drop_reason_t`. Same rationale as above —
/// new enum values land here so the consumer-side metric scrape
/// stays stable across releases. Indexed by the C enum's underlying
/// value (`GN_DROP_NONE == 0` ... `GN_DROP_ATTESTATION_IDENTITY_CHANGE`).
constexpr std::array<const char*, 18> kDropReasonMetricNames = {
    "drop.none",
    "drop.frame_too_large",
    "drop.payload_too_large",
    "drop.queue_hard_cap",
    "drop.reserved_bit_set",
    "drop.deframe_corrupt",
    "drop.zero_sender",
    "drop.unknown_receiver",
    "drop.relay_ttl_exceeded",
    "drop.relay_loop_dedup",
    "drop.rate_limited",
    "drop.trust_class_mismatch",
    "drop.attestation_bad_size",
    "drop.attestation_replay",
    "drop.attestation_parse_failed",
    "drop.attestation_bad_signature",
    "drop.attestation_expired_or_invalid",
    "drop.attestation_identity_change",
};

static_assert(static_cast<std::size_t>(GN_DROP_ATTESTATION_IDENTITY_CHANGE) + 1
                  == kDropReasonMetricNames.size(),
              "kDropReasonMetricNames must stay aligned with the "
              "gn_drop_reason_t enum.");

[[nodiscard]] const char* drop_reason_metric_name(gn_drop_reason_t r) noexcept {
    const auto idx = static_cast<std::size_t>(r);
    return idx < kDropReasonMetricNames.size()
               ? kDropReasonMetricNames[idx]
               : "drop.unknown";
}

}  // namespace

MetricsRegistry::MetricsRegistry() {
    /// Pre-create the cardinality-rejected slot so the slow-path
    /// reject branch can increment without taking another writer
    /// lock to allocate the slot itself. The slot stays present
    /// regardless of cap state so an exporter scrape always finds
    /// it.
    auto slot = std::make_unique<std::atomic<std::uint64_t>>(0);
    cardinality_rejected_ = slot.get();
    counters_.emplace(std::string{"metrics.cardinality_rejected"},
                       std::move(slot));
}

void MetricsRegistry::set_max_counter_names(std::uint32_t cap) noexcept {
    max_counter_names_.store(cap, std::memory_order_release);
}

MetricsRegistry::Map::const_iterator
MetricsRegistry::find(std::string_view name) const {
    /// `unordered_map`'s heterogeneous lookup with
    /// `is_transparent`-marked hash and equal_to widens the
    /// comparison to `string_view`. The fast path therefore avoids
    /// constructing a temporary `std::string` for the lookup —
    /// important on the dispatch hot path where every router
    /// result emits a metric.
    return counters_.find(name);
}

void MetricsRegistry::increment(std::string_view name) {
    /// Fast path: the counter already exists. A shared lock is
    /// enough — every concurrent reader and every other writer of
    /// an *existing* counter passes through here without serialising.
    {
        std::shared_lock lk(mu_);
        if (auto it = find(name); it != counters_.end()) {
            it->second->fetch_add(1, std::memory_order_relaxed);
            return;
        }
    }

    /// Slow path: first hit on this counter name. Take the writer
    /// lock and re-check — a concurrent caller may have inserted
    /// between our shared-lock release and the unique-lock acquire.
    std::unique_lock lk(mu_);
    if (auto it = find(name); it != counters_.end()) {
        it->second->fetch_add(1, std::memory_order_relaxed);
        return;
    }

    /// Cardinality cap (`metrics.en.md` §3.1). Zero disables the
    /// check; a non-zero cap rejects the *new* counter and bumps
    /// `metrics.cardinality_rejected` so the operator can spot the
    /// cliff without losing established names. LRU eviction would
    /// silently lose data on every Prometheus scrape.
    const std::uint32_t cap =
        max_counter_names_.load(std::memory_order_acquire);
    if (cap != 0 && counters_.size() >= cap) {
        cardinality_rejected_->fetch_add(1, std::memory_order_relaxed);
        return;
    }

    auto slot = std::make_unique<std::atomic<std::uint64_t>>(1);
    counters_.emplace(std::string{name}, std::move(slot));
}

void MetricsRegistry::increment_route_outcome(RouteOutcome outcome) {
    increment(route_outcome_metric_name(outcome));
}

void MetricsRegistry::increment_drop_reason(gn_drop_reason_t reason) {
    increment(drop_reason_metric_name(reason));
}

std::uint64_t MetricsRegistry::value(std::string_view name) const {
    std::shared_lock lk(mu_);
    if (auto it = find(name); it != counters_.end()) {
        return it->second->load(std::memory_order_relaxed);
    }
    return 0;
}

void MetricsRegistry::for_each(
    const std::function<void(std::string_view, std::uint64_t)>& visitor) const {
    std::shared_lock lk(mu_);
    for (const auto& [name, slot] : counters_) {
        visitor(name, slot->load(std::memory_order_relaxed));
    }
}

std::size_t MetricsRegistry::iterate(gn_counter_visitor_t visitor,
                                       void* user_data) const {
    if (!visitor) return 0;
    std::shared_lock lk(mu_);
    std::size_t visited = 0;
    for (const auto& [name, slot] : counters_) {
        ++visited;
        /// A throwing visitor would unwind through `mu_`'s held
        /// shared lock, an `extern "C"` boundary in the middle of
        /// the kernel's read-side critical section. Wrap the call
        /// and break the walk on throw — same effect as a
        /// non-zero verdict.
        const auto verdict_opt = safe_call_value<std::int32_t>(
            "metrics.iterate.visitor",
            visitor, user_data, name.c_str(),
            slot->load(std::memory_order_relaxed));
        if (verdict_opt.value_or(1) != 0) break;
    }
    return visited;
}

}  // namespace gn::core
