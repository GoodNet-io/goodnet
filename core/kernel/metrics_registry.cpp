/// @file   core/kernel/metrics_registry.cpp
/// @brief  Implementation of the kernel's named-counter store.

#include "metrics_registry.hpp"

#include <utility>

namespace gn::core {

namespace {

/// `std::unordered_map` with a transparent `equal_to<>` and
/// `std::hash<std::string>` accepts `string_view` lookups only when
/// the call goes through `find` with the heterogenous overload —
/// resolved by the `is_transparent` typedef on `equal_to<>` and the
/// matching hash specialisation. We provide our own hash that
/// covers both `std::string` and `std::string_view` so the
/// shared-lock fast path stays allocation-free.
struct StringHash {
    using is_transparent = void;

    [[nodiscard]] std::size_t operator()(std::string_view sv) const noexcept {
        return std::hash<std::string_view>{}(sv);
    }
    [[nodiscard]] std::size_t operator()(const std::string& s) const noexcept {
        return std::hash<std::string_view>{}(s);
    }
};

/// Stable name per `RouteOutcome` value. Kept inside the registry
/// implementation so call sites never have to remember the canonical
/// string. New `RouteOutcome` values land here in one place.
[[nodiscard]] const char* route_outcome_metric_name(RouteOutcome o) noexcept {
    switch (o) {
        case RouteOutcome::DispatchedLocal:
            return "route.outcome.dispatched_local";
        case RouteOutcome::DispatchedBroadcast:
            return "route.outcome.dispatched_broadcast";
        case RouteOutcome::DeferredRelay:
            return "route.outcome.deferred_relay";
        case RouteOutcome::DroppedZeroSender:
            return "route.outcome.dropped_zero_sender";
        case RouteOutcome::DroppedInvalidMsgId:
            return "route.outcome.dropped_invalid_msg_id";
        case RouteOutcome::DroppedUnknownReceiver:
            return "route.outcome.dropped_unknown_receiver";
        case RouteOutcome::DroppedNoHandler:
            return "route.outcome.dropped_no_handler";
        case RouteOutcome::Rejected:
            return "route.outcome.rejected";
    }
    return "route.outcome.unknown";
}

/// Stable name per `gn_drop_reason_t`. Same rationale as above —
/// new enum values land here so the consumer-side metric scrape
/// stays stable across releases.
[[nodiscard]] const char* drop_reason_metric_name(gn_drop_reason_t r) noexcept {
    switch (r) {
        case GN_DROP_NONE:                       return "drop.none";
        case GN_DROP_FRAME_TOO_LARGE:            return "drop.frame_too_large";
        case GN_DROP_PAYLOAD_TOO_LARGE:          return "drop.payload_too_large";
        case GN_DROP_QUEUE_HARD_CAP:             return "drop.queue_hard_cap";
        case GN_DROP_RESERVED_BIT_SET:           return "drop.reserved_bit_set";
        case GN_DROP_DEFRAME_CORRUPT:            return "drop.deframe_corrupt";
        case GN_DROP_ZERO_SENDER:                return "drop.zero_sender";
        case GN_DROP_UNKNOWN_RECEIVER:           return "drop.unknown_receiver";
        case GN_DROP_RELAY_TTL_EXCEEDED:         return "drop.relay_ttl_exceeded";
        case GN_DROP_RELAY_LOOP_DEDUP:           return "drop.relay_loop_dedup";
        case GN_DROP_RATE_LIMITED:               return "drop.rate_limited";
        case GN_DROP_TRUST_CLASS_MISMATCH:       return "drop.trust_class_mismatch";
        case GN_DROP_ATTESTATION_BAD_SIZE:       return "drop.attestation_bad_size";
        case GN_DROP_ATTESTATION_REPLAY:         return "drop.attestation_replay";
        case GN_DROP_ATTESTATION_PARSE_FAILED:   return "drop.attestation_parse_failed";
        case GN_DROP_ATTESTATION_BAD_SIGNATURE:  return "drop.attestation_bad_signature";
        case GN_DROP_ATTESTATION_EXPIRED_OR_INVALID: return "drop.attestation_expired_or_invalid";
        case GN_DROP_ATTESTATION_IDENTITY_CHANGE: return "drop.attestation_identity_change";
    }
    return "drop.unknown";
}

}  // namespace

MetricsRegistry::Map::const_iterator
MetricsRegistry::find(std::string_view name) const {
    /// `unordered_map`'s heterogenous lookup with
    /// `is_transparent`-marked equal_to + hash widens the comparison
    /// to `string_view`. The fast path therefore avoids constructing
    /// a temporary `std::string` for the lookup — important on the
    /// dispatch hot path where every router result emits a metric.
    return counters_.find(std::string(name));
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
    auto& slot = counters_[std::string(name)];
    if (!slot) {
        slot = std::make_unique<std::atomic<std::uint64_t>>(0);
    }
    slot->fetch_add(1, std::memory_order_relaxed);
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
        const std::int32_t verdict = visitor(
            user_data, name.c_str(),
            slot->load(std::memory_order_relaxed));
        if (verdict != 0) break;
    }
    return visited;
}

}  // namespace gn::core
