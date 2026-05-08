/// @file   core/kernel/capability_blob.cpp

#include "capability_blob.hpp"

#include <algorithm>
#include <utility>

namespace gn::core {

namespace {

constexpr std::size_t kPrefixBytes = 8;  // BE64 expiry

[[nodiscard]] std::int64_t decode_be64(const std::uint8_t* in) noexcept {
    std::uint64_t u = 0;
    u |= static_cast<std::uint64_t>(in[0]) << 56;
    u |= static_cast<std::uint64_t>(in[1]) << 48;
    u |= static_cast<std::uint64_t>(in[2]) << 40;
    u |= static_cast<std::uint64_t>(in[3]) << 32;
    u |= static_cast<std::uint64_t>(in[4]) << 24;
    u |= static_cast<std::uint64_t>(in[5]) << 16;
    u |= static_cast<std::uint64_t>(in[6]) <<  8;
    u |= static_cast<std::uint64_t>(in[7]);
    return static_cast<std::int64_t>(u);
}

}  // namespace

gn_subscription_id_t CapabilityBlobBus::subscribe(
    gn_capability_blob_cb_t cb,
    void* user_data,
    void (*ud_destroy)(void*)) {
    if (cb == nullptr) return GN_INVALID_SUBSCRIPTION_ID;
    std::unique_lock lock(mu_);
    Entry e;
    e.id         = static_cast<gn_subscription_id_t>(next_id_++);
    e.cb         = cb;
    e.user_data  = user_data;
    e.ud_destroy = ud_destroy;
    entries_.push_back(e);
    return e.id;
}

bool CapabilityBlobBus::unsubscribe(gn_subscription_id_t id) {
    Entry removed{};
    bool found = false;
    {
        std::unique_lock lock(mu_);
        auto it = std::find_if(entries_.begin(), entries_.end(),
            [id](const Entry& e) { return e.id == id; });
        if (it == entries_.end()) return false;
        removed = *it;
        if (it != entries_.end() - 1) {
            *it = entries_.back();
        }
        entries_.pop_back();
        found = true;
    }
    /// Run the destructor outside the lock — caller code may
    /// (legitimately) reach back through the bus on a teardown
    /// path; we don't want to hold our mutex during their work.
    if (found && removed.ud_destroy != nullptr) {
        removed.ud_destroy(removed.user_data);
    }
    return found;
}

void CapabilityBlobBus::on_inbound(gn_conn_id_t from_conn,
                                    const std::uint8_t* payload,
                                    std::size_t size) {
    if (payload == nullptr || size < kPrefixBytes) return;

    const auto expires = decode_be64(payload);
    const auto* blob   = payload + kPrefixBytes;
    const auto blob_n  = size - kPrefixBytes;

    /// Snapshot under shared lock so subscribers added or removed
    /// during the fan-out do not invalidate the iteration. The
    /// callbacks run unlocked — they may re-enter the bus.
    std::vector<Entry> snapshot;
    {
        std::shared_lock lock(mu_);
        snapshot = entries_;
    }
    for (const auto& e : snapshot) {
        e.cb(e.user_data, from_conn, blob, blob_n, expires);
    }
}

std::size_t CapabilityBlobBus::subscriber_count() const noexcept {
    std::shared_lock lock(mu_);
    return entries_.size();
}

CapabilityBlobBus::~CapabilityBlobBus() {
    /// Run destructors for any leftover subscribers.
    std::vector<Entry> remaining;
    {
        std::unique_lock lock(mu_);
        remaining.swap(entries_);
    }
    for (const auto& e : remaining) {
        if (e.ud_destroy != nullptr) {
            e.ud_destroy(e.user_data);
        }
    }
}

} // namespace gn::core
