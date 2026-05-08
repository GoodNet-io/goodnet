/// @file   core/kernel/capability_blob.hpp
/// @brief  Kernel-side distribution bus for capability TLV blobs.
///
/// Plugins drive sender-side through `host_api->present_capability_blob`
/// and receiver-side through `host_api->subscribe_capability_blob`.
/// The bus mediates: it tracks subscribers (callback + user_data)
/// and fans out inbound `msg_id 0x13` payloads to all of them on
/// the publishing thread (the strand that ran
/// `notify_inbound_bytes`).
///
/// Wire format of the inbound payload:
///   [8 bytes BE] expires_unix_ts (signed)
///   [N bytes  ] blob
///
/// Kernel does not parse the blob — that's app-domain. The hard
/// cap (`gn_limits_t::max_capability_blob_bytes`, default 16 KiB)
/// gates the sender-side enqueue.

#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <shared_mutex>
#include <vector>

#include <sdk/conn_events.h>
#include <sdk/identity.h>
#include <sdk/types.h>

namespace gn::core {

class CapabilityBlobBus {
public:
    CapabilityBlobBus()                                       = default;
    CapabilityBlobBus(const CapabilityBlobBus&)               = delete;
    CapabilityBlobBus& operator=(const CapabilityBlobBus&)    = delete;

    /// Returns a non-zero subscription id on success; the caller
    /// passes the same id to `unsubscribe`. `ud_destroy` is
    /// invoked once with `user_data` when the subscription is
    /// removed (whether by `unsubscribe` or destructor).
    [[nodiscard]] gn_subscription_id_t subscribe(
        gn_capability_blob_cb_t cb,
        void* user_data,
        void (*ud_destroy)(void*));

    /// Removes the subscription and runs its `ud_destroy` (if any).
    /// Returns `true` if removed, `false` if id absent.
    bool unsubscribe(gn_subscription_id_t id);

    /// Fan out an inbound payload to every subscriber. Caller
    /// holds the bytes for the duration of the call; subscribers
    /// must not retain. Parses the 8-byte BE expiry prefix; a
    /// payload shorter than 8 bytes is silently dropped.
    void on_inbound(gn_conn_id_t from_conn,
                     const std::uint8_t* payload,
                     std::size_t size);

    [[nodiscard]] std::size_t subscriber_count() const noexcept;

    ~CapabilityBlobBus();

private:
    struct Entry {
        gn_subscription_id_t      id;
        gn_capability_blob_cb_t   cb;
        void*                     user_data;
        void                    (*ud_destroy)(void*);
    };

    mutable std::shared_mutex   mu_;
    std::vector<Entry>          entries_;
    std::uint64_t               next_id_{1};
};

} // namespace gn::core
