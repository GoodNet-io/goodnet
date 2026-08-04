/// @file   core/kernel/conn_event.hpp
/// @brief  Internal payload for the kernel's connection-event
///         channel. Plugins consume this through the C ABI in
///         `sdk/conn_events.h`; the in-process subscribers (kernel
///         components, kind tests) work directly with this type.
///
/// Authoritative semantics live in `docs/contracts/conn-events.en.md`.

#pragma once

#include <cstdint>

#include <sdk/conn_events.h>
#include <sdk/cpp/types.hpp>
#include <sdk/topology.h>
#include <sdk/trust.h>

namespace gn::core {

struct ConnEvent {
    gn_conn_event_kind_t kind;
    gn_conn_id_t         conn          = GN_INVALID_ID;
    gn_trust_class_t     trust         = GN_TRUST_UNTRUSTED;
    PublicKey            remote_pk     {};
    std::uint64_t        pending_bytes = 0;
    /// IDENTITY_ROTATED payload — borrowed for callback duration; null otherwise.
    const std::uint8_t*  user_pk_prev      = nullptr;
    const std::uint8_t*  user_pk_next      = nullptr;
    const std::uint64_t* rotation_seq      = nullptr;
    /// TOPOLOGY_MISMATCH payload — 32-byte peer fingerprint; borrowed; null otherwise.
    const std::uint8_t*  peer_fingerprint  = nullptr;
    /// CONTOUR_BROKEN / CONTOUR_LIVE payload — borrowed for callback duration; null/0 otherwise.
    const char*          contour_provider_id  = nullptr;
    std::uint32_t        contour_trust_mask   = 0;
    gn_contour_state_t   contour_state        = GN_CONTOUR_LIVE;
    std::uint32_t        _pad_contour         = 0;
    void*                _reserved[4]      {};
};

} // namespace gn::core
