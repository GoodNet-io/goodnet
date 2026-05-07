/// @file   core/kernel/conn_event.hpp
/// @brief  Internal payload for the kernel's connection-event
///         channel. Plugins consume this through the C ABI in
///         `sdk/conn_events.h`; the in-process subscribers (kernel
///         components, kind tests) work directly with this type.
///
/// Authoritative semantics live in `docs/contracts/conn-events.en.md`.

#pragma once

#include <cstdint>

#include <sdk/cpp/types.hpp>
#include <sdk/conn_events.h>
#include <sdk/trust.h>

namespace gn::core {

struct ConnEvent {
    gn_conn_event_kind_t kind;
    gn_conn_id_t         conn          = GN_INVALID_ID;
    gn_trust_class_t     trust         = GN_TRUST_UNTRUSTED;
    PublicKey            remote_pk     {};
    std::uint64_t        pending_bytes = 0;
};

} // namespace gn::core
