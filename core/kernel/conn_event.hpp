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
    /// Kind-specific payload pointers. For `IDENTITY_ROTATED`:
    /// `_reserved[0]` borrows the previous `user_pk` (32 bytes),
    /// `_reserved[1]` the new `user_pk`, `_reserved[2]` a
    /// `const std::uint64_t*` to the rotation counter. Pointers
    /// borrow for the duration of the dispatch call. Other kinds
    /// leave the slot zero.
    void*                _reserved[4]  {};
};

} // namespace gn::core
