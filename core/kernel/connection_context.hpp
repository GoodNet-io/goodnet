/// @file   core/kernel/connection_context.hpp
/// @brief  Full definition of the per-connection context.
///
/// `gn_connection_context_s` is the struct that plugins see only by
/// pointer; the layout lives here, kernel-side. Plugins read its state
/// through the C ABI accessors in `sdk/connection.h`.

#pragma once

#include <sdk/cpp/types.hpp>
#include <sdk/trust.h>
#include <sdk/types.h>

/// Defined in the global namespace because the C ABI in
/// `sdk/connection.h` forward-declares it as `struct gn_connection_context_s`.
struct gn_connection_context_s {
    gn::PublicKey      local_pk{};       ///< local node identity
    gn::PublicKey      remote_pk{};      ///< peer pk (post-Noise)
    gn_conn_id_t       conn_id{GN_INVALID_ID};
    gn_trust_class_t   trust{GN_TRUST_UNTRUSTED};

    /// Plugin-private scratch slot. Opaque to the kernel; transports
    /// stash per-connection state here for protocol/security layer
    /// partners to pick up.
    void*              plugin_state{nullptr};

    /// ABI evolution; must be zero-initialised.
    void*              _reserved[4]{};
};
