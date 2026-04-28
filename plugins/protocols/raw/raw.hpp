// SPDX-License-Identifier: MIT
/// @file   plugins/protocols/raw/raw.hpp
/// @brief  Opaque-payload protocol layer.
///
/// `raw` is the protocol layer for scenarios where the wire shape
/// is already settled by external means and the kernel only needs
/// to ride bytes through. Three target workloads:
///
/// - **Simulation harness** — drive the kernel without paying for
///   GNET framing overhead during deterministic tests.
/// - **PCAP replay** — feed captured frames straight into the
///   kernel for offline analysis or fuzzing of upper-layer
///   handlers without re-deriving a synthetic transport.
/// - **Foreign-protocol passthrough** — bridge plugins that have
///   already framed their outbound bytes (because the foreign
///   system did) inject them through `raw` so the kernel does not
///   add a GNET header on top.
///
/// `frame` writes the envelope's payload verbatim. `deframe`
/// produces exactly one envelope whose payload borrows from the
/// input buffer; the message's sender / receiver are filled from
/// the connection context. The protocol layer carries no header
/// of its own; what arrived is what the next handler sees.
///
/// Trust policy: `raw` is permitted only on `GN_TRUST_LOOPBACK`
/// and `GN_TRUST_INTRA_NODE` per `security-trust.md` §4. `deframe`
/// rejects on any other trust class with `GN_ERR_INVALID_ENVELOPE`
/// — there is no scenario where opaque-passthrough on a public
/// network is safe.

#pragma once

#include <sdk/connection.h>
#include <sdk/protocol.h>
#include <sdk/types.h>

namespace gn::protocol::raw {

/// Returned by `protocol_id`. Stable across v1.x.
inline constexpr const char kProtocolId[] = "raw-v1";

/// Build the `gn_protocol_layer_vtable_t` for the static-link
/// helper. Plugin entry would invoke this once at registration;
/// in v1 the `raw` layer is statically linkable into the kernel
/// binary as a build-time alternative to `gnet-v1`.
[[nodiscard]] gn_protocol_layer_vtable_t make_vtable() noexcept;

}  // namespace gn::protocol::raw
