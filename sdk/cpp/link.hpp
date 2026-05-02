/// @file   sdk/cpp/link.hpp
/// @brief  C++ abstract base for link plugins.
///
/// Mirrors `gn_link_vtable_t` from `sdk/link.h`. C++ plugin
/// authors inherit from `gn::ILink` and export the vtable through
/// the plugin entry point. The contract for the interface is in
/// `docs/contracts/link.md`.

#pragma once

#include <cstdint>
#include <span>
#include <string_view>

#include <sdk/cpp/types.hpp>
#include <sdk/link.h>
#include <sdk/types.h>

namespace gn {

/// @brief Scatter-gather byte span used by `send_batch`.
///
/// Each element in the outer span describes one contiguous byte span
/// that the link coalesces into a single OS-level write.
using ByteSpanList = std::span<const std::span<const std::uint8_t>>;

/// @brief Link plugin interface.
///
/// Links move bytes — they do not interpret payloads, do not
/// authenticate peers (security plugins do that), and do not route
/// messages (the kernel does that). The single-writer invariant from
/// `link.md` §4 applies to every implementation: at most one task
/// may be writing to a given underlying socket at a time, regardless
/// of how the language enforces it (mutex, single-task ownership,
/// actor mailbox).
///
/// Async work posted by a link implementation captures a weak
/// observer of the link's reference-counted handle and upgrades
/// before dereferencing link state. See `plugin-lifetime.md` §4.
class ILink {
public:
    virtual ~ILink() = default;

    /// Stable lowercase scheme name. Examples: `"tcp"`, `"udp"`,
    /// `"ws"`. Returned `string_view` outlives the plugin.
    [[nodiscard]] virtual std::string_view scheme() const noexcept = 0;

    /// Begin accepting connections matching the scheme.
    ///
    /// The link parses the URI itself and binds the listening
    /// socket. Subsequent inbound connections are surfaced through
    /// the host-API `notify_connect` slot.
    virtual Result<void> listen(std::string_view uri) = 0;

    /// Initiate an outbound connection.
    ///
    /// Returns immediately. Once the underlying handshake completes
    /// (TCP three-way / WebSocket upgrade / etc.) the link calls
    /// back through the host-API `notify_connect` slot.
    virtual Result<void> connect(std::string_view uri) = 0;

    /// Send a single frame on an existing connection.
    ///
    /// `bytes` is borrowed for the duration of the call. The
    /// link copies internally if it needs to retain the bytes
    /// past return.
    virtual Result<void> send(gn_conn_id_t conn,
                              std::span<const std::uint8_t> bytes) = 0;

    /// Send a scatter-gather batch on a single connection.
    ///
    /// The batch is one logical write — it must not interleave with
    /// other sends on the same connection. Implementations may use
    /// `writev`-style multiplex internally.
    virtual Result<void> send_batch(gn_conn_id_t conn,
                                    ByteSpanList batch) = 0;

    /// Close a connection. Idempotent — a second call on the same
    /// connection returns success as a no-op.
    virtual Result<void> disconnect(gn_conn_id_t conn) = 0;

    /// Per-link extension surface for stats and runtime config
    /// tweaks. Returns an empty string when no extension is exposed.
    [[nodiscard]] virtual std::string_view extension_name() const noexcept {
        return {};
    }

    /// Vtable for the extension named by `extension_name()`. Returns
    /// nullptr when no extension is exposed.
    [[nodiscard]] virtual const void* extension_vtable() const noexcept {
        return nullptr;
    }
};

} // namespace gn
