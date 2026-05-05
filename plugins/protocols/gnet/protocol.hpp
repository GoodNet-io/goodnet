/// @file   plugins/protocols/gnet/protocol.hpp
/// @brief  GNET implementation of `IProtocolLayer`.
///
/// `GnetProtocol` translates between the kernel-side `gn_message_t`
/// envelope and GNET v1 wire bytes. Per
/// `docs/contracts/protocol-layer.md` it is the canonical
/// mesh-framing for v1.x and statically links into the kernel binary.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <sdk/cpp/protocol_layer.hpp>
#include <sdk/cpp/types.hpp>

namespace gn::plugins::gnet {

/// IProtocolLayer implementation for the GNET v1 wire format.
///
/// One instance per kernel; thread-safety on the dispatch path is the
/// kernel's responsibility (per-connection serialisation through the
/// transport strand).
class GnetProtocol final : public ::gn::IProtocolLayer {
public:
    static constexpr std::string_view kProtocolId = "gnet-v1";

    GnetProtocol()                                = default;
    GnetProtocol(const GnetProtocol&)             = delete;
    GnetProtocol& operator=(const GnetProtocol&)  = delete;

    /// Returns "gnet-v1". Used by the handler registry to scope
    /// `(protocol_id, msg_id)` registrations to this layer.
    [[nodiscard]] std::string_view protocol_id() const noexcept override;

    /// Parse zero or more envelopes out of decrypted byte stream.
    ///
    /// The returned span borrows from an internal buffer that is
    /// reused on every call. The kernel must dispatch the messages
    /// before invoking deframe again on the same instance.
    [[nodiscard]] ::gn::Result<::gn::DeframeResult> deframe(
        ::gn::ConnectionContext& ctx,
        std::span<const std::uint8_t> bytes) override;

    /// Serialise a single envelope into wire bytes.
    ///
    /// Decides the wire mode (direct, broadcast, relay-transit) from
    /// envelope content and connection context per the rules in
    /// `plugins/protocols/gnet/docs/wire-format.md` §3.
    [[nodiscard]] ::gn::Result<std::vector<std::uint8_t>> frame(
        ::gn::ConnectionContext& ctx,
        const gn_message_t& msg) override;

    /// Largest payload size GNET can frame in one message. Computed
    /// against `kMaxFrameBytes` minus the worst-case header (relay
    /// transit: fixed header + sender_pk + receiver_pk).
    [[nodiscard]] std::size_t max_payload_size() const noexcept override;

private:
    /// Buffer of envelopes returned to the caller across one dispatch
    /// cycle. Reused on every deframe call to avoid per-call allocation.
    std::vector<gn_message_t> deframe_buffer_;
};

} // namespace gn::plugins::gnet
