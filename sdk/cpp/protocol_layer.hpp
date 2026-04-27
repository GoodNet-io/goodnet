/**
 * @file   sdk/cpp/protocol_layer.hpp
 * @brief  C++ abstract interface for the mesh-framing protocol layer.
 *
 * The kernel statically links exactly one implementation. Plugins written
 * in C++ inherit from @ref gn::IProtocolLayer and export their vtable
 * through the plugin entry point.
 *
 * Contract: `docs/contracts/protocol-layer.md`.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <sdk/connection.h>
#include <sdk/cpp/types.hpp>

namespace gn {

/**
 * @brief Per-connection state passed to deframe/frame.
 *
 * Aliased to the C ABI struct declared in `sdk/connection.h`. Plugins
 * receive a reference and read state through the accessors declared
 * in the same C header (`gn_ctx_local_pk`, `gn_ctx_remote_pk`, …).
 * The full struct definition lives in `core/kernel/connection_context.hpp`.
 */
using ConnectionContext = ::gn_connection_context_t;

/**
 * @brief Result of a single deframe call.
 *
 * Messages are borrowed from the input byte buffer and only valid until
 * the kernel finishes the dispatch cycle.
 */
struct DeframeResult {
    std::span<const gn_message_t> messages;
    std::size_t                   bytes_consumed{0};
};

/**
 * @brief Mesh-framing protocol interface.
 *
 * The kernel binary statically links exactly one implementation. The
 * canonical implementation for v1.x is `gnet-v1` in
 * `plugins/protocols/gnet/`.
 */
class IProtocolLayer {
public:
    virtual ~IProtocolLayer() = default;

    /**
     * @brief Stable identifier for handler registration. Lowercase
     *        hyphenated; e.g. `"gnet-v1"`.
     */
    [[nodiscard]] virtual std::string_view protocol_id() const noexcept = 0;

    /**
     * @brief Parse envelopes out of a decrypted byte stream.
     *
     * @param ctx   per-connection state
     * @param bytes decrypted input (may contain a partial trailing frame)
     *
     * @return @ref DeframeResult on success. Message payload pointers
     *         borrow from @p bytes for the duration of one dispatch cycle.
     */
    virtual Result<DeframeResult> deframe(
        ConnectionContext& ctx,
        std::span<const std::uint8_t> bytes) = 0;

    /**
     * @brief Serialise an envelope into wire bytes.
     *
     * @return owned byte buffer ready to be handed to the security layer.
     */
    virtual Result<std::vector<std::uint8_t>> frame(
        ConnectionContext& ctx,
        const gn_message_t& msg) = 0;

    /**
     * @brief Maximum payload that this implementation can frame in one
     *        message. Used by the kernel for fragmentation decisions.
     *
     * Must be constant over the lifetime of the instance.
     */
    [[nodiscard]] virtual std::size_t max_payload_size() const noexcept = 0;
};

} // namespace gn
