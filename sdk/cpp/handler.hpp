/**
 * @file   sdk/cpp/handler.hpp
 * @brief  C++ abstract interface for application-level message handlers.
 *
 * Handlers consume envelopes whose `(protocol_id, msg_id)` pair matches
 * their registration.
 */
#pragma once

#include <cstdint>
#include <span>
#include <string_view>

#include <sdk/cpp/types.hpp>
#include <sdk/handler.h>

namespace gn {

/**
 * @brief Propagation policy returned from `handle_message`.
 *
 * Mirrors @ref gn_propagation_t with C++ enum-class scoping.
 */
enum class Propagation : int {
    Continue = GN_PROP_CONTINUE, /**< pass envelope to the next handler */
    Consumed = GN_PROP_CONSUMED, /**< stop dispatch chain — handled */
    Reject   = GN_PROP_REJECT    /**< drop envelope and close the connection */
};

/**
 * @brief Userspace consumer of envelopes.
 *
 * Handlers are registered by the kernel against a `(protocol_id, msg_id)`
 * pair. Multiple handlers may share the same pair; dispatch order is
 * priority-driven (TBD in handler registration contract).
 */
class IHandler {
public:
    virtual ~IHandler() = default;

    /// Identifier of the protocol layer this handler binds to.
    [[nodiscard]] virtual std::string_view protocol_id() const noexcept = 0;

    /**
     * @brief Message identifiers this handler consumes.
     *
     * Returned span is borrowed for the lifetime of the handler.
     */
    [[nodiscard]] virtual std::span<const std::uint32_t>
    supported_msg_ids() const noexcept = 0;

    /**
     * @brief Synchronous dispatch entry.
     *
     * `envelope.payload` is borrowed and only valid until the function
     * returns. Implementations that retain payload bytes must copy.
     */
    virtual Propagation handle_message(const gn_message_t& envelope) = 0;

    /// Optional lifecycle hooks.
    virtual void on_init()     {}
    virtual void on_shutdown() {}
};

} // namespace gn
