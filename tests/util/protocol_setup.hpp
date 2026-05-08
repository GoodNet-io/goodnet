/// @file   tests/util/protocol_setup.hpp
/// @brief  Test helper that registers a protocol layer with the kernel.
///
/// Pre-relax the same line in test fixtures was
/// `kernel.set_protocol_layer(proto)`. After the relax of
/// `IProtocolLayer` to a registry (see commit history on
/// `feat/protocol-layer-registry`) registration goes through
/// `Kernel::protocol_layers().register_layer(...)` and yields an id.
/// Most fixtures don't care about the id; this helper hides the
/// out-id plumbing and the `(void)` discard of the registration
/// result.

#pragma once

#include <memory>
#include <utility>

#include <core/kernel/kernel.hpp>
#include <core/registry/protocol_layer.hpp>
#include <sdk/cpp/protocol_layer.hpp>

namespace gn::test::util {

/// Register @p layer on @p kernel, returning the issued id. Test
/// fixtures that want the id may capture it; the
/// `register_default_protocol(kernel, layer)` overload below
/// discards it for the common case.
inline ::gn::core::protocol_layer_id_t register_protocol(
    ::gn::core::Kernel& kernel,
    std::shared_ptr<::gn::IProtocolLayer> layer) noexcept {
    ::gn::core::protocol_layer_id_t id = ::gn::core::kInvalidProtocolLayerId;
    (void)kernel.protocol_layers().register_layer(std::move(layer), &id);
    return id;
}

/// Register @p layer on @p kernel without surfacing the issued id.
/// Pre-relax replacement for `kernel.set_protocol_layer(layer)`
/// where the fixture only needs the layer to dispatch.
inline void register_default_protocol(
    ::gn::core::Kernel& kernel,
    std::shared_ptr<::gn::IProtocolLayer> layer) noexcept {
    (void)register_protocol(kernel, std::move(layer));
}

} // namespace gn::test::util
