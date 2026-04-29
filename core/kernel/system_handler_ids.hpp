/// @file   core/kernel/system_handler_ids.hpp
/// @brief  Reserved msg_id values for kernel-internal dispatch.
///
/// Plugins cannot register handlers on these ids — `HandlerRegistry`
/// rejects with `GN_ERR_INVALID_ENVELOPE` per
/// `docs/contracts/handler-registration.md` §2a.

#pragma once

#include <cstdint>

namespace gn::core {

/// Attestation dispatcher — `docs/contracts/attestation.md` §3.
/// 232-byte payload; kernel intercepts after deframe, before
/// regular handler chain dispatch.
inline constexpr std::uint32_t kAttestationMsgId = 0x11;

/// Returns true when @p msg_id is reserved for a kernel-internal
/// dispatcher and must not appear in the plugin-facing handler
/// registry.
[[nodiscard]] constexpr bool is_reserved_system_msg_id(std::uint32_t msg_id) noexcept {
    return msg_id == kAttestationMsgId;
}

} // namespace gn::core
