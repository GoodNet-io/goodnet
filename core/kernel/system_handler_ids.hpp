/// @file   core/kernel/system_handler_ids.hpp
/// @brief  Reserved msg_id values for identity-bearing transport dispatch.
///
/// Three classes — see `docs/contracts/handler-registration.en.md` §2a:
///
/// 1. **Registration-blocked** (`kAttestationMsgId`). Plugins cannot
///    register a handler. The kernel holds a priority=255 handler
///    registered at `gn_core_start()`. `HandlerRegistry` rejects
///    plugin attempts with `GN_ERR_INVALID_ENVELOPE`.
///
/// 2. **Kernel-first, plugin-observable** (`0x12`, `0x13`). Plugins
///    may register at priority 0–253. The kernel's priority=255
///    handler runs first; priority=255 within the identity range is
///    kernel-reserved (`is_identity_range_msg_id()` + priority=255
///    gate in `HandlerRegistry`).
///
/// 3. **Identity-range** (`0x10..0x1F`). All ids in this range block
///    the inject-boundary path so a bridge plugin cannot spoof
///    identity events onto foreign connections.

#pragma once

#include <cstdint>

namespace gn::core {

/// Identity-range start (inclusive). Anything in [start, end] is
/// reserved for kernel-internal or identity-bearing transport.
inline constexpr std::uint32_t kIdentityRangeStart    = 0x10;
inline constexpr std::uint32_t kIdentityRangeEnd      = 0x1F;

/// Attestation dispatcher — `docs/contracts/attestation.en.md` §3.
/// 232-byte payload; kernel intercepts after deframe, before
/// regular handler chain dispatch. Hard-reserved.
inline constexpr std::uint32_t kAttestationMsgId      = 0x11;

/// Identity-rotation announcement — `docs/contracts/identity.en.md`
/// §7. 150-byte signed proof. The receiver-side kernel handler
/// lives in `core/kernel/host_api/notifications.cpp::notify_inbound_bytes`
/// (rotation branch).
inline constexpr std::uint32_t kIdentityRotationMsgId = 0x12;

/// Capability-blob distribution — `docs/contracts/capability-tlv.en.md`.
/// Variable-length payload carried as the framing for
/// `host_api->present_capability_blob` / `subscribe_capability_blob`.
inline constexpr std::uint32_t kCapabilityBlobMsgId   = 0x13;

/// User-level 2FA challenge / response wire pair — see
/// `docs/contracts/system-handlers.en.md` §3 (table row `0x14` /
/// `0x15`) which points to `identity.en.md` §6 for the protocol
/// details. Apps drive the challenge-response via standard send /
/// handler registration on these ids. Plugin-reserved
/// (registerable, not injectable).
inline constexpr std::uint32_t kIdentityChallengeMsgId = 0x14;
inline constexpr std::uint32_t kIdentityResponseMsgId  = 0x15;

/// Priority used by all kernel system handlers. Plugin registrations
/// at this priority within the identity range are rejected; outside
/// the identity range the value is unrestricted.
/// See `handler-registration.en.md` §4.
inline constexpr std::uint8_t kKernelHandlerPriority = 255u;

/// Returns true when @p msg_id is registration-blocked for plugins
/// (currently only `0x11` attestation). The kernel holds a
/// priority=255 handler for this id; plugins get
/// `GN_ERR_INVALID_ENVELOPE` on any registration attempt.
[[nodiscard]] constexpr bool is_reserved_system_msg_id(std::uint32_t msg_id) noexcept {
    return msg_id == kAttestationMsgId;
}

/// Returns true when @p msg_id falls in the identity range. The
/// kernel treats these ids as identity-bearing for the purpose of
/// blocking inject-boundary calls and enforcing the priority=255
/// kernel-reservation gate.
[[nodiscard]] constexpr bool is_identity_range_msg_id(std::uint32_t msg_id) noexcept {
    return msg_id >= kIdentityRangeStart && msg_id <= kIdentityRangeEnd;
}

} // namespace gn::core
