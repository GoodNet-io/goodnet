/// @file   core/kernel/system_handler_ids.hpp
/// @brief  Reserved msg_id values for kernel-internal and identity
///         transport dispatch.
///
/// Two classes of reservations:
///
/// 1. **Hard-reserved** (`kAttestationMsgId`). The kernel intercepts
///    these ids in `notify_inbound_bytes` before the regular handler
///    chain runs; plugins cannot register a handler on them and
///    cannot inject them through the inject-boundary path.
///    `HandlerRegistry` rejects with `GN_ERR_INVALID_ENVELOPE` per
///    `docs/contracts/handler-registration.en.md` §2a.
///
/// 2. **Identity-range** (`0x10..0x1F`). Carved out for kernel
///    transport of identity-bearing payloads (rotation announces,
///    capability blobs, user-level challenge / response). `0x11`
///    is the hard-reserved attestation slot inside the range; the
///    rest carry plugin-driven payloads but stay off the
///    inject-boundary path so a misbehaving plugin cannot spoof an
///    identity event onto another plugin's connection.

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
/// §7. 150-byte signed proof. The follow-up rotation patch wires
/// the receiver-side kernel handler.
inline constexpr std::uint32_t kIdentityRotationMsgId = 0x12;

/// Capability-blob distribution — `docs/contracts/capability-tlv.en.md`.
/// Variable-length payload carried as the framing for
/// `host_api->present_capability_blob` / `subscribe_capability_blob`.
inline constexpr std::uint32_t kCapabilityBlobMsgId   = 0x13;

/// User-level 2FA challenge / response wire pair — see
/// `docs/recipes/user-2fa-via-plugins.md`. Apps drive the
/// challenge-response via standard send / handler registration on
/// these ids. Plugin-reserved (registerable, not injectable).
inline constexpr std::uint32_t kIdentityChallengeMsgId = 0x14;
inline constexpr std::uint32_t kIdentityResponseMsgId  = 0x15;

/// Returns true when @p msg_id is **hard-reserved** — kernel
/// intercepts it directly and plugins cannot register a handler.
/// Currently `0x11` (attestation). Other ids in the identity
/// range are plugin-registerable; see `is_identity_range_msg_id`.
[[nodiscard]] constexpr bool is_reserved_system_msg_id(std::uint32_t msg_id) noexcept {
    return msg_id == kAttestationMsgId;
}

/// Returns true when @p msg_id falls in the identity range. The
/// kernel treats these ids as identity-bearing for the purpose of
/// blocking inject-boundary calls — a plugin must not synthesise
/// an identity event on a connection it does not own.
[[nodiscard]] constexpr bool is_identity_range_msg_id(std::uint32_t msg_id) noexcept {
    return msg_id >= kIdentityRangeStart && msg_id <= kIdentityRangeEnd;
}

} // namespace gn::core
