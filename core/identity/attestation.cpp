/// @file   core/identity/attestation.cpp
/// @brief  Implementation of user-signed device attestation.

#include "attestation.hpp"

#include <cstring>

#include <core/util/endian.hpp>

namespace gn::core::identity {

namespace {

/// Build the message bytes that the attestation signature covers:
///     user_pk || device_pk || expiry_unix_ts (big-endian int64).
[[nodiscard]] std::array<std::uint8_t, 72> canonical_payload(
    const ::gn::PublicKey& user_pk,
    const ::gn::PublicKey& device_pk,
    std::int64_t           expiry_unix_ts) noexcept {
    std::array<std::uint8_t, 72> buf{};
    std::memcpy(buf.data(),       user_pk.data(),   GN_PUBLIC_KEY_BYTES);
    std::memcpy(buf.data() + 32,  device_pk.data(), GN_PUBLIC_KEY_BYTES);
    /// Big-endian for cross-platform parse. Cast-then-write covers
    /// negative values via two's complement bit pattern.
    ::gn::util::write_be<std::uint64_t>(
        std::span<std::uint8_t>(buf.data() + 64, 8),
        static_cast<std::uint64_t>(expiry_unix_ts));
    return buf;
}

} // namespace

::gn::Result<Attestation> Attestation::create(
    const KeyPair&         user,
    const ::gn::PublicKey& device_pk,
    std::int64_t           expiry_unix_ts) {

    Attestation att;
    att.user_pk        = user.public_key();
    att.device_pk      = device_pk;
    att.expiry_unix_ts = expiry_unix_ts;

    auto payload = canonical_payload(att.user_pk, att.device_pk,
                                      att.expiry_unix_ts);
    auto sig = user.sign(std::span<const std::uint8_t>(payload));
    if (!sig) return std::unexpected(sig.error());

    att.signature = *sig;
    return att;
}

bool Attestation::verify(const ::gn::PublicKey& expected_user,
                         std::int64_t           now_unix_ts) const noexcept {
    if (expected_user != user_pk) return false;
    if (expiry_unix_ts <= now_unix_ts) return false;

    auto payload = canonical_payload(user_pk, device_pk, expiry_unix_ts);
    return KeyPair::verify(user_pk,
                           std::span<const std::uint8_t>(payload),
                           std::span<const std::uint8_t,
                                     kEd25519SignatureBytes>(signature));
}

std::array<std::uint8_t, kAttestationBytes>
Attestation::to_bytes() const noexcept {
    std::array<std::uint8_t, kAttestationBytes> buf{};
    std::memcpy(buf.data(),      user_pk.data(),   32);
    std::memcpy(buf.data() + 32, device_pk.data(), 32);
    ::gn::util::write_be<std::uint64_t>(
        std::span<std::uint8_t>(buf.data() + 64, 8),
        static_cast<std::uint64_t>(expiry_unix_ts));
    std::memcpy(buf.data() + 72, signature.data(), 64);
    return buf;
}

::gn::Result<Attestation> Attestation::from_bytes(
    std::span<const std::uint8_t, kAttestationBytes> bytes) noexcept {

    Attestation att;
    std::memcpy(att.user_pk.data(),   bytes.data(),      32);
    std::memcpy(att.device_pk.data(), bytes.data() + 32, 32);
    const auto exp = ::gn::util::read_be<std::uint64_t>(
        std::span<const std::uint8_t>(bytes.data() + 64, 8));
    att.expiry_unix_ts = static_cast<std::int64_t>(exp);
    std::memcpy(att.signature.data(), bytes.data() + 72, 64);
    return att;
}

} // namespace gn::core::identity
