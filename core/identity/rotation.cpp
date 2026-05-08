/// @file   core/identity/rotation.cpp

#include "rotation.hpp"

#include <cstring>

#include <sodium.h>

namespace gn::core::identity {

namespace {

void encode_be64(std::int64_t value, std::uint8_t* out) noexcept {
    const auto u = static_cast<std::uint64_t>(value);
    out[0] = static_cast<std::uint8_t>((u >> 56) & 0xFFu);
    out[1] = static_cast<std::uint8_t>((u >> 48) & 0xFFu);
    out[2] = static_cast<std::uint8_t>((u >> 40) & 0xFFu);
    out[3] = static_cast<std::uint8_t>((u >> 32) & 0xFFu);
    out[4] = static_cast<std::uint8_t>((u >> 24) & 0xFFu);
    out[5] = static_cast<std::uint8_t>((u >> 16) & 0xFFu);
    out[6] = static_cast<std::uint8_t>((u >>  8) & 0xFFu);
    out[7] = static_cast<std::uint8_t>( u        & 0xFFu);
}

[[nodiscard]] std::uint64_t decode_be64_u(const std::uint8_t* in) noexcept {
    std::uint64_t u = 0;
    u |= static_cast<std::uint64_t>(in[0]) << 56;
    u |= static_cast<std::uint64_t>(in[1]) << 48;
    u |= static_cast<std::uint64_t>(in[2]) << 40;
    u |= static_cast<std::uint64_t>(in[3]) << 32;
    u |= static_cast<std::uint64_t>(in[4]) << 24;
    u |= static_cast<std::uint64_t>(in[5]) << 16;
    u |= static_cast<std::uint64_t>(in[6]) <<  8;
    u |= static_cast<std::uint64_t>(in[7]);
    return u;
}

[[nodiscard]] std::int64_t decode_be64_s(const std::uint8_t* in) noexcept {
    return static_cast<std::int64_t>(decode_be64_u(in));
}

void compose_signed_prefix(
    std::uint8_t                     buf[kRotationProofSignedBytes],
    const ::gn::PublicKey&           new_user_pk,
    const ::gn::PublicKey&           prev_user_pk,
    std::uint64_t                    counter,
    std::int64_t                     valid_from_unix_ts) {
    std::size_t off = 0;
    std::memcpy(buf + off, kRotationMagic.data(), kRotationMagic.size());
    off += kRotationMagic.size();
    buf[off++] = kRotationVersion;
    buf[off++] = 0;  // flags
    std::memcpy(buf + off, new_user_pk.data(),  GN_PUBLIC_KEY_BYTES);
    off += GN_PUBLIC_KEY_BYTES;
    std::memcpy(buf + off, prev_user_pk.data(), GN_PUBLIC_KEY_BYTES);
    off += GN_PUBLIC_KEY_BYTES;
    encode_be64(static_cast<std::int64_t>(counter), buf + off);
    off += 8;
    encode_be64(valid_from_unix_ts, buf + off);
    /// off + 8 == kRotationProofSignedBytes by construction.
}

}  // namespace

::gn::Result<std::array<std::uint8_t, kRotationProofBytes>>
sign_rotation(const KeyPair&                prev_user_kp,
              const ::gn::PublicKey&        new_user_pk,
              std::uint64_t                 counter,
              std::int64_t                  valid_from_unix_ts) {
    if (!prev_user_kp.has_secret()) {
        return std::unexpected(::gn::Error{
            GN_ERR_INVALID_STATE,
            "sign_rotation: prev_user keypair has no secret"});
    }

    std::array<std::uint8_t, kRotationProofBytes> out{};
    compose_signed_prefix(out.data(), new_user_pk,
                           prev_user_kp.public_key(),
                           counter, valid_from_unix_ts);

    /// SHA-256 of the signed prefix is the message Ed25519 signs.
    std::array<std::uint8_t, crypto_hash_sha256_BYTES> digest{};
    if (::crypto_hash_sha256(digest.data(), out.data(),
                              kRotationProofSignedBytes) != 0) {
        return std::unexpected(::gn::Error{
            GN_ERR_OUT_OF_MEMORY, "sign_rotation: SHA-256 failed"});
    }

    auto sig = prev_user_kp.sign(std::span<const std::uint8_t>(digest));
    if (!sig) return std::unexpected(sig.error());
    std::memcpy(out.data() + kRotationProofSigOffset, sig->data(), 64);
    return out;
}

::gn::Result<RotationProof>
verify_rotation(std::span<const std::uint8_t>      wire,
                const ::gn::PublicKey&             expected_prev_user_pk) {
    if (wire.size() != kRotationProofBytes) {
        return std::unexpected(::gn::Error{
            GN_ERR_INTEGRITY_FAILED,
            "rotation: wrong wire size"});
    }
    if (std::memcmp(wire.data(), kRotationMagic.data(),
                     kRotationMagic.size()) != 0) {
        return std::unexpected(::gn::Error{
            GN_ERR_INTEGRITY_FAILED, "rotation: bad magic"});
    }
    if (wire[kRotationMagic.size()] != kRotationVersion) {
        return std::unexpected(::gn::Error{
            GN_ERR_VERSION_MISMATCH, "rotation: bad version"});
    }
    if (wire[kRotationMagic.size() + 1] != 0) {
        return std::unexpected(::gn::Error{
            GN_ERR_INTEGRITY_FAILED, "rotation: bad flags"});
    }

    RotationProof out{};
    std::size_t off = 6;
    std::memcpy(out.new_user_pk.data(),  wire.data() + off, GN_PUBLIC_KEY_BYTES);
    off += GN_PUBLIC_KEY_BYTES;
    std::memcpy(out.prev_user_pk.data(), wire.data() + off, GN_PUBLIC_KEY_BYTES);
    off += GN_PUBLIC_KEY_BYTES;
    out.counter            = decode_be64_u(wire.data() + off);
    off += 8;
    out.valid_from_unix_ts = decode_be64_s(wire.data() + off);
    /// off + 8 == kRotationProofSigOffset by construction; the
    /// signature is read from the fixed offset below, no further
    /// `off` advance needed.
    std::memcpy(out.sig_by_prev.data(),
                wire.data() + kRotationProofSigOffset, 64);

    /// Anti-confusion: the proof's `prev_user_pk` must match the
    /// caller's expected pinned user_pk for this peer. Without the
    /// gate a misrouted proof from another peer could verify
    /// against its own `prev_user_pk` and trick the receiver into
    /// accepting an unrelated rotation.
    if (out.prev_user_pk != expected_prev_user_pk) {
        return std::unexpected(::gn::Error{
            GN_ERR_INTEGRITY_FAILED, "rotation: prev_user_pk mismatch"});
    }

    /// Verify Ed25519 signature against the SHA-256 digest of the
    /// signed prefix.
    std::array<std::uint8_t, crypto_hash_sha256_BYTES> digest{};
    if (::crypto_hash_sha256(digest.data(), wire.data(),
                              kRotationProofSignedBytes) != 0) {
        return std::unexpected(::gn::Error{
            GN_ERR_OUT_OF_MEMORY, "rotation: SHA-256 failed"});
    }
    if (!KeyPair::verify(out.prev_user_pk,
                          std::span<const std::uint8_t>(digest),
                          std::span<const std::uint8_t, 64>(out.sig_by_prev))) {
        return std::unexpected(::gn::Error{
            GN_ERR_INTEGRITY_FAILED, "rotation: bad signature"});
    }
    return out;
}

} // namespace gn::core::identity
