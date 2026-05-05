/// @file   core/identity/node_identity.hpp
/// @brief  Aggregated node identity — user keypair, device keypair,
///         attestation, and the derived mesh address.
///
/// One NodeIdentity per running kernel for the single-tenant case;
/// future multi-device deployments compose several device-side
/// NodeIdentity instances under one persistent UserKeyPair.

#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>

#include "attestation.hpp"
#include "derive.hpp"
#include "keypair.hpp"

namespace gn::core::identity {

/// On-disk identity file size. Format pinned in `node_identity.cpp`:
/// 4-byte magic + 1-byte version + 8-byte expiry_be64 +
/// 32-byte user seed + 32-byte device seed = 77 bytes.
inline constexpr std::size_t kIdentityFileBytes = 77;

class NodeIdentity {
public:
    NodeIdentity()                                = default;
    NodeIdentity(const NodeIdentity&)             = delete;
    NodeIdentity& operator=(const NodeIdentity&)  = delete;

    NodeIdentity(NodeIdentity&&)                  = default;
    NodeIdentity& operator=(NodeIdentity&&)       = default;

    /// Generate a fresh identity: random user keypair, random device
    /// keypair, attestation valid until @p expiry_unix_ts, derived
    /// address bound to the pair.
    [[nodiscard]] static ::gn::Result<NodeIdentity>
    generate(std::int64_t expiry_unix_ts);

    /// Compose from existing keypairs — used when a long-term user
    /// keypair was loaded from backup and a fresh device keypair was
    /// minted on this machine.
    [[nodiscard]] static ::gn::Result<NodeIdentity>
    compose(KeyPair&& user, KeyPair&& device, std::int64_t expiry_unix_ts);

    [[nodiscard]] const KeyPair&            user()        const noexcept { return user_; }
    [[nodiscard]] const KeyPair&            device()      const noexcept { return device_; }
    [[nodiscard]] const Attestation&        attestation() const noexcept { return att_; }
    [[nodiscard]] const ::gn::PublicKey&    address()     const noexcept { return address_; }

    /// Persist this identity to @p path. Writes a 77-byte binary
    /// blob at file mode `0600` so a casual `cat` of the directory
    /// does not leak secret material to peers on the host. Format:
    /// magic + version + expiry + (user, device) seeds; the
    /// attestation signature and the derived address are reproduced
    /// deterministically on `load_from_file`. Failure modes:
    /// - `GN_ERR_INVALID_STATE` if the keypairs were wiped.
    /// - `GN_ERR_NULL_ARG` on empty @p path.
    /// - `GN_ERR_OUT_OF_MEMORY` on filesystem write failure.
    [[nodiscard]] static ::gn::Result<void>
    save_to_file(const NodeIdentity& self, const std::string& path);

    /// Inverse of `save_to_file`. Reconstructs the full identity from
    /// the saved seeds, re-derives the attestation and address, and
    /// returns the assembled instance. Verifies the magic + version
    /// prefix and the attestation's own signature before returning;
    /// a tampered file fails with `GN_ERR_INTEGRITY_FAILED` rather
    /// than silently producing garbage keys.
    [[nodiscard]] static ::gn::Result<NodeIdentity>
    load_from_file(const std::string& path);

private:
    KeyPair         user_;
    KeyPair         device_;
    Attestation     att_{};
    ::gn::PublicKey address_{};
};

} // namespace gn::core::identity
