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
#include <utility>

#include "attestation.hpp"
#include "derive.hpp"
#include "keypair.hpp"

namespace gn::core::identity {

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

private:
    KeyPair         user_;
    KeyPair         device_;
    Attestation     att_{};
    ::gn::PublicKey address_{};
};

} // namespace gn::core::identity
