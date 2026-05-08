/// @file   core/identity/node_identity.hpp
/// @brief  Aggregated node identity — user keypair, device keypair,
///         attestation, derived mesh address, sub-key registry,
///         rotation counter + history.
///
/// One NodeIdentity per running kernel (single-tenant). Multi-device
/// deployments compose several NodeIdentity instances under one
/// persistent user keypair; rotation propagates through
/// `core/identity/rotation.{hpp,cpp}`.

#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "attestation.hpp"
#include "derive.hpp"
#include "keypair.hpp"
#include "sub_key_registry.hpp"

namespace gn::core::identity {

/// One past-rotation entry recorded by the kernel for retroactive
/// signature verification of historical proofs. Rotation logic
/// (`core/identity/rotation.{hpp,cpp}`) populates this vector
/// when the kernel either announces or applies a rotation.
struct RotationEntry {
    ::gn::PublicKey                 prev_user_pk;
    ::gn::PublicKey                 next_user_pk;
    std::uint64_t                   counter;
    std::int64_t                    valid_from_unix_ts;
    std::array<std::uint8_t, 64>    sig_by_prev;
};

class NodeIdentity {
public:
    NodeIdentity()                                = default;
    NodeIdentity(const NodeIdentity&)             = delete;
    NodeIdentity& operator=(const NodeIdentity&)  = delete;

    NodeIdentity(NodeIdentity&&)                  = default;
    NodeIdentity& operator=(NodeIdentity&&)       = default;

    /// Generate a fresh identity: random user keypair, random device
    /// keypair, attestation valid until @p expiry_unix_ts, derived
    /// address bound to the device keypair only (per
    /// `docs/contracts/identity.en.md` §3 decouple).
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

    [[nodiscard]] SubKeyRegistry&           sub_keys()       noexcept { return sub_keys_; }
    [[nodiscard]] const SubKeyRegistry&     sub_keys() const noexcept { return sub_keys_; }

    [[nodiscard]] std::uint64_t rotation_counter() const noexcept {
        return rotation_counter_;
    }
    [[nodiscard]] const std::vector<RotationEntry>&
    rotation_history() const noexcept { return rotation_history_; }

    /// Bump the rotation counter (Phase 5 calls this when announcing
    /// or applying a rotation). Returns the new value.
    std::uint64_t bump_rotation_counter() noexcept {
        return ++rotation_counter_;
    }

    /// Append a rotation entry to the kernel-side history.
    /// Rotation logic calls this after persisting the new
    /// `user_` keypair.
    void push_rotation_history(RotationEntry entry) {
        rotation_history_.push_back(entry);
    }

    /// Persist this identity to @p path at file mode `0600`.
    /// Format: 4-byte magic `"GNID"` + 1-byte version + 1-byte
    /// flags + 8-byte expiry + user_seed + device_seed +
    /// rotation_counter + sub-key entries + rotation history.
    /// Failure modes:
    /// - `GN_ERR_INVALID_STATE` if the keypairs were wiped.
    /// - `GN_ERR_NULL_ARG` on empty @p path.
    /// - `GN_ERR_OUT_OF_MEMORY` on filesystem write failure.
    [[nodiscard]] static ::gn::Result<void>
    save_to_file(const NodeIdentity& self, const std::string& path);

    /// Inverse of `save_to_file`. Verifies the magic + version
    /// prefix and the attestation's own signature; a tampered
    /// file fails with `GN_ERR_INTEGRITY_FAILED`.
    [[nodiscard]] static ::gn::Result<NodeIdentity>
    load_from_file(const std::string& path);

    /// Deep-clone this identity. Used by host_api thunks that
    /// mutate identity state (`register_local_key`,
    /// `delete_local_key`, rotation): callers clone the current
    /// instance, mutate the clone, then swap it in via
    /// `Kernel::set_node_identity`. Concurrent readers of the
    /// prior instance keep a valid `shared_ptr<const>` snapshot.
    [[nodiscard]] ::gn::Result<NodeIdentity> clone() const;

private:
    KeyPair                     user_;
    KeyPair                     device_;
    Attestation                 att_{};
    ::gn::PublicKey             address_{};
    SubKeyRegistry              sub_keys_;
    std::uint64_t               rotation_counter_ = 0;
    std::vector<RotationEntry>  rotation_history_;
};

} // namespace gn::core::identity
