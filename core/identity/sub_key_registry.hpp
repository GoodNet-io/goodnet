/// @file   core/identity/sub_key_registry.hpp
/// @brief  Kernel-held per-purpose sub-key registry under one
///         NodeIdentity (NodeIdentity v2 §3 of identity.en.md).
///
/// The registry holds Ed25519 keypairs the local node uses for
/// purposes beyond the built-in pair (`user_pk`,
/// `device_pk`) — e.g. recovery keys, second-factor signing keys,
/// capability-invoke keys. Plugins never see private bytes; they
/// drive the registry through the host_api slots
/// `register_local_key` / `delete_local_key` / `list_local_keys`
/// and request signing through `sign_local` /
/// `sign_local_by_id`. All entries persist with the parent
/// `NodeIdentity` in the on-disk v2 file (`identity.en.md` §3a).
///
/// Concurrency: NodeIdentity is the unit of synchronization. The
/// kernel publishes a NodeIdentity through `set_node_identity`
/// (atomic shared_ptr swap); concurrent readers either see the
/// prior or the new value, never a half-written state. Mutations
/// build a fresh NodeIdentity (clone, mutate, swap), so the
/// registry itself is plain data with no in-class mutex.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <sdk/identity.h>

#include "keypair.hpp"

namespace gn::core::identity {

/// One entry in the sub-key registry.
struct SubKeyEntry {
    gn_key_id_t       id;
    gn_key_purpose_t  purpose;
    KeyPair           kp;
    std::string       label;
    std::int64_t      created_unix_ts;
};

/// Plain-data backing of the sub-key registry. Lives inside
/// NodeIdentity; the kernel composes operations on a
/// freshly-cloned NodeIdentity and swaps the result in.
class SubKeyRegistry {
public:
    SubKeyRegistry()                                    = default;
    SubKeyRegistry(const SubKeyRegistry&)               = delete;
    SubKeyRegistry& operator=(const SubKeyRegistry&)    = delete;
    SubKeyRegistry(SubKeyRegistry&&)                    = default;
    SubKeyRegistry& operator=(SubKeyRegistry&&)         = default;

    /// Register a new keypair under @p purpose with optional
    /// free-text label. Returns the kernel-allocated id; the
    /// id encodes the purpose in its top 4 bits so iteration
    /// callers can filter without re-touching the registry.
    [[nodiscard]] gn_key_id_t insert(gn_key_purpose_t purpose,
                                      KeyPair&&        kp,
                                      std::string_view label,
                                      std::int64_t     created_unix_ts);

    /// Remove the entry with the given id, zeroising the
    /// private bytes through `KeyPair`'s destructor. Returns
    /// `true` if removed, `false` if id not present.
    bool erase(gn_key_id_t id);

    /// Snapshot the descriptors of every live sub-key for
    /// `list_local_keys`. Caller-supplied buffer is filled in
    /// kernel-allocation order. `*out_count` reports the total
    /// (so callers can re-call with a larger buffer if
    /// truncated).
    void snapshot(gn_key_descriptor_t* out, std::size_t cap,
                  std::size_t* out_count) const;

    /// Find the first entry whose `purpose` matches and return
    /// a const pointer to the keypair. Returns `nullptr` if no
    /// entry matches.
    [[nodiscard]] const KeyPair* find_first_of_purpose(
        gn_key_purpose_t purpose) const noexcept;

    /// Find the entry by id and return a const pointer to its
    /// keypair. Returns `nullptr` if no entry matches.
    [[nodiscard]] const KeyPair* find_by_id(
        gn_key_id_t id) const noexcept;

    /// Direct entry access — registry is plain-data, no
    /// internal locking. Used by the parent NodeIdentity for
    /// serialization and clone.
    [[nodiscard]] const std::vector<SubKeyEntry>& entries() const noexcept {
        return entries_;
    }
    std::vector<SubKeyEntry>& entries_mut() noexcept {
        return entries_;
    }

    [[nodiscard]] std::size_t size() const noexcept {
        return entries_.size();
    }

private:
    std::vector<SubKeyEntry>  entries_;
    /// Monotonic counter the kernel uses to mint ids. Top 4 bits
    /// of the produced id encode `purpose`; bottom 60 bits hold
    /// the counter.
    std::uint64_t             next_counter_ = 1;
};

/// Encode purpose + counter into the 64-bit `gn_key_id_t`. Top
/// 4 bits = purpose (1..15), bottom 60 bits = monotonic counter.
[[nodiscard]] inline gn_key_id_t encode_key_id(gn_key_purpose_t purpose,
                                                std::uint64_t    counter) noexcept {
    const std::uint64_t purpose_bits =
        (static_cast<std::uint64_t>(purpose) & 0x0Fu) << 60;
    return static_cast<gn_key_id_t>(purpose_bits | (counter & 0x0FFFFFFFFFFFFFFFull));
}

/// Pull purpose out of a `gn_key_id_t`. Used by iteration
/// callers that want to filter without touching the registry.
[[nodiscard]] inline gn_key_purpose_t purpose_of(gn_key_id_t id) noexcept {
    return static_cast<gn_key_purpose_t>((id >> 60) & 0x0Fu);
}

} // namespace gn::core::identity
