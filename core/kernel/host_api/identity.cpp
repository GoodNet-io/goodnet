/// @file   core/kernel/host_api/identity.cpp
/// @brief  Identity primitives + capability blob slots.

#include "../host_api_internal.hpp"

#include <cstring>
#include <ctime>
#include <vector>

#include <core/identity/node_identity.hpp>
#include <core/identity/rotation.hpp>
#include <sdk/identity.h>

#include "../system_handler_ids.hpp"

namespace gn::core::host_api_thunks {

using namespace host_api_internal;

namespace {

/// Channel tag for capability_blob subscriptions. Mirrors the
/// subscription-id packing scheme in `control.cpp`.
constexpr std::uint64_t kSubChannelShift       = 60;
constexpr std::uint64_t kSubTokenMask          =
    (std::uint64_t{1} << kSubChannelShift) - 1;
constexpr std::uint64_t kCapabilityBlobChannel = 2;

}  // namespace

gn_result_t register_local_key(void* host_ctx,
                                gn_key_purpose_t purpose,
                                const char* label,
                                gn_key_id_t* out_id) {
    if (!host_ctx || !out_id) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    *out_id = GN_INVALID_KEY_ID;

    auto current = pc->kernel->node_identity();
    if (!current) return GN_ERR_INVALID_STATE;

    auto cloned = current->clone();
    if (!cloned) return cloned.error().code;

    auto kp = identity::KeyPair::generate();
    if (!kp) return kp.error().code;

    const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    const std::string_view label_sv = (label != nullptr) ? label : "";
    const auto id = cloned->sub_keys().insert(purpose, std::move(*kp),
                                               label_sv, now);
    *out_id = id;

    pc->kernel->set_node_identity(std::move(*cloned));
    return GN_OK;
}

gn_result_t delete_local_key(void* host_ctx, gn_key_id_t id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    if (id == GN_INVALID_KEY_ID) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto current = pc->kernel->node_identity();
    if (!current) return GN_ERR_INVALID_STATE;

    auto cloned = current->clone();
    if (!cloned) return cloned.error().code;

    if (!cloned->sub_keys().erase(id)) return GN_ERR_NOT_FOUND;
    pc->kernel->set_node_identity(std::move(*cloned));
    return GN_OK;
}

gn_result_t list_local_keys(void* host_ctx,
                             gn_key_descriptor_t* out_array,
                             std::size_t array_cap,
                             std::size_t* out_count) {
    if (!host_ctx || !out_count) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto current = pc->kernel->node_identity();
    if (!current) {
        *out_count = 0;
        return GN_ERR_INVALID_STATE;
    }
    current->sub_keys().snapshot(out_array, array_cap, out_count);
    return GN_OK;
}

gn_result_t sign_local(void* host_ctx,
                        gn_key_purpose_t purpose,
                        const std::uint8_t* payload,
                        std::size_t size,
                        std::uint8_t out_sig[64]) {
    if (!host_ctx || !out_sig) return GN_ERR_NULL_ARG;
    if (!payload && size > 0) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto current = pc->kernel->node_identity();
    if (!current) return GN_ERR_INVALID_STATE;

    const identity::KeyPair* kp = nullptr;
    switch (purpose) {
    case GN_KEY_PURPOSE_ASSERT:
    case GN_KEY_PURPOSE_ROTATION_SIGN:
        kp = &current->user();
        break;
    case GN_KEY_PURPOSE_AUTH:
    case GN_KEY_PURPOSE_KEY_AGREEMENT:
        kp = &current->device();
        break;
    default:
        kp = current->sub_keys().find_first_of_purpose(purpose);
        break;
    }
    if (!kp) return GN_ERR_NOT_FOUND;

    auto sig = kp->sign(std::span<const std::uint8_t>(payload, size));
    if (!sig) return sig.error().code;
    std::memcpy(out_sig, sig->data(), 64);
    return GN_OK;
}

gn_result_t sign_local_by_id(void* host_ctx,
                              gn_key_id_t id,
                              const std::uint8_t* payload,
                              std::size_t size,
                              std::uint8_t out_sig[64]) {
    if (!host_ctx || !out_sig) return GN_ERR_NULL_ARG;
    if (id == GN_INVALID_KEY_ID) return GN_ERR_NULL_ARG;
    if (!payload && size > 0) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto current = pc->kernel->node_identity();
    if (!current) return GN_ERR_INVALID_STATE;

    const auto* kp = current->sub_keys().find_by_id(id);
    if (!kp) return GN_ERR_NOT_FOUND;

    auto sig = kp->sign(std::span<const std::uint8_t>(payload, size));
    if (!sig) return sig.error().code;
    std::memcpy(out_sig, sig->data(), 64);
    return GN_OK;
}

gn_result_t get_peer_user_pk(void* host_ctx,
                              gn_conn_id_t conn,
                              std::uint8_t out_pk[GN_PUBLIC_KEY_BYTES]) {
    if (!host_ctx || !out_pk) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;

    auto pin = pc->kernel->connections().get_pinned_peer(rec->remote_pk);
    if (!pin) return GN_ERR_INVALID_STATE;
    std::memcpy(out_pk, pin->user_pk.data(), GN_PUBLIC_KEY_BYTES);
    return GN_OK;
}

gn_result_t get_peer_device_pk(void* host_ctx,
                                gn_conn_id_t conn,
                                std::uint8_t out_pk[GN_PUBLIC_KEY_BYTES]) {
    if (!host_ctx || !out_pk) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;

    auto pin = pc->kernel->connections().get_pinned_peer(rec->remote_pk);
    if (!pin) return GN_ERR_INVALID_STATE;
    std::memcpy(out_pk, pin->device_pk.data(), GN_PUBLIC_KEY_BYTES);
    return GN_OK;
}

gn_result_t get_handshake_hash(void* host_ctx,
                                gn_conn_id_t conn,
                                std::uint8_t out_hash[GN_HASH_BYTES]) {
    if (!host_ctx || !out_hash) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;

    auto pin = pc->kernel->connections().get_pinned_peer(rec->remote_pk);
    if (!pin) return GN_ERR_INVALID_STATE;
    std::memcpy(out_hash, pin->handshake_hash.data(), GN_HASH_BYTES);
    return GN_OK;
}

gn_result_t announce_rotation(void* host_ctx,
                               std::int64_t valid_from_unix_ts) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto current = pc->kernel->node_identity();
    if (!current) return GN_ERR_INVALID_STATE;

    auto new_user_kp = identity::KeyPair::generate();
    if (!new_user_kp) return new_user_kp.error().code;

    auto cloned = current->clone();
    if (!cloned) return cloned.error().code;
    const auto next_counter = cloned->bump_rotation_counter();

    auto proof = identity::sign_rotation(
        current->user(), new_user_kp->public_key(),
        next_counter, valid_from_unix_ts);
    if (!proof) return proof.error().code;

    identity::RotationEntry entry{};
    entry.prev_user_pk        = current->user().public_key();
    entry.next_user_pk        = new_user_kp->public_key();
    entry.counter             = next_counter;
    entry.valid_from_unix_ts  = valid_from_unix_ts;
    std::memcpy(entry.sig_by_prev.data(),
                proof->data() + identity::kRotationProofSigOffset,
                64);
    cloned->push_rotation_history(entry);

    auto device_kp = cloned->device().clone();
    if (!device_kp) return device_kp.error().code;
    auto rotated = identity::NodeIdentity::compose(
        std::move(*new_user_kp), std::move(*device_kp),
        cloned->attestation().expiry_unix_ts);
    if (!rotated) return rotated.error().code;
    auto& dst_subs = rotated->sub_keys().entries_mut();
    for (auto& e : cloned->sub_keys().entries_mut()) {
        dst_subs.push_back(std::move(e));
    }
    while (rotated->rotation_counter() < next_counter) {
        rotated->bump_rotation_counter();
    }
    for (const auto& h : cloned->rotation_history()) {
        rotated->push_rotation_history(h);
    }

    pc->kernel->set_node_identity(std::move(*rotated));

    auto live_conns = std::vector<gn_conn_id_t>{};
    pc->kernel->connections().for_each(
        [&live_conns](const ConnectionRecord& rec,
                       const ConnectionRegistry::CounterSnapshot&) -> bool {
            if (rec.trust >= GN_TRUST_PEER) {
                live_conns.push_back(rec.id);
            }
            return false;
        });
    for (const auto conn : live_conns) {
        (void)send(host_ctx, conn, kIdentityRotationMsgId,
                    proof->data(), proof->size());
    }
    return GN_OK;
}

gn_result_t present_capability_blob(void* host_ctx,
                                     gn_conn_id_t conn,
                                     const std::uint8_t* blob,
                                     std::size_t size,
                                     std::int64_t expires_unix_ts) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    if (!blob && size > 0) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    const auto& limits = pc->kernel->limits();
    if (limits.max_capability_blob_bytes != 0
        && size > limits.max_capability_blob_bytes) {
        pc->kernel->metrics().increment("drop.capability_blob_too_large");
        return GN_ERR_PAYLOAD_TOO_LARGE;
    }

    std::vector<std::uint8_t> wire(8 + size);
    const auto u = static_cast<std::uint64_t>(expires_unix_ts);
    wire[0] = static_cast<std::uint8_t>((u >> 56) & 0xFFu);
    wire[1] = static_cast<std::uint8_t>((u >> 48) & 0xFFu);
    wire[2] = static_cast<std::uint8_t>((u >> 40) & 0xFFu);
    wire[3] = static_cast<std::uint8_t>((u >> 32) & 0xFFu);
    wire[4] = static_cast<std::uint8_t>((u >> 24) & 0xFFu);
    wire[5] = static_cast<std::uint8_t>((u >> 16) & 0xFFu);
    wire[6] = static_cast<std::uint8_t>((u >>  8) & 0xFFu);
    wire[7] = static_cast<std::uint8_t>( u        & 0xFFu);
    if (size > 0) std::memcpy(wire.data() + 8, blob, size);

    return send(host_ctx, conn, kCapabilityBlobMsgId,
                 wire.data(), wire.size());
}

gn_result_t subscribe_capability_blob(void* host_ctx,
                                       gn_capability_blob_cb_t cb,
                                       void* user_data,
                                       void (*ud_destroy)(void*),
                                       gn_subscription_id_t* out_id) {
    if (!host_ctx || !cb || !out_id) return GN_ERR_NULL_ARG;
    *out_id = GN_INVALID_SUBSCRIPTION_ID;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    const auto bus_id = pc->kernel->capability_blob_bus().subscribe(
        cb, user_data, ud_destroy);
    if (bus_id == GN_INVALID_SUBSCRIPTION_ID) return GN_ERR_NULL_ARG;
    *out_id = (kCapabilityBlobChannel << kSubChannelShift)
              | (bus_id & kSubTokenMask);
    return GN_OK;
}

}  // namespace gn::core::host_api_thunks
