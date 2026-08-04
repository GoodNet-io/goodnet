/// @file   core/kernel/system_handlers.cpp
/// @brief  Kernel system handlers for identity-range msg_ids.
///
/// Replaces the hardcoded special-case branches that previously lived
/// in `notify_inbound_bytes`. Each handler is a priority=255 entry
/// registered at `gn_core_start()` for every active protocol.
/// See `docs/contracts/system-handlers.en.md` §1–2.

#include "system_handlers.hpp"

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <sdk/handler.h>
#include <sdk/types.h>

#include "attestation_dispatcher.hpp"
#include "capability_blob.hpp"
#include "conn_event.hpp"
#include "kernel.hpp"
#include "system_handler_ids.hpp"

#include <core/identity/rotation.hpp>
#include <core/registry/handler.hpp>
#include <core/registry/protocol_layer.hpp>

namespace gn::core {

namespace {

// ── Attestation handler (0x11) ─────────────────────────────────────────────

gn_propagation_t attestation_handle(void* self, const gn_message_t* env) noexcept {
    auto* k = static_cast<Kernel*>(self);
    auto session = k->sessions().find(env->conn_id);
    if (session) {
        const std::span<const std::uint8_t> payload{env->payload, env->payload_size};
        (void)k->attestation_dispatcher().on_inbound(*k, env->conn_id, *session, payload);
    }
    return GN_PROPAGATION_CONSUMED;
}

gn_handler_vtable_t make_attestation_vtable() noexcept {
    gn_handler_vtable_t v{};
    v.api_size      = sizeof(gn_handler_vtable_t);
    v.handle_message = attestation_handle;
    return v;
}

// ── Rotation handler (0x12) ────────────────────────────────────────────────

gn_propagation_t rotation_handle(void* self, const gn_message_t* env) noexcept {
    auto* k  = static_cast<Kernel*>(self);
    auto  rec = k->connections().find_by_id(env->conn_id);
    if (!rec) return GN_PROPAGATION_CONSUMED;

    auto pin = k->connections().get_pinned_peer(rec->remote_pk);
    if (!pin) return GN_PROPAGATION_CONSUMED;

    auto verified = identity::verify_rotation(
        std::span<const std::uint8_t>{env->payload, env->payload_size},
        pin->user_pk);
    if (!verified) {
        k->metrics().increment("drop.rotation_bad_proof");
        return GN_PROPAGATION_CONTINUE;
    }
    if (k->connections().apply_rotation(
            rec->remote_pk, verified->new_user_pk, verified->counter) != GN_OK) {
        k->metrics().increment("drop.rotation_replay");
        return GN_PROPAGATION_CONTINUE;
    }

    ConnEvent ev{};
    ev.kind         = GN_CONN_EVENT_IDENTITY_ROTATED;
    ev.conn         = env->conn_id;
    ev.trust        = rec->trust;
    ev.remote_pk    = rec->remote_pk;
    ev.user_pk_prev = verified->prev_user_pk.data();
    ev.user_pk_next = verified->new_user_pk.data();
    ev.rotation_seq = &verified->counter;
    k->on_conn_event().fire(ev);

    return GN_PROPAGATION_CONTINUE;
}

gn_handler_vtable_t make_rotation_vtable() noexcept {
    gn_handler_vtable_t v{};
    v.api_size       = sizeof(gn_handler_vtable_t);
    v.handle_message = rotation_handle;
    return v;
}

// ── Capability blob handler (0x13) ─────────────────────────────────────────

gn_propagation_t capability_blob_handle(void* self, const gn_message_t* env) noexcept {
    auto* k = static_cast<Kernel*>(self);
    k->capability_blob_bus().on_inbound(env->conn_id, env->payload, env->payload_size);
    return GN_PROPAGATION_CONTINUE;
}

gn_handler_vtable_t make_capability_blob_vtable() noexcept {
    gn_handler_vtable_t v{};
    v.api_size       = sizeof(gn_handler_vtable_t);
    v.handle_message = capability_blob_handle;
    return v;
}

// ── Static vtable instances ────────────────────────────────────────────────

// Vtables are stateless; one copy per msg_id is sufficient for all protocols.
const gn_handler_vtable_t kAttestationVtable     = make_attestation_vtable();
const gn_handler_vtable_t kRotationVtable        = make_rotation_vtable();
const gn_handler_vtable_t kCapabilityBlobVtable  = make_capability_blob_vtable();

} // namespace

void register_kernel_system_handlers(
    Kernel&                              kernel,
    const std::vector<std::string_view>& protocol_ids,
    std::vector<gn_handler_id_t>&        out_ids)
{
    struct SysEntry {
        std::uint32_t            msg_id;
        const gn_handler_vtable_t* vtable;
    };
    constexpr SysEntry kEntries[] = {
        { kAttestationMsgId,   &kAttestationVtable    },
        { kIdentityRotationMsgId, &kRotationVtable    },
        { kCapabilityBlobMsgId,   &kCapabilityBlobVtable },
    };

    for (const auto& proto_id : protocol_ids) {
        for (const auto& e : kEntries) {
            gn_handler_id_t hid = GN_INVALID_ID;
            (void)kernel.handlers().register_handler(
                kDefaultHandlerNamespace,
                proto_id,
                e.msg_id,
                kKernelHandlerPriority,
                e.vtable,
                &kernel,
                &hid,
                {},
                "gn.kernel",
                /*allow_kernel_reserved*/ true);
            if (hid != GN_INVALID_ID) {
                out_ids.push_back(hid);
            }
        }
    }
}

void unregister_kernel_system_handlers(
    Kernel&                        kernel,
    std::vector<gn_handler_id_t>&  ids)
{
    for (const auto id : ids) {
        (void)kernel.handlers().unregister_handler(id);
    }
    ids.clear();
}

} // namespace gn::core
