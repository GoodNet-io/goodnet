/// @file   core/kernel/connection_context.cpp
/// @brief  C ABI accessor implementations for `gn_connection_context_t`.

#include "connection_context.hpp"

#include <cstring>
#include <memory>

#include <sdk/connection.h>

extern "C" {

const std::uint8_t* gn_ctx_local_pk(const gn_connection_context_t* ctx) {
    return ctx ? ctx->local_pk.data() : nullptr;
}

const std::uint8_t* gn_ctx_remote_pk(const gn_connection_context_t* ctx) {
    return ctx ? ctx->remote_pk.data() : nullptr;
}

gn_conn_id_t gn_ctx_conn_id(const gn_connection_context_t* ctx) {
    return ctx ? ctx->conn_id : GN_INVALID_ID;
}

gn_trust_class_t gn_ctx_trust(const gn_connection_context_t* ctx) {
    return ctx ? ctx->trust : GN_TRUST_UNTRUSTED;
}

int gn_ctx_allows_relay(const gn_connection_context_t* ctx) {
    return (ctx != nullptr && ctx->allows_relay) ? 1 : 0;
}

void* gn_ctx_plugin_state(const gn_connection_context_t* ctx) {
    return ctx ? ctx->plugin_state : nullptr;
}

void gn_ctx_set_plugin_state(gn_connection_context_t* ctx, void* state) {
    if (ctx) ctx->plugin_state = state;
}

gn_connection_context_t* gn_ctx_make_for_test(
    const std::uint8_t* local_pk,
    const std::uint8_t* remote_pk,
    gn_conn_id_t conn_id,
    gn_trust_class_t trust,
    int allows_relay) {
    auto* ctx = new (std::nothrow) gn_connection_context_t{};
    if (ctx == nullptr) return nullptr;
    if (local_pk != nullptr) {
        std::memcpy(ctx->local_pk.data(), local_pk, GN_PUBLIC_KEY_BYTES);
    }
    if (remote_pk != nullptr) {
        std::memcpy(ctx->remote_pk.data(), remote_pk, GN_PUBLIC_KEY_BYTES);
    }
    ctx->conn_id      = conn_id;
    ctx->trust        = trust;
    ctx->allows_relay = (allows_relay != 0);
    return ctx;
}

void gn_ctx_destroy(gn_connection_context_t* ctx) {
    delete ctx;
}

} // extern "C"
