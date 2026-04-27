/// @file   core/kernel/connection_context.cpp
/// @brief  C ABI accessor implementations for `gn_connection_context_t`.

#include "connection_context.hpp"

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

void* gn_ctx_plugin_state(const gn_connection_context_t* ctx) {
    return ctx ? ctx->plugin_state : nullptr;
}

void gn_ctx_set_plugin_state(gn_connection_context_t* ctx, void* state) {
    if (ctx) ctx->plugin_state = state;
}

} // extern "C"
