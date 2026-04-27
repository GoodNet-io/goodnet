/// @file   core/kernel/host_api_builder.cpp
/// @brief  Implementation of `build_host_api`.

#include "host_api_builder.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <core/util/log.hpp>

#include "connection_context.hpp"
#include "kernel.hpp"

namespace gn::core {

namespace {

/* ── Slot thunks. Each casts host_ctx → PluginContext* and dispatches. ── */

gn_result_t thunk_send(void* host_ctx,
                       gn_conn_id_t conn,
                       uint32_t msg_id,
                       const uint8_t* payload,
                       size_t payload_size) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_UNKNOWN_RECEIVER;

    auto trans = pc->kernel->transports().find_by_scheme(rec->transport_scheme);
    if (!trans || !trans->vtable || !trans->vtable->send) {
        return GN_ERR_NOT_IMPLEMENTED;
    }

    auto* layer = pc->kernel->protocol_layer();
    if (!layer) return GN_ERR_NOT_IMPLEMENTED;

    /// Build the envelope from the connection's identity and the
    /// caller-provided payload.
    gn_message_t env{};
    env.msg_id       = msg_id;
    env.payload      = payload;
    env.payload_size = payload_size;
    if (auto local = pc->kernel->identities().any(); local) {
        std::memcpy(env.sender_pk, local->data(), GN_PUBLIC_KEY_BYTES);
    }
    std::memcpy(env.receiver_pk, rec->remote_pk.data(), GN_PUBLIC_KEY_BYTES);

    gn_connection_context_t ctx{};
    ctx.conn_id   = conn;
    ctx.trust     = rec->trust;
    ctx.remote_pk = rec->remote_pk;
    if (auto local = pc->kernel->identities().any(); local) {
        ctx.local_pk = *local;
    }

    auto framed = layer->frame(ctx, env);
    if (!framed) return framed.error().code;

    return trans->vtable->send(trans->self, conn,
                               framed->data(), framed->size());
}

gn_result_t thunk_disconnect(void* host_ctx, gn_conn_id_t conn) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_UNKNOWN_RECEIVER;
    auto trans = pc->kernel->transports().find_by_scheme(rec->transport_scheme);
    if (!trans || !trans->vtable || !trans->vtable->disconnect) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    return trans->vtable->disconnect(trans->self, conn);
}

gn_result_t thunk_register_transport(void* host_ctx,
                                     const char* scheme,
                                     const gn_transport_vtable_t* vtable,
                                     void* transport_self,
                                     gn_transport_id_t* out_id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    return pc->kernel->transports().register_transport(
        scheme, vtable, transport_self, out_id);
}

gn_result_t thunk_unregister_transport(void* host_ctx, gn_transport_id_t id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    return pc->kernel->transports().unregister_transport(id);
}

gn_result_t thunk_register_handler(void* host_ctx,
                                   const char* protocol_id,
                                   uint32_t msg_id,
                                   uint8_t priority,
                                   const gn_handler_vtable_t* vtable,
                                   void* handler_self,
                                   gn_handler_id_t* out_id) {
    if (!host_ctx || !protocol_id || !vtable || !out_id) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    return pc->kernel->handlers().register_handler(
        protocol_id, msg_id, priority, vtable, handler_self, out_id);
}

gn_result_t thunk_unregister_handler(void* host_ctx, gn_handler_id_t id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    return pc->kernel->handlers().unregister_handler(id);
}

const gn_limits_t* thunk_limits(void* host_ctx) {
    if (!host_ctx) return nullptr;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    return &pc->kernel->limits();
}

gn_result_t thunk_config_get_string(void* host_ctx,
                                    const char* key,
                                    char** out_str,
                                    void (**out_free)(char*)) {
    if (!host_ctx || !key || !out_str || !out_free) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);

    std::string buf;
    const auto rc = pc->kernel->config().get_string(key, buf);
    if (rc != GN_OK) return rc;

    /// Plain malloc'd C string the caller frees through *out_free.
    auto* heap = static_cast<char*>(std::malloc(buf.size() + 1));
    if (!heap) return GN_ERR_OUT_OF_MEMORY;
    std::memcpy(heap, buf.data(), buf.size());
    heap[buf.size()] = '\0';

    *out_str  = heap;
    *out_free = +[](char* p) { std::free(p); };
    return GN_OK;
}

gn_result_t thunk_config_get_int64(void* host_ctx,
                                   const char* key,
                                   int64_t* out_value) {
    if (!host_ctx || !key || !out_value) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    std::int64_t v = 0;
    const auto rc = pc->kernel->config().get_int64(key, v);
    if (rc != GN_OK) return rc;
    *out_value = v;
    return GN_OK;
}

void thunk_log(void* host_ctx, gn_log_level_t level, const char* fmt, ...) {
    if (!host_ctx || !fmt) return;
    auto* pc = static_cast<PluginContext*>(host_ctx);

    /// Map the C ABI level to spdlog's enum.
    auto sp_lvl = ::spdlog::level::info;
    switch (level) {
        case GN_LOG_TRACE: sp_lvl = ::spdlog::level::trace;    break;
        case GN_LOG_DEBUG: sp_lvl = ::spdlog::level::debug;    break;
        case GN_LOG_INFO:  sp_lvl = ::spdlog::level::info;     break;
        case GN_LOG_WARN:  sp_lvl = ::spdlog::level::warn;     break;
        case GN_LOG_ERROR: sp_lvl = ::spdlog::level::err;      break;
        case GN_LOG_FATAL: sp_lvl = ::spdlog::level::critical; break;
    }
    if (!::gn::log::kernel().should_log(sp_lvl)) return;

    /// Render varargs into a stack buffer; truncate beyond 4 KiB so the
    /// hot path stays allocation-free.
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    ::gn::log::kernel().log(sp_lvl, "[{}] {}", pc->plugin_name, buf);
}

gn_result_t thunk_notify_connect(void* host_ctx,
                                 const uint8_t remote_pk[GN_PUBLIC_KEY_BYTES],
                                 const char* uri,
                                 const char* scheme,
                                 gn_trust_class_t trust,
                                 gn_conn_id_t* out_conn) {
    if (!host_ctx || !remote_pk || !uri || !scheme || !out_conn) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);

    ConnectionRecord rec;
    rec.id = pc->kernel->connections().alloc_id();
    rec.uri = uri;
    rec.transport_scheme = scheme;
    rec.trust = trust;
    std::memcpy(rec.remote_pk.data(), remote_pk, GN_PUBLIC_KEY_BYTES);

    const gn_result_t rc =
        pc->kernel->connections().insert_with_index(std::move(rec));
    if (rc != GN_OK) return rc;

    *out_conn = rec.id;
    return GN_OK;
}

gn_result_t thunk_notify_inbound_bytes(void* host_ctx,
                                       gn_conn_id_t conn,
                                       const uint8_t* bytes,
                                       size_t size) {
    if (!host_ctx || (!bytes && size > 0)) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);

    /// Look up the connection record to populate the per-call context.
    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_UNKNOWN_RECEIVER;

    gn_connection_context_t ctx{};
    ctx.conn_id   = conn;
    ctx.trust     = rec->trust;
    ctx.remote_pk = rec->remote_pk;
    if (auto local = pc->kernel->identities().any(); local) {
        ctx.local_pk = *local;
    }

    auto* layer = pc->kernel->protocol_layer();
    if (layer == nullptr) return GN_ERR_NOT_IMPLEMENTED;

    auto deframed = layer->deframe(ctx, std::span<const std::uint8_t>{bytes, size});
    if (!deframed.has_value()) return deframed.error().code;

    auto& router = pc->kernel->router();
    for (const auto& env : deframed->messages) {
        (void)router.route_inbound(layer->protocol_id(), env);
    }
    return GN_OK;
}

gn_result_t thunk_notify_disconnect(void* host_ctx,
                                    gn_conn_id_t conn,
                                    gn_result_t /*reason*/) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    return pc->kernel->connections().erase_with_index(conn);
}

} // namespace

host_api_t build_host_api(PluginContext& ctx) {
    host_api_t a{};
    a.api_size = sizeof(host_api_t);
    a.host_ctx = &ctx;

    a.send                  = &thunk_send;
    a.disconnect            = &thunk_disconnect;

    a.register_handler      = &thunk_register_handler;
    a.unregister_handler    = &thunk_unregister_handler;

    a.register_transport    = &thunk_register_transport;
    a.unregister_transport  = &thunk_unregister_transport;

    a.limits                = &thunk_limits;
    a.log                   = &thunk_log;

    a.config_get_string     = &thunk_config_get_string;
    a.config_get_int64      = &thunk_config_get_int64;

    a.notify_connect        = &thunk_notify_connect;
    a.notify_inbound_bytes  = &thunk_notify_inbound_bytes;
    a.notify_disconnect     = &thunk_notify_disconnect;

    /// Other slots remain NULL; plugins guard with GN_API_HAS.
    return a;
}

} // namespace gn::core
