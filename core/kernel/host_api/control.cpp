/// @file   core/kernel/host_api/control.cpp
/// @brief  Control-plane slots: queries, registration, extensions,
///         timers, subscriptions, metrics, limits, config, log,
///         security, lifecycle. Every slot here is small and shares
///         no helpers with the heavy paths in messaging/notifications.

#include "../host_api_internal.hpp"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <spdlog/spdlog.h>

#include <core/util/log.hpp>

#include "../connection_context.hpp"
#include "../safe_invoke.hpp"

namespace gn::core::host_api_thunks {

using namespace host_api_internal;

namespace {

constexpr std::uint64_t kSubChannelShift       = 60;
constexpr std::uint64_t kSubChannelMask        =
    static_cast<std::uint64_t>(0xF) << kSubChannelShift;
constexpr std::uint64_t kSubTokenMask          =
    (std::uint64_t{1} << kSubChannelShift) - 1;
constexpr std::uint64_t kCapabilityBlobChannel = 2;

[[nodiscard]] constexpr std::uint64_t pack_subscription_id(
    gn_subscribe_channel_t channel, std::uint64_t token) noexcept {
    return (static_cast<std::uint64_t>(channel) << kSubChannelShift) |
           (token & kSubTokenMask);
}

[[nodiscard]] constexpr std::uint64_t token_of_id(std::uint64_t id) noexcept {
    return id & kSubTokenMask;
}

struct UserDataGuard {
    void* user_data = nullptr;
    void (*ud_destroy)(void*) = nullptr;
    UserDataGuard(void* ud, void (*d)(void*)) noexcept
        : user_data(ud), ud_destroy(d) {}
    UserDataGuard(const UserDataGuard&)            = delete;
    UserDataGuard& operator=(const UserDataGuard&) = delete;
    ~UserDataGuard() {
        if (ud_destroy) ud_destroy(user_data);
    }
};

constexpr std::uint64_t kRegisterChannelShift = 60;
constexpr std::uint64_t kRegisterChannelMask  =
    static_cast<std::uint64_t>(0xF) << kRegisterChannelShift;
constexpr std::uint64_t kRegisterTokenMask    =
    (std::uint64_t{1} << kRegisterChannelShift) - 1;

[[nodiscard]] constexpr std::uint64_t pack_register_id(
    gn_register_kind_t kind, std::uint64_t token) noexcept {
    return (static_cast<std::uint64_t>(kind) << kRegisterChannelShift) |
           (token & kRegisterTokenMask);
}

[[nodiscard]] constexpr gn_register_kind_t kind_of_register_id(
    std::uint64_t id) noexcept {
    return static_cast<gn_register_kind_t>(
        (id & kRegisterChannelMask) >> kRegisterChannelShift);
}

[[nodiscard]] constexpr std::uint64_t token_of_register_id(
    std::uint64_t id) noexcept {
    return id & kRegisterTokenMask;
}

[[nodiscard]] ::spdlog::level::level_enum
map_log_level(gn_log_level_t level) noexcept {
    switch (level) {
        case GN_LOG_TRACE: return ::spdlog::level::trace;
        case GN_LOG_DEBUG: return ::spdlog::level::debug;
        case GN_LOG_INFO:  return ::spdlog::level::info;
        case GN_LOG_WARN:  return ::spdlog::level::warn;
        case GN_LOG_ERROR: return ::spdlog::level::err;
        case GN_LOG_FATAL: return ::spdlog::level::critical;
    }
    return ::spdlog::level::off;
}

}  // namespace

// ── Queries ────────────────────────────────────────────────────────

gn_result_t find_conn_by_pk(void* host_ctx,
                             const std::uint8_t pk[GN_PUBLIC_KEY_BYTES],
                             gn_conn_id_t* out_conn) {
    if (!host_ctx || !pk || !out_conn) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    PublicKey key{};
    std::memcpy(key.data(), pk, GN_PUBLIC_KEY_BYTES);
    auto rec = pc->kernel->connections().find_by_pk(key);
    if (!rec) return GN_ERR_NOT_FOUND;
    *out_conn = rec->id;
    return GN_OK;
}

gn_result_t get_endpoint(void* host_ctx, gn_conn_id_t conn,
                          gn_endpoint_t* out) {
    if (!host_ctx || !out) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;

    std::memset(out, 0, sizeof(*out));
    out->conn_id = rec->id;
    std::memcpy(out->remote_pk, rec->remote_pk.data(), GN_PUBLIC_KEY_BYTES);
    out->trust = rec->trust;

    const std::size_t uri_n =
        std::min(rec->uri.size(), static_cast<std::size_t>(GN_ENDPOINT_URI_MAX - 1));
    std::memcpy(out->uri, rec->uri.data(), uri_n);
    out->uri[uri_n] = '\0';

    const std::size_t scheme_n =
        std::min(rec->scheme.size(), sizeof(out->scheme) - 1);
    std::memcpy(out->scheme, rec->scheme.data(), scheme_n);
    out->scheme[scheme_n] = '\0';

    const auto counters = pc->kernel->connections().read_counters(conn);
    out->bytes_in            = counters.bytes_in;
    out->bytes_out           = counters.bytes_out;
    out->frames_in           = counters.frames_in;
    out->frames_out          = counters.frames_out;
    out->pending_queue_bytes = counters.pending_queue_bytes;
    out->last_rtt_us         = counters.last_rtt_us;
    return GN_OK;
}

// ── Security registry ──────────────────────────────────────────────

gn_result_t register_security(void* host_ctx,
                               const char* provider_id,
                               const gn_security_provider_vtable_t* vtable,
                               void* security_self) {
    if (!host_ctx || !provider_id || !vtable) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->security().register_provider(
        provider_id, vtable, security_self, pc->plugin_anchor);
}

gn_result_t unregister_security(void* host_ctx, const char* provider_id) {
    if (!host_ctx || !provider_id) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->security().unregister_provider(provider_id);
}

// ── Extension registry ─────────────────────────────────────────────

gn_result_t query_extension_checked(void* host_ctx,
                                     const char* name,
                                     uint32_t version,
                                     const void** out_vtable) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->extensions().query_extension_checked(
        name, version, out_vtable);
}

gn_result_t register_extension(void* host_ctx,
                                const char* name,
                                uint32_t version,
                                const void* vtable) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->extensions().register_extension(
        name, version, vtable, pc->plugin_anchor);
}

gn_result_t unregister_extension(void* host_ctx, const char* name) {
    if (!host_ctx || !name) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->extensions().unregister_extension(name);
}

// ── Timers ─────────────────────────────────────────────────────────

gn_result_t set_timer(void* host_ctx,
                       std::uint32_t delay_ms,
                       gn_task_fn_t fn,
                       void* user_data,
                       gn_timer_id_t* out_id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->timers().set_timer(
        delay_ms, fn, user_data, pc->plugin_anchor, out_id);
}

gn_result_t cancel_timer(void* host_ctx, gn_timer_id_t id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->timers().cancel_timer(id);
}

// ── Subscriptions ──────────────────────────────────────────────────

gn_result_t subscribe_conn_state(void* host_ctx,
                                  gn_conn_state_cb_t cb,
                                  void* user_data,
                                  void (*ud_destroy)(void*),
                                  gn_subscription_id_t* out_id) {
    if (!host_ctx || !cb || !out_id) return GN_ERR_NULL_ARG;

    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto anchor_weak = std::weak_ptr<PluginAnchor>(pc->plugin_anchor);
    const bool anchor_set = static_cast<bool>(pc->plugin_anchor);
    auto ud_guard = std::make_shared<UserDataGuard>(user_data, ud_destroy);

    auto token = pc->kernel->on_conn_event().subscribe(
        [cb, ud_guard, anchor_weak, anchor_set](const ConnEvent& ev) {
            std::optional<GateGuard> guard;
            if (anchor_set) {
                guard = GateGuard::acquire(anchor_weak);
                if (!guard) return;
            }
            gn_conn_event_t e{};
            e.api_size      = sizeof(gn_conn_event_t);
            e.kind          = ev.kind;
            e.conn          = ev.conn;
            e.trust         = ev.trust;
            e.pending_bytes = ev.pending_bytes;
            std::memcpy(e.remote_pk, ev.remote_pk.data(),
                        GN_PUBLIC_KEY_BYTES);
            safe_call_void("subscriber.conn_state",
                cb, ud_guard->user_data, &e);
        });
    if (token == signal::SignalChannel<ConnEvent>::kInvalidToken) {
        return GN_ERR_LIMIT_REACHED;
    }
    *out_id = pack_subscription_id(GN_SUBSCRIBE_CONN_STATE,
                                    static_cast<std::uint64_t>(token));
    return GN_OK;
}

gn_result_t subscribe_config_reload(void* host_ctx,
                                     gn_config_reload_cb_t cb,
                                     void* user_data,
                                     void (*ud_destroy)(void*),
                                     gn_subscription_id_t* out_id) {
    if (!host_ctx || !cb || !out_id) return GN_ERR_NULL_ARG;

    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto anchor_weak = std::weak_ptr<PluginAnchor>(pc->plugin_anchor);
    const bool anchor_set = static_cast<bool>(pc->plugin_anchor);
    auto ud_guard = std::make_shared<UserDataGuard>(user_data, ud_destroy);

    auto token = pc->kernel->on_config_reload().subscribe(
        [cb, ud_guard, anchor_weak, anchor_set](const signal::Empty&) {
            if (anchor_set) {
                auto guard = GateGuard::acquire(anchor_weak);
                if (!guard) return;
            }
            safe_call_void("subscriber.config_reload",
                cb, ud_guard->user_data);
        });
    if (token == signal::SignalChannel<signal::Empty>::kInvalidToken) {
        return GN_ERR_LIMIT_REACHED;
    }
    *out_id = pack_subscription_id(GN_SUBSCRIBE_CONFIG_RELOAD,
                                    static_cast<std::uint64_t>(token));
    return GN_OK;
}

gn_result_t unsubscribe(void* host_ctx,
                         gn_subscription_id_t id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    if (id == GN_INVALID_SUBSCRIPTION_ID) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    const auto raw_channel =
        (id & kSubChannelMask) >> kSubChannelShift;
    const auto token = token_of_id(id);

    switch (raw_channel) {
    case GN_SUBSCRIBE_CONN_STATE:
        pc->kernel->on_conn_event().unsubscribe(
            static_cast<signal::SignalChannel<ConnEvent>::Token>(token));
        return GN_OK;
    case GN_SUBSCRIBE_CONFIG_RELOAD:
        pc->kernel->on_config_reload().unsubscribe(
            static_cast<signal::SignalChannel<signal::Empty>::Token>(token));
        return GN_OK;
    case kCapabilityBlobChannel:
        return pc->kernel->capability_blob_bus().unsubscribe(token)
                   ? GN_OK
                   : GN_ERR_NOT_FOUND;
    default:
        return GN_ERR_NOT_FOUND;
    }
}

// ── Lifecycle / metrics / for_each_connection ─────────────────────

int32_t is_shutdown_requested(void* host_ctx) {
    if (!host_ctx) return 0;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return 1;
    if (!pc->plugin_anchor) return 0;
    return pc->plugin_anchor->shutdown_requested.load(
        std::memory_order_acquire) ? 1 : 0;
}

void emit_counter(void* host_ctx, const char* name) {
    if (!host_ctx || !name) return;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return;
    pc->kernel->metrics().increment(name);
}

std::uint64_t iterate_counters(void* host_ctx,
                                gn_counter_visitor_t visitor,
                                void* user_data) {
    if (!host_ctx || !visitor) return 0;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return 0;
    return pc->kernel->metrics().iterate(visitor, user_data);
}

gn_result_t for_each_connection(void* host_ctx,
                                 gn_conn_visitor_t visitor,
                                 void* user_data) {
    if (!host_ctx || !visitor) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    pc->kernel->connections().for_each(
        [visitor, user_data](const ConnectionRecord& rec,
                              const ConnectionRegistry::CounterSnapshot& /*counters*/) -> bool {
            const auto rc_opt = safe_call_value<int>(
                "for_each_connection.visitor",
                visitor, user_data,
                rec.id, rec.trust,
                rec.remote_pk.data(), rec.uri.c_str());
            return rc_opt.value_or(1) == 0;
        });
    return GN_OK;
}

gn_result_t notify_backpressure(void* host_ctx,
                                 gn_conn_id_t conn,
                                 gn_conn_event_kind_t kind,
                                 std::uint64_t pending_bytes) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    if (!link_role(pc)) return GN_ERR_NOT_IMPLEMENTED;
    if (kind != GN_CONN_EVENT_BACKPRESSURE_SOFT &&
        kind != GN_CONN_EVENT_BACKPRESSURE_CLEAR) {
        return GN_ERR_INVALID_ENVELOPE;
    }

    auto rec_for_check = pc->kernel->connections().find_by_id(conn);
    if (rec_for_check && !conn_owned_by_caller(pc, *rec_for_check)) {
        return GN_ERR_NOT_FOUND;
    }

    ConnEvent ev{};
    ev.kind          = kind;
    ev.conn          = conn;
    ev.pending_bytes = pending_bytes;
    if (rec_for_check) {
        ev.trust     = rec_for_check->trust;
        ev.remote_pk = rec_for_check->remote_pk;
    }
    pc->kernel->connections().set_pending_bytes(conn, pending_bytes);
    pc->kernel->on_conn_event().fire(ev);
    return GN_OK;
}

// ── Vtable registration ────────────────────────────────────────────

gn_result_t register_vtable(void* host_ctx,
                             gn_register_kind_t kind,
                             const gn_register_meta_t* meta,
                             const void* vtable,
                             void* self,
                             std::uint64_t* out_id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;

    switch (kind) {
    case GN_REGISTER_HANDLER:
    case GN_REGISTER_LINK:
        break;
    default:
        return GN_ERR_INVALID_ENVELOPE;
    }

    if (!meta || !meta->name || !vtable || !out_id) {
        return GN_ERR_NULL_ARG;
    }
    if (meta->api_size < sizeof(gn_register_meta_t)) {
        return GN_ERR_VERSION_MISMATCH;
    }

    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    switch (kind) {
    case GN_REGISTER_HANDLER: {
        gn_handler_id_t inner = GN_INVALID_ID;
        const std::string_view declared_namespace =
            meta->namespace_id != nullptr
                ? std::string_view{meta->namespace_id}
                : std::string_view{};
        const auto rc = pc->kernel->handlers().register_handler(
            declared_namespace,
            meta->name, meta->msg_id, meta->priority,
            static_cast<const gn_handler_vtable_t*>(vtable),
            self, &inner, pc->plugin_anchor, pc->plugin_name);
        if (rc != GN_OK) return rc;
        *out_id = pack_register_id(GN_REGISTER_HANDLER,
                                    static_cast<std::uint64_t>(inner));
        return GN_OK;
    }
    case GN_REGISTER_LINK: {
        gn_link_id_t inner = GN_INVALID_ID;
        const std::string_view declared_protocol_id =
            meta->protocol_id != nullptr
                ? std::string_view{meta->protocol_id}
                : std::string_view{};
        const auto rc = pc->kernel->links().register_link(
            meta->name,
            declared_protocol_id,
            static_cast<const gn_link_vtable_t*>(vtable),
            self, &inner, pc->plugin_anchor);
        if (rc != GN_OK) return rc;
        *out_id = pack_register_id(GN_REGISTER_LINK,
                                    static_cast<std::uint64_t>(inner));
        return GN_OK;
    }
    }
    return GN_ERR_INVALID_ENVELOPE;
}

gn_result_t unregister_vtable(void* host_ctx, std::uint64_t id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    const auto kind  = kind_of_register_id(id);
    const auto token = token_of_register_id(id);

    switch (kind) {
    case GN_REGISTER_HANDLER:
        return pc->kernel->handlers().unregister_handler(
            static_cast<gn_handler_id_t>(token));
    case GN_REGISTER_LINK:
        return pc->kernel->links().unregister_link(
            static_cast<gn_link_id_t>(token));
    }
    return GN_ERR_NOT_FOUND;
}

// ── Limits / config / log ──────────────────────────────────────────

const gn_limits_t* limits(void* host_ctx) {
    if (!host_ctx) return nullptr;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return nullptr;
    return &pc->kernel->limits();
}

gn_result_t config_get(void* host_ctx,
                        const char* key,
                        gn_config_value_type_t type,
                        std::size_t index,
                        void* out_value,
                        void** out_user_data,
                        void (**out_free)(void*, void*)) {
    if (!host_ctx || !key || !out_value) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    switch (type) {
    case GN_CONFIG_VALUE_INT64:
    case GN_CONFIG_VALUE_BOOL:
    case GN_CONFIG_VALUE_DOUBLE:
    case GN_CONFIG_VALUE_STRING:
    case GN_CONFIG_VALUE_ARRAY_SIZE:
        break;
    default:
        return GN_ERR_INVALID_ENVELOPE;
    }

    const bool is_string =
        (type == GN_CONFIG_VALUE_STRING);
    if (is_string && (!out_free || !out_user_data))  return GN_ERR_NULL_ARG;
    if (!is_string && (out_free || out_user_data))   return GN_ERR_NULL_ARG;

    const bool is_array_size =
        (type == GN_CONFIG_VALUE_ARRAY_SIZE);
    const bool is_indexable =
        (type == GN_CONFIG_VALUE_INT64) ||
        (type == GN_CONFIG_VALUE_STRING);
    if (is_array_size && index != GN_CONFIG_NO_INDEX) {
        return GN_ERR_OUT_OF_RANGE;
    }
    if (!is_indexable && !is_array_size && index != GN_CONFIG_NO_INDEX) {
        return GN_ERR_OUT_OF_RANGE;
    }

    auto& cfg = pc->kernel->config();

    switch (type) {
    case GN_CONFIG_VALUE_INT64: {
        std::int64_t v = 0;
        const auto rc = (index == GN_CONFIG_NO_INDEX)
            ? cfg.get_int64(key, v)
            : cfg.get_array_int64(key, index, v);
        if (rc != GN_OK) return rc;
        *static_cast<std::int64_t*>(out_value) = v;
        return GN_OK;
    }
    case GN_CONFIG_VALUE_BOOL: {
        bool v = false;
        const auto rc = cfg.get_bool(key, v);
        if (rc != GN_OK) return rc;
        *static_cast<std::int32_t*>(out_value) = v ? 1 : 0;
        return GN_OK;
    }
    case GN_CONFIG_VALUE_DOUBLE: {
        return cfg.get_double(key, *static_cast<double*>(out_value));
    }
    case GN_CONFIG_VALUE_STRING: {
        std::string buf;
        const auto rc = (index == GN_CONFIG_NO_INDEX)
            ? cfg.get_string(key, buf)
            : cfg.get_array_string(key, index, buf);
        if (rc != GN_OK) return rc;

        auto* heap = static_cast<char*>(std::malloc(buf.size() + 1));
        if (!heap) return GN_ERR_OUT_OF_MEMORY;
        std::memcpy(heap, buf.data(), buf.size());
        heap[buf.size()] = '\0';

        *static_cast<char**>(out_value) = heap;
        *out_user_data = nullptr;
        *out_free = +[](void* /*user_data*/, void* p) { std::free(p); };
        return GN_OK;
    }
    case GN_CONFIG_VALUE_ARRAY_SIZE: {
        std::size_t v = 0;
        const auto rc = cfg.get_array_size(key, v);
        if (rc != GN_OK) return rc;
        *static_cast<std::size_t*>(out_value) = v;
        return GN_OK;
    }
    }
    return GN_ERR_INVALID_ENVELOPE;
}

int32_t log_should_log(void* host_ctx, gn_log_level_t level) {
    if (!host_ctx) return 0;
    if (!ctx_live(static_cast<PluginContext*>(host_ctx))) [[unlikely]] return 0;
    const auto sp_lvl = map_log_level(level);
    if (sp_lvl == ::spdlog::level::off) return 0;
    return ::gn::log::kernel()->should_log(sp_lvl) ? 1 : 0;
}

void log_emit(void* host_ctx, gn_log_level_t level,
               const char* file, int32_t line, const char* msg) {
    if (!host_ctx || !msg) return;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return;

    const auto sp_lvl = map_log_level(level);
    if (sp_lvl == ::spdlog::level::off) return;
    if (!::gn::log::kernel()->should_log(sp_lvl)) return;

    const ::spdlog::source_loc loc{file ? file : "", line, ""};
    if (pc->plugin_name.empty()) {
        ::gn::log::kernel()->log(loc, sp_lvl, "{}", msg);
    } else {
        ::gn::log::kernel()->log(loc, sp_lvl,
                                "[{}] {}", pc->plugin_name, msg);
    }
}

}  // namespace gn::core::host_api_thunks
