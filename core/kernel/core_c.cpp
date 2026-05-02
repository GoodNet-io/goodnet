/// @file   core/kernel/core_c.cpp
/// @brief  Library-as-binary C ABI implementation — thin shim over
///         `gn::core::Kernel` for non-C++ hosts.
///
/// Binds every entry in `sdk/core.h` to the kernel's C++ internals.
/// The opaque handle layout lives in `core_c_internal.hpp` so the
/// fields can move freely without surface rebuild.

#include "core_c_internal.hpp"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <core/identity/node_identity.hpp>
#include <core/plugin/plugin_manifest.hpp>
#include <core/util/log.hpp>

#include <sdk/extensions/link.h>

namespace {

constexpr std::uint32_t kPackedVersion =
    (static_cast<std::uint32_t>(GN_SDK_VERSION_MAJOR) << 16) |
    (static_cast<std::uint32_t>(GN_SDK_VERSION_MINOR) << 8)  |
    static_cast<std::uint32_t>(GN_SDK_VERSION_PATCH);

inline constexpr const char kVersionString[] = "1.0.0-dev";

/// Walk the kernel through `Load → Wire → Resolve → Ready`. Every
/// transition is best-effort: an FSM that already sits past the
/// requested phase no-ops without flagging an error so concurrent
/// callers race through without contention.
void walk_to_ready(gn::core::Kernel& kernel) {
    using gn::core::Phase;
    (void)kernel.advance_to(Phase::Load);
    (void)kernel.advance_to(Phase::Wire);
    (void)kernel.advance_to(Phase::Resolve);
    (void)kernel.advance_to(Phase::Ready);
}

/// Derive scheme prefix from a URI ("tcp://1.2.3.4:9" → "tcp"). The
/// host passes NULL when it wants this auto-detection. Returns
/// empty view on URIs without `://`.
std::string_view derive_scheme(std::string_view uri) {
    auto sep = uri.find("://");
    if (sep == std::string_view::npos) return {};
    return uri.substr(0, sep);
}

}  // namespace

extern "C" {

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

gn_core_t* gn_core_create(void) {
    try {
        return new gn_core_s();
    } catch (...) {
        /// Per `safe_invoke.hpp` discipline: never let a C++ exception
        /// cross the C ABI. OOM and any other throw collapse to NULL.
        return nullptr;
    }
}

gn_core_t* gn_core_create_from_json(const char* json_str) {
    if (json_str == nullptr) return nullptr;
    auto* core = gn_core_create();
    if (core == nullptr) return nullptr;
    if (gn_core_reload_config_json(core, json_str) != GN_OK) {
        gn_core_destroy(core);
        return nullptr;
    }
    return core;
}

void gn_core_destroy(gn_core_t* core) {
    if (core == nullptr) return;

    /// Release every host-side subscription before tearing down the
    /// channels they live on. `unregister_handler` and channel
    /// `unsubscribe` are idempotent — the post-stop walk just clears
    /// the std::vector slots.
    {
        std::lock_guard lk(core->subs_mu);
        for (auto& sub : core->message_subs) {
            (void)core->kernel.handlers().unregister_handler(sub->handler_id);
        }
        for (auto& sub : core->conn_subs) {
            core->kernel.on_conn_event().unsubscribe(sub.channel_token);
        }
        core->message_subs.clear();
        core->conn_subs.clear();
    }

    /// Drain plugin manager BEFORE the kernel destructor walks the
    /// registries — same `kernel.stop() before dlclose` invariant the
    /// legacy `gn_core::~gn_core` enforced.
    core->kernel.stop();
    core->plugins.shutdown();

    {
        std::lock_guard lk(core->wait_mu);
    }
    core->wait_cv.notify_all();

    delete core;
}

gn_result_t gn_core_init(gn_core_t* core) {
    if (core == nullptr) return GN_ERR_NULL_ARG;

    bool expected = false;
    if (!core->init_done.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        return GN_ERR_INVALID_STATE;
    }

    auto identity = gn::core::identity::NodeIdentity::generate(/*expiry*/ 0);
    if (!identity.has_value()) {
        core->init_done.store(false, std::memory_order_release);
        return GN_ERR_INTEGRITY_FAILED;
    }
    const auto pk = identity->device().public_key();
    core->kernel.identities().add(pk);
    core->kernel.set_node_identity(std::move(*identity));

    core->protocol = std::make_shared<gn::plugins::gnet::GnetProtocol>();
    core->kernel.set_protocol_layer(core->protocol);

    walk_to_ready(core->kernel);
    return GN_OK;
}

gn_result_t gn_core_start(gn_core_t* core) {
    if (core == nullptr) return GN_ERR_NULL_ARG;
    walk_to_ready(core->kernel);
    (void)core->kernel.advance_to(gn::core::Phase::Running);
    return GN_OK;
}

void gn_core_stop(gn_core_t* core) {
    if (core == nullptr) return;
    core->kernel.stop();
    {
        std::lock_guard lk(core->wait_mu);
    }
    core->wait_cv.notify_all();
}

void gn_core_wait(gn_core_t* core) {
    if (core == nullptr) return;
    std::unique_lock lk(core->wait_mu);
    core->wait_cv.wait(lk, [core] {
        const auto p = core->kernel.current_phase();
        return p == gn::core::Phase::Shutdown ||
               p == gn::core::Phase::Unload;
    });
}

int gn_core_is_running(gn_core_t* core) {
    if (core == nullptr) return 0;
    return core->kernel.current_phase() == gn::core::Phase::Running ? 1 : 0;
}

gn_result_t gn_core_reload_config_json(gn_core_t* core, const char* json_str) {
    if (core == nullptr || json_str == nullptr) return GN_ERR_NULL_ARG;
    return core->kernel.reload_config(std::string_view{json_str});
}

/* ── Configuration & limits ──────────────────────────────────────────────── */

const gn_limits_t* gn_core_limits(gn_core_t* core) {
    if (core == nullptr) return nullptr;
    return &core->kernel.limits();
}

gn_result_t gn_core_set_limits(gn_core_t* core, const gn_limits_t* limits) {
    if (core == nullptr || limits == nullptr) return GN_ERR_NULL_ARG;
    if (core->init_done.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }
    core->kernel.set_limits(*limits);
    return GN_OK;
}

/* ── Identity ────────────────────────────────────────────────────────────── */

gn_result_t gn_core_get_pubkey(gn_core_t* core,
                                uint8_t out_pk[GN_PUBLIC_KEY_BYTES]) {
    if (core == nullptr || out_pk == nullptr) return GN_ERR_NULL_ARG;
    auto identity = core->kernel.node_identity();
    if (identity == nullptr) return GN_ERR_INVALID_STATE;
    const auto pk = identity->device().public_key();
    std::memcpy(out_pk, pk.data(), GN_PUBLIC_KEY_BYTES);
    return GN_OK;
}

/* ── Network ─────────────────────────────────────────────────────────────── */

gn_result_t gn_core_connect(gn_core_t* core,
                             const char* uri,
                             const char* scheme,
                             gn_conn_id_t* out_conn) {
    if (core == nullptr || uri == nullptr || out_conn == nullptr) {
        return GN_ERR_NULL_ARG;
    }
    *out_conn = GN_INVALID_ID;

    /// Either the host hands us the scheme explicitly, or we derive
    /// it from the URI prefix. An unrecognised URI without `://`
    /// surfaces as NOT_FOUND because no link could possibly match.
    std::string_view scheme_sv =
        (scheme != nullptr && *scheme != '\0')
            ? std::string_view{scheme}
            : derive_scheme(std::string_view{uri});
    if (scheme_sv.empty()) return GN_ERR_NOT_FOUND;

    /// Resolve the per-link extension (`gn.link.<scheme>`) and call
    /// its `connect` slot. Bypassing host_api here costs one
    /// `query_extension_checked` call but gives a single C ABI entry
    /// for the host without forcing it to know the extension naming.
    char ext_name[64];
    const int n = std::snprintf(ext_name, sizeof(ext_name),
                                 "gn.link.%.*s",
                                 static_cast<int>(scheme_sv.size()),
                                 scheme_sv.data());
    if (n <= 0 || static_cast<std::size_t>(n) >= sizeof(ext_name)) {
        return GN_ERR_INVALID_ENVELOPE;
    }
    const auto* ext = static_cast<const gn_link_api_t*>(
        gn_core_query_extension_checked(core, ext_name, GN_EXT_LINK_VERSION));
    if (ext == nullptr || ext->connect == nullptr) {
        return GN_ERR_NOT_FOUND;
    }
    return ext->connect(ext->ctx, uri, out_conn);
}

gn_result_t gn_core_send_to(gn_core_t* core,
                             gn_conn_id_t conn,
                             uint32_t msg_id,
                             const uint8_t* payload,
                             size_t payload_size) {
    if (core == nullptr) return GN_ERR_NULL_ARG;
    if (payload == nullptr && payload_size > 0) return GN_ERR_NULL_ARG;
    if (core->api.send == nullptr) return GN_ERR_NOT_IMPLEMENTED;
    return core->api.send(core->api.host_ctx, conn, msg_id, payload, payload_size);
}

void gn_core_broadcast(gn_core_t* core,
                        uint32_t msg_id,
                        const uint8_t* payload,
                        size_t payload_size) {
    if (core == nullptr) return;
    /// `for_each_connection` walks under per-shard read locks; pass
    /// each id into `gn_core_send_to`. Failures on individual
    /// connections do not stop the walk — the broadcast is
    /// best-effort by contract (mirrors legacy `Orchestrator::broadcast`).
    core->kernel.connections().for_each(
        [core, msg_id, payload, payload_size]
        (const gn::core::ConnectionRecord& rec) -> bool {
            (void)gn_core_send_to(core, rec.id, msg_id, payload, payload_size);
            return true;
        });
}

gn_result_t gn_core_disconnect(gn_core_t* core, gn_conn_id_t conn) {
    if (core == nullptr) return GN_ERR_NULL_ARG;
    if (core->api.disconnect == nullptr) return GN_ERR_NOT_IMPLEMENTED;
    return core->api.disconnect(core->api.host_ctx, conn);
}

/* ── Stats / introspection ───────────────────────────────────────────────── */

gn_result_t gn_core_get_stats(gn_core_t* core, gn_stats_t* out) {
    if (core == nullptr || out == nullptr) return GN_ERR_NULL_ARG;
    /// Producer must zero-init `_reserved` per `abi-evolution.md` §4.
    for (std::size_t i = 0;
         i < sizeof(out->_reserved) / sizeof(out->_reserved[0]); ++i) {
        if (out->_reserved[i] != nullptr) return GN_ERR_INVALID_ENVELOPE;
    }

    out->connections_active    = core->kernel.connections().size();
    out->handlers_registered   = core->kernel.handlers().size();
    out->links_registered      = core->kernel.links().size();
    out->extensions_registered = core->kernel.extensions().size();
    out->bytes_in              = 0;
    out->bytes_out             = 0;
    out->frames_in             = 0;
    out->frames_out            = 0;
    core->kernel.connections().for_each(
        [out](const gn::core::ConnectionRecord& rec) -> bool {
            out->bytes_in   += rec.bytes_in;
            out->bytes_out  += rec.bytes_out;
            out->frames_in  += rec.frames_in;
            out->frames_out += rec.frames_out;
            return true;
        });
    out->plugin_dlclose_leaks = core->plugins.leaked_handles();
    return GN_OK;
}

size_t gn_core_connection_count(gn_core_t* core) {
    if (core == nullptr) return 0;
    return core->kernel.connections().size();
}

size_t gn_core_handler_count(gn_core_t* core) {
    if (core == nullptr) return 0;
    return core->kernel.handlers().size();
}

size_t gn_core_link_count(gn_core_t* core) {
    if (core == nullptr) return 0;
    return core->kernel.links().size();
}

/* ── Subscriptions ───────────────────────────────────────────────────────── */

namespace {

/// Wrapper handler vtable that bridges the kernel's
/// `gn_handler_vtable_t::handle_message` callsite to the application's
/// `gn_message_cb_t`. Each `gn_core_subscribe` call owns one
/// `MessageSub` instance — the vtable's `self` is the sub pointer.
gn_propagation_t message_sub_handle(void* self, const gn_message_t* env) {
    auto* sub = static_cast<gn_core_s::MessageSub*>(self);
    if (sub != nullptr && sub->cb != nullptr && env != nullptr) {
        /// Connection id is not on the envelope; we do not surface it
        /// to the C callback today. A future minor adds an envelope
        /// `_reserved` slot for it (host-api.md §11 evolution path).
        sub->cb(sub->user, /*conn=*/GN_INVALID_ID, env->msg_id,
                env->payload, env->payload_size);
    }
    return GN_PROPAGATION_CONTINUE;
}

const gn_handler_vtable_t kMessageSubVtable = []() {
    gn_handler_vtable_t v{};
    v.api_size       = sizeof(gn_handler_vtable_t);
    v.handle_message = &message_sub_handle;
    return v;
}();

}  // namespace

uint64_t gn_core_subscribe(gn_core_t* core,
                            uint32_t msg_id,
                            gn_message_cb_t cb,
                            void* user_data) {
    if (core == nullptr || cb == nullptr) return 0;

    auto sub = std::make_unique<gn_core_s::MessageSub>();
    sub->cb     = cb;
    sub->user   = user_data;
    sub->msg_id = msg_id;
    sub->token  = core->next_token.fetch_add(1, std::memory_order_relaxed);

    gn_handler_id_t hid = GN_INVALID_ID;
    const gn_result_t rc = core->kernel.handlers().register_handler(
        /*protocol_id*/ "gnet-v1",
        /*msg_id*/      msg_id,
        /*priority*/    128,
        &kMessageSubVtable,
        /*self*/        sub.get(),
        &hid,
        /*lifetime_anchor*/ {});
    if (rc != GN_OK || hid == GN_INVALID_ID) return 0;
    sub->handler_id = hid;

    const std::uint64_t token = sub->token;
    {
        std::lock_guard lk(core->subs_mu);
        core->message_subs.push_back(std::move(sub));
    }
    return token;
}

void gn_core_unsubscribe(gn_core_t* core, uint64_t token) {
    if (core == nullptr || token == 0) return;
    std::unique_ptr<gn_core_s::MessageSub> erased;
    {
        std::lock_guard lk(core->subs_mu);
        auto it = std::find_if(
            core->message_subs.begin(), core->message_subs.end(),
            [token](const auto& s) { return s->token == token; });
        if (it == core->message_subs.end()) return;
        erased = std::move(*it);
        core->message_subs.erase(it);
    }
    /// Unregister AFTER releasing the subs mutex so a callback already
    /// in flight does not deadlock on the same mutex while the
    /// HandlerRegistry waits to retire the entry.
    (void)core->kernel.handlers().unregister_handler(erased->handler_id);
}

uint64_t gn_core_on_conn_state(gn_core_t* core,
                                gn_conn_event_cb_t cb,
                                void* user_data) {
    if (core == nullptr || cb == nullptr) return 0;
    const std::uint64_t token =
        core->next_token.fetch_add(1, std::memory_order_relaxed);

    /// Wrap the C callback in a std::function the SignalChannel keeps
    /// alive for the duration of the subscription.
    auto channel_token = core->kernel.on_conn_event().subscribe(
        [cb, user_data](const gn::core::ConnEvent& ev) {
            /// Translate kernel-internal `ConnEvent` into the
            /// public `gn_conn_event_t` shape. Field names align by
            /// design (mirror struct).
            gn_conn_event_t out{};
            out.kind         = ev.kind;
            out.conn         = ev.conn;
            out.trust        = ev.trust;
            std::memcpy(out.remote_pk, ev.remote_pk.data(), GN_PUBLIC_KEY_BYTES);
            out.pending_bytes = ev.pending_bytes;
            cb(user_data, &out);
        });

    {
        std::lock_guard lk(core->subs_mu);
        core->conn_subs.push_back({token, channel_token});
    }
    return token;
}

void gn_core_off_conn_state(gn_core_t* core, uint64_t token) {
    if (core == nullptr || token == 0) return;
    std::uint64_t signal_token = 0;
    bool found = false;
    {
        std::lock_guard lk(core->subs_mu);
        auto it = std::find_if(core->conn_subs.begin(), core->conn_subs.end(),
                                [token](const auto& s) { return s.token == token; });
        if (it == core->conn_subs.end()) return;
        signal_token = it->channel_token;
        found        = true;
        core->conn_subs.erase(it);
    }
    if (found) {
        core->kernel.on_conn_event().unsubscribe(signal_token);
    }
}

/* ── Plugin lifecycle ────────────────────────────────────────────────────── */

gn_result_t gn_core_load_plugin(gn_core_t* core,
                                 const char* so_path,
                                 const uint8_t expected_sha256[32]) {
    if (core == nullptr || so_path == nullptr || expected_sha256 == nullptr) {
        return GN_ERR_NULL_ARG;
    }

    /// Build a single-entry manifest so the loader runs in production
    /// mode (manifest_required = true) even for one .so. Mismatched
    /// hash → `GN_ERR_INTEGRITY_FAILED` from `PluginManager::load`.
    gn::core::PluginManifest manifest;
    gn::core::PluginHash sha{};
    std::memcpy(sha.data(), expected_sha256, 32);
    manifest.add_entry(std::string(so_path), sha);

    core->plugins.set_manifest(std::move(manifest));
    core->plugins.set_manifest_required(true);

    std::array<std::string, 1> paths{std::string(so_path)};
    std::string diagnostic;
    const gn_result_t rc = core->plugins.load(
        std::span<const std::string>{paths}, &diagnostic);
    if (rc != GN_OK && !diagnostic.empty()) {
        /// Surface the loader's diagnostic through the kernel's
        /// spdlog instance directly — the embedding context's
        /// host_api log slot would re-route through `safe_invoke`,
        /// adding latency for an already-failing path.
        gn::log::warn("core_c: load_plugin failed: {}", diagnostic);
    }
    return rc;
}

gn_result_t gn_core_unload_plugin(gn_core_t* core, const char* name) {
    if (core == nullptr || name == nullptr) return GN_ERR_NULL_ARG;
    /// PluginManager today only exposes `shutdown()` (full teardown),
    /// not per-name unload. v1.x roadmap: per-name reload (host-api.md
    /// §10 hot-reload section). For now the per-name path returns
    /// `NOT_IMPLEMENTED`; hosts that need full-teardown go through
    /// `gn_core_destroy` + new `gn_core_create`.
    (void)name;
    (void)core;
    return GN_ERR_NOT_IMPLEMENTED;
}

/* ── Provider registration ───────────────────────────────────────────────── */

gn_result_t gn_core_register_security(
    gn_core_t* core,
    const gn_register_meta_t* meta,
    const gn_security_provider_vtable_t* vtable,
    void* self) {
    if (core == nullptr || meta == nullptr || meta->name == nullptr ||
        vtable == nullptr) {
        return GN_ERR_NULL_ARG;
    }
    /// `register_vtable` covers HANDLER and LINK kinds; security
    /// providers go through their own slot per host_api.h §SECURITY.
    /// The `meta->name` doubles as `provider_id` so the registration
    /// shape mirrors HANDLER / LINK on the C ABI surface even though
    /// the backing kernel call differs.
    if (core->api.register_security == nullptr) return GN_ERR_NOT_IMPLEMENTED;
    return core->api.register_security(
        core->api.host_ctx, meta->name, vtable, self);
}

gn_result_t gn_core_register_protocol(
    gn_core_t* core,
    const gn_protocol_layer_vtable_t* vtable,
    void* self) {
    if (core == nullptr || vtable == nullptr) return GN_ERR_NULL_ARG;
    /// Protocol layer is not a vtable kind on `register_vtable` — the
    /// kernel statically links a single layer. The C ABI entry is
    /// reserved for future hot-swap; for now hosts that need a
    /// non-default protocol register their layer through the C++ side
    /// before init. Returns NOT_IMPLEMENTED until the kernel exposes
    /// a runtime swap.
    (void)self;
    return GN_ERR_NOT_IMPLEMENTED;
}

gn_handler_id_t gn_core_register_handler(
    gn_core_t* core,
    const gn_register_meta_t* meta,
    const gn_handler_vtable_t* vtable,
    void* self) {
    if (core == nullptr || meta == nullptr || vtable == nullptr) {
        return GN_INVALID_HANDLER_ID;
    }
    if (core->api.register_vtable == nullptr) return GN_INVALID_HANDLER_ID;
    gn_handler_id_t out = GN_INVALID_HANDLER_ID;
    const gn_result_t rc = core->api.register_vtable(
        core->api.host_ctx, GN_REGISTER_HANDLER,
        meta, vtable, self, &out);
    return rc == GN_OK ? out : GN_INVALID_HANDLER_ID;
}

gn_link_id_t gn_core_register_link(
    gn_core_t* core,
    const gn_register_meta_t* meta,
    const gn_link_vtable_t* vtable,
    void* self) {
    if (core == nullptr || meta == nullptr || vtable == nullptr) {
        return GN_INVALID_LINK_ID;
    }
    if (core->api.register_vtable == nullptr) return GN_INVALID_LINK_ID;
    gn_link_id_t out = GN_INVALID_LINK_ID;
    const gn_result_t rc = core->api.register_vtable(
        core->api.host_ctx, GN_REGISTER_LINK,
        meta, vtable, self, &out);
    return rc == GN_OK ? out : GN_INVALID_LINK_ID;
}

/* ── Extensions ──────────────────────────────────────────────────────────── */

const void* gn_core_query_extension_checked(
    gn_core_t* core,
    const char* name,
    uint32_t required_version) {
    if (core == nullptr || name == nullptr) return nullptr;
    if (core->api.query_extension_checked == nullptr) return nullptr;
    const void* out_vt = nullptr;
    const gn_result_t rc = core->api.query_extension_checked(
        core->api.host_ctx, name, required_version, &out_vt);
    return rc == GN_OK ? out_vt : nullptr;
}

gn_result_t gn_core_register_extension(
    gn_core_t* core,
    const char* name,
    uint32_t version,
    const void* vtable) {
    if (core == nullptr || name == nullptr || vtable == nullptr) {
        return GN_ERR_NULL_ARG;
    }
    if (core->api.register_extension == nullptr) return GN_ERR_NOT_IMPLEMENTED;
    return core->api.register_extension(
        core->api.host_ctx, name, version, vtable);
}

gn_result_t gn_core_unregister_extension(gn_core_t* core, const char* name) {
    if (core == nullptr || name == nullptr) return GN_ERR_NULL_ARG;
    if (core->api.unregister_extension == nullptr) return GN_ERR_NOT_IMPLEMENTED;
    return core->api.unregister_extension(core->api.host_ctx, name);
}

/* ── host_api accessor ───────────────────────────────────────────────────── */

const host_api_t* gn_core_host_api(gn_core_t* core) {
    if (core == nullptr) return nullptr;
    return &core->api;
}

/* ── Version ─────────────────────────────────────────────────────────────── */

const char* gn_version(void) {
    return kVersionString;
}

uint32_t gn_version_packed(void) {
    return kPackedVersion;
}

}  // extern "C"
