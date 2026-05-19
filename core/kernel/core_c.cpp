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
#include <filesystem>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <core/identity/node_identity.hpp>
#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/plugin_anchor.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/plugin/plugin_manager.hpp>
#include <core/plugin/plugin_manifest.hpp>
#include <core/plugin/plugin_runtime.hpp>
#include <core/util/log.hpp>

#include <core/identity/identity_plugin_signer.hpp>

#include <sdk/extensions/identity.h>
#include <sdk/extensions/link.h>
#include <sdk/plugin_runtime.h>

namespace {

/// Packed kernel version in the canonical layout exposed by
/// `gn_version_pack` (major:8 << 24 | minor:8 << 16 | patch:16).
/// `gn_version_packed()` returns this value to plugins; both sides
/// must agree on the same bit layout so ordered comparison works.
constexpr std::uint32_t kPackedVersion =
    gn_version_pack(static_cast<std::uint32_t>(GN_SDK_VERSION_MAJOR),
                    static_cast<std::uint32_t>(GN_SDK_VERSION_MINOR),
                    static_cast<std::uint32_t>(GN_SDK_VERSION_PATCH));

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

gn_result_t gn_core_install_identity_from_file(gn_core_t*  core,
                                               const char* path) {
    if (core == nullptr || path == nullptr) return GN_ERR_NULL_ARG;

    // Same `init_done` gate `gn_core_init` uses — the C ABI
    // contract is "install before init". Calling on an already-
    // initialised kernel is the operator's bug; surface it as
    // INVALID_STATE rather than racing the protocol-layer
    // registration.
    if (core->init_done.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }
    if (core->kernel.has_node_identity()) {
        return GN_ERR_INVALID_STATE;
    }

    auto loaded = gn::core::identity::NodeIdentity::load_from_file(path);
    if (!loaded) {
        // `NodeIdentity::load_from_file` returns a tl::expected
        // with a `Error` describing the failure. We don't have
        // a stable enum mapping yet; surface NOT_FOUND when the
        // file is plain missing, INTEGRITY_FAILED otherwise so
        // the operator can distinguish "no key yet" from "key
        // tampered or unreadable".
        std::error_code ec;
        if (!std::filesystem::exists(path, ec)) {
            return GN_ERR_NOT_FOUND;
        }
        return GN_ERR_INTEGRITY_FAILED;
    }

    const auto pk = loaded->device().public_key();
    core->kernel.identities().add(pk);
    core->kernel.set_node_identity(std::move(*loaded));
    return GN_OK;
}

gn_result_t gn_core_install_identity_from_provider(
    gn_core_t* core, const char* extension_id, const char* key_label) {

    if (core == nullptr) return GN_ERR_NULL_ARG;
    if (extension_id == nullptr || *extension_id == '\0') return GN_ERR_NULL_ARG;
    if (key_label == nullptr) return GN_ERR_NULL_ARG;

    /// Same pre-init gate `gn_core_install_identity_from_file` uses —
    /// the install has to land before `gn_core_init` runs the
    /// fresh-keypair mint. Mutually exclusive with the file path: a
    /// kernel that already carries an installed identity rejects a
    /// second install so operators don't accidentally swap secrets
    /// mid-startup.
    if (core->init_done.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }
    if (core->kernel.has_node_identity()) {
        return GN_ERR_INVALID_STATE;
    }

    /// Look up the extension by id under the canonical identity-signer
    /// version pin from `sdk/extensions/identity.h`. The kernel
    /// requires the registered major to match exactly and the minor
    /// to be at least the pinned one (`abi-evolution.en.md` §2);
    /// older plugins surface as `GN_ERR_VERSION_MISMATCH` here.
    const void* vtable_raw = nullptr;
    const auto query_rc = core->kernel.extensions().query_extension_checked(
        extension_id, GN_EXT_IDENTITY_SIGNER_VERSION, &vtable_raw);
    if (query_rc != GN_OK) {
        return query_rc;
    }
    if (vtable_raw == nullptr) return GN_ERR_NOT_FOUND;

    const auto* vtable =
        static_cast<const gn_identity_signer_vtable_t*>(vtable_raw);

    /// `api_size` minimum: producer struct must extend at least
    /// through the `sign` thunk so both thunks are addressable. A
    /// plugin built against a future SDK that appended more thunks
    /// is still accepted — the kernel only uses the slots it knows.
    constexpr std::size_t required_api_size =
        offsetof(gn_identity_signer_vtable_t, sign) +
        sizeof(static_cast<gn_identity_signer_vtable_t*>(nullptr)->sign);
    if (vtable->api_size < required_api_size) {
        return GN_ERR_VERSION_MISMATCH;
    }

    /// `ctx` passed to plugin thunks is the vtable pointer itself —
    /// plugins that need self-state embed the vtable as the first
    /// member of a wrapper struct so `(void*)ctx == &wrapper` lets
    /// them recover their state by cast. Plugins that don't need any
    /// state simply ignore the argument. The kernel never
    /// dereferences `ctx` directly.
    void* const ctx =
        const_cast<void*>(static_cast<const void*>(vtable));

    auto signer = std::make_unique<gn::core::identity::IdentityPluginSigner>(
        vtable, ctx, std::string{key_label});

    /// `NodeIdentity::from_signer` runs the eager pubkey fetch
    /// (plugin populates the user public key once and the kernel
    /// caches it) plus the attestation signing pass through the
    /// plugin, so a misbehaving provider surfaces as a deterministic
    /// install-time failure rather than a runtime crash mid-session.
    auto identity = gn::core::identity::NodeIdentity::from_signer(
        std::move(signer), /*expiry*/ 0);
    if (!identity) {
        const auto err = identity.error().code;
        /// Bubble up the precise diagnostic where possible —
        /// `GN_ERR_NOT_IMPLEMENTED` from a vtable missing a thunk,
        /// `GN_ERR_NULL_ARG` from a NULL output, etc. — and fall back
        /// to `GN_ERR_INTEGRITY_FAILED` only for unexpected paths.
        if (err != GN_OK) return err;
        return GN_ERR_INTEGRITY_FAILED;
    }

    const auto device_pk = identity->device().public_key();
    core->kernel.identities().add(device_pk);
    core->kernel.set_node_identity(std::move(*identity));
    return GN_OK;
}

gn_result_t gn_core_init(gn_core_t* core) {
    if (core == nullptr) return GN_ERR_NULL_ARG;

    bool expected = false;
    if (!core->init_done.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        return GN_ERR_INVALID_STATE;
    }

    // Skip the fresh-keypair mint when the host already injected
    // a NodeIdentity through `gn_core_install_identity_from_file`.
    // Production hosts that keep one identity per system (chat
    // clients, operator daemons) want their persisted key to
    // outlive `gn_core_init`; the throw-away mint is reserved for
    // ad-hoc CLIs that don't carry state across runs.
    if (!core->kernel.has_node_identity()) {
        auto identity = gn::core::identity::NodeIdentity::generate(/*expiry*/ 0);
        if (!identity.has_value()) {
            core->init_done.store(false, std::memory_order_release);
            return GN_ERR_INTEGRITY_FAILED;
        }
        const auto pk = identity->device().public_key();
        core->kernel.identities().add(pk);
        core->kernel.set_node_identity(std::move(*identity));
    }

    /// Protocol layers register through `gn_core_register_protocol`
    /// (C ABI hosts) or `kernel.protocol_layers().register_layer(...)`
    /// (in-tree C++ hosts). `gn_core_init` does NOT auto-register the
    /// gnet layer any more — `core/` includes nothing from `plugins/`
    /// per `abi-evolution.en.md` §3, and the host program owns the
    /// decision of which protocols ship alongside its embedding.

    walk_to_ready(core->kernel);

#ifdef GOODNET_STATIC_PLUGINS
    // Static-linkage build: every bundled plugin's entry symbols
    // ship inside the kernel binary (suffix-renamed per
    // `sdk/plugin.h` macros) and `gn_plugin_static_registry[]`
    // carries their addresses. Walk the registry now so embedded
    // hosts (Solas, in-process operator UIs) don't have to call
    // `PluginManager::load_static` themselves — the dynamic-load
    // path in `gn_core_load_plugin` stays available for hosts that
    // do their own composition.
    {
        std::string diag;
        if (const auto rc = core->plugins.load_static(&diag);
            rc != GN_OK) {
            // Don't roll back `init_done` — the kernel is otherwise
            // healthy and the host might recover by registering
            // providers in-process; just surface the diagnostic on
            // stderr the same way `goodnetd run` does.
            (void)std::fprintf(stderr,
                "gn_core_init: static plugin load failed — %s\n",
                diag.c_str());
        }
    }
#endif

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

gn_result_t gn_core_listen(gn_core_t* core, const char* uri) {
    if (core == nullptr || uri == nullptr) {
        return GN_ERR_NULL_ARG;
    }

    /// Derive scheme from the URI prefix. The connect-side accepts
    /// an explicit override; listen has no such parameter today —
    /// every host call site passes a canonical `<scheme>://...`
    /// URI, and adding a second parameter would diverge from
    /// `gn_core_connect`'s NULL-derive-from-uri default without a
    /// concrete need. If a future link uses a non-prefixed scheme
    /// the signature can grow `gn_core_listen_ex(core, uri, scheme)`
    /// alongside this entry without breaking the additive contract.
    const std::string_view scheme_sv =
        derive_scheme(std::string_view{uri});
    if (scheme_sv.empty()) return GN_ERR_NOT_FOUND;

    /// Resolve through the kernel link registry rather than the
    /// `gn.link.<scheme>` extension's `listen` slot — the latter
    /// is the L2 composer entry and returns `GN_ERR_NOT_IMPLEMENTED`
    /// on baseline links (TCP, UDP). The registry's vtable
    /// `listen` is the kernel-driven path the link plugin's
    /// `Class::listen` implements; accepted conns surface through
    /// the link's `notify_connect` calls, which the kernel forwards
    /// onto the conn-event channel `gn_core_on_conn_state`
    /// subscribers see.
    auto entry = core->kernel.links().find_by_scheme(scheme_sv);
    if (!entry.has_value() ||
        entry->vtable == nullptr ||
        entry->vtable->listen == nullptr) {
        return GN_ERR_NOT_FOUND;
    }
    return entry->vtable->listen(entry->self, uri);
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
        (const gn::core::ConnectionRecord& rec,
         const gn::core::ConnectionRegistry::CounterSnapshot& /*counters*/) -> bool {
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
    /// Producer must zero-init `_reserved` per `abi-evolution.en.md` §4.
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
    /// Counters live on the per-id `AtomicCounters` slot, not on
    /// the record itself; `for_each` snapshots them under the same
    /// shard lock that publishes the record, so the accumulator
    /// observes a coherent (record, counters) pair without a
    /// second `shared_mutex` acquire (which would be UB per
    /// `std::shared_mutex` non-recursion).
    core->kernel.connections().for_each(
        [out](const gn::core::ConnectionRecord& /*rec*/,
              const gn::core::ConnectionRegistry::CounterSnapshot& c) -> bool {
            out->bytes_in   += c.bytes_in;
            out->bytes_out  += c.bytes_out;
            out->frames_in  += c.frames_in;
            out->frames_out += c.frames_out;
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
        /// `_reserved` slot for it (host-api.en.md §11 evolution path).
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
        /*protocol_id*/ gn::core::kDefaultProtocolId,
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

gn_result_t gn_core_load_plugins_batch(gn_core_t* core,
                                        const char* const* so_paths,
                                        const uint8_t* expected_sha256s,
                                        size_t count) {
    if (core == nullptr) return GN_ERR_NULL_ARG;
    if (count == 0) return GN_OK;
    if (so_paths == nullptr || expected_sha256s == nullptr) {
        return GN_ERR_NULL_ARG;
    }

    /// Build a single manifest containing every requested entry, then
    /// hand the full path list to `PluginManager::load` in one call.
    /// Mirrors what `gn_core_load_plugin` does for a one-shot load,
    /// but lets a non-C++ host populate the kernel with several
    /// plugins (security + link + handler) without the
    /// PluginManager-already-active gate firing on the second call.
    gn::core::PluginManifest manifest;
    std::vector<std::string> paths;
    paths.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        if (so_paths[i] == nullptr) return GN_ERR_NULL_ARG;
        gn::core::PluginHash sha{};
        std::memcpy(sha.data(), expected_sha256s + i * 32, 32);
        manifest.add_entry(std::string(so_paths[i]), sha);
        paths.emplace_back(so_paths[i]);
    }

    core->plugins.set_manifest(std::move(manifest));
    core->plugins.set_manifest_required(true);

    std::string diagnostic;
    const gn_result_t rc = core->plugins.load(
        std::span<const std::string>{paths}, &diagnostic);
    if (rc != GN_OK && !diagnostic.empty()) {
        gn::log::warn("core_c: load_plugins_batch failed: {}", diagnostic);
    }
    return rc;
}

gn_result_t gn_core_unload_plugin(gn_core_t* core, const char* name) {
    if (core == nullptr || name == nullptr) return GN_ERR_NULL_ARG;
    /// Per-name unload walks the same `unregister → drain → shutdown
    /// → close` chain `gn_core_destroy` runs, but limited to the one
    /// matching instance. Quiescence semantics match the full-
    /// teardown path: the kernel waits up to
    /// `PluginManager::quiescence_timeout()` for outstanding dispatch
    /// snapshots to drop their `lifetime_anchor` copies before
    /// closing the `.so`. Unknown names report `GN_ERR_NOT_FOUND`;
    /// the call is idempotent past that point.
    return core->plugins.unload(std::string_view{name});
}

/* ── External plugin runtime adapter ─────────────────────────────────────── */

namespace {

/// Bridge between the kernel-private `IPluginRuntime` C++ interface
/// and the public C-ABI `gn_plugin_runtime_vtable_t` declared in
/// `sdk/plugin_runtime.h`. A host that wants to load plugins under a
/// non-built-in kind (Wasm, JVM bridge, sandbox proxy) implements the
/// C vtable; `gn_core_register_runtime` constructs one of these
/// adapters, drives the vtable's runtime-level `init` thunk, and
/// hands the adapter to `PluginManager::register_runtime`.
///
/// Lifecycle mapping — see `sdk/plugin_runtime.h` for the
/// design rationale. The C ABI collapses the C++ interface's six
/// lifecycle methods to four because a non-`dlopen` runtime has no
/// meaningful distinction between «open the artefact» and «activate
/// its handlers»:
///
///   IPluginRuntime::load           → vtable `register_plugin` thunk
///   IPluginRuntime::init           → no-op (folded into load)
///   IPluginRuntime::register_plugin→ no-op (folded into load)
///   IPluginRuntime::unregister     → vtable `unregister` thunk
///   IPluginRuntime::shutdown       → no-op (folded into unregister)
///   IPluginRuntime::close          → no-op
///
/// The vtable's runtime-level `init` / `shutdown` thunks bracket the
/// adapter's own lifetime (init runs from the adapter ctor, shutdown
/// from the dtor).
class CAbiRuntime final : public gn::core::IPluginRuntime {
public:
    CAbiRuntime(std::string                       kind,
                const gn_plugin_runtime_vtable_t& vtable,
                void*                             ctx) noexcept
        : kind_(std::move(kind)),
          vtable_(vtable),
          ctx_(ctx) {}

    /// The adapter dtor fires the runtime-level shutdown thunk
    /// exactly when the host's `init` had returned GN_OK. The adapter
    /// is owned by `PluginManager::runtimes_` (a `std::map` of
    /// `unique_ptr<IPluginRuntime>`), so the dtor runs when
    /// `PluginManager::~PluginManager` drops the runtime registry —
    /// after every instance has been torn down. The `init_succeeded_`
    /// gate skips the `shutdown` thunk when the runtime was dropped
    /// because its own `init` failed; the host did not get a paired
    /// init, so the kernel does not fire an unpaired shutdown.
    ~CAbiRuntime() override {
        if (init_succeeded_ && vtable_.shutdown != nullptr) {
            (void)vtable_.shutdown(ctx_);
        }
    }

    CAbiRuntime(const CAbiRuntime&)            = delete;
    CAbiRuntime& operator=(const CAbiRuntime&) = delete;

    /// Dispatch the vtable's runtime-level `init` thunk. Caller is
    /// `gn_core_register_runtime`; a non-`GN_OK` return rolls back
    /// the registration (the adapter is dropped before the
    /// PluginManager sees it; `init_succeeded_` stays false so the
    /// dtor skips the unpaired `shutdown` thunk).
    [[nodiscard]] gn_result_t dispatch_init() noexcept {
        if (vtable_.init == nullptr) {
            init_succeeded_ = true;
            return GN_OK;
        }
        const auto rc = vtable_.init(ctx_);
        if (rc == GN_OK) init_succeeded_ = true;
        return rc;
    }

    gn_result_t load(const std::string&                       path,
                      const gn::core::PluginLoadContext&       ctx,
                      gn::core::PluginInstance&                out,
                      std::string&                             diag) override {
        if (ctx.kernel == nullptr) {
            diag = "c-abi runtime requires kernel context";
            return GN_ERR_NULL_ARG;
        }
        if (vtable_.register_plugin == nullptr) {
            diag = "c-abi runtime '" + kind_ +
                   "' has no register_plugin thunk";
            return GN_ERR_NOT_IMPLEMENTED;
        }

        /// The descriptor's `plugin_name` doubles as the foreign
        /// runtime's `entry_name`. The manifest entry's path is the
        /// only artefact reference the kernel has, so the C-side
        /// runtime must derive both the human-readable name and the
        /// resource locator from it. The plugin name defaults to the
        /// path with the `.so`-style suffix trimmed; downstream the
        /// foreign runtime can override by writing its own descriptor
        /// once a richer manifest schema lands.
        out.path = path;
        std::string plugin_name = path;
        if (auto slash = plugin_name.find_last_of('/');
            slash != std::string::npos) {
            plugin_name.erase(0, slash + 1);
        }
        if (auto dot = plugin_name.rfind('.');
            dot != std::string::npos && dot > 0) {
            plugin_name.erase(dot);
        }
        out.descriptor.plugin_name = std::move(plugin_name);

        gn_plugin_instance_t instance = GN_PLUGIN_INSTANCE_INVALID;
        const auto rc = vtable_.register_plugin(
            ctx_, out.descriptor.plugin_name.c_str(),
            path.c_str(), &instance);
        if (rc != GN_OK) {
            diag = "c-abi runtime '" + kind_ +
                   "' register_plugin returned ";
            diag += gn_strerror(rc);
            diag += " for ";
            diag += path;
            return rc;
        }
        if (instance == GN_PLUGIN_INSTANCE_INVALID) {
            diag = "c-abi runtime '" + kind_ +
                   "' returned GN_OK but did not mint a handle for ";
            diag += path;
            return GN_ERR_INTERNAL;
        }

        out.ctx = std::make_unique<gn::core::PluginContext>();
        out.ctx->plugin_name   = out.descriptor.plugin_name;
        out.ctx->kernel        = ctx.kernel;
        out.ctx->plugin_anchor = std::make_shared<gn::core::PluginAnchor>();
        out.api      = gn::core::build_host_api(*out.ctx);
        out.runtime  = this;
        /// Smuggle the foreign instance handle through `PluginInstance::self`
        /// — the slot is otherwise reserved for the plugin's opaque
        /// state pointer (`gn_plugin_init`'s `**self_out`), and our
        /// foreign runtime has neither. Cast goes through `uintptr_t`
        /// so the round-trip is well-defined across 32/64-bit hosts.
        out.self     = reinterpret_cast<void*>(
            static_cast<std::uintptr_t>(instance));
        out.registered = false;
        return GN_OK;
    }

    gn_result_t init(gn::core::PluginInstance&) override {
        /// The C ABI vtable's `register_plugin` thunk performs both
        /// "open the artefact" and "run its init" — there is no
        /// separate per-plugin init step at this layer. Returning
        /// GN_OK lets PluginManager's two-phase activation walk
        /// straight to register_one.
        return GN_OK;
    }

    gn_result_t register_plugin(gn::core::PluginInstance&) override {
        /// Same rationale as `init`: the foreign runtime registered
        /// the plugin during the load thunk.
        return GN_OK;
    }

    void unregister(gn::core::PluginInstance& inst) override {
        if (vtable_.unregister == nullptr) return;
        const auto handle = static_cast<gn_plugin_instance_t>(
            reinterpret_cast<std::uintptr_t>(inst.self));
        if (handle == GN_PLUGIN_INSTANCE_INVALID) return;
        (void)vtable_.unregister(ctx_, handle);
        /// Stamp the handle out so a second unregister (idempotent
        /// teardown chain) is a true no-op rather than a stale
        /// dispatch with a recycled handle.
        inst.self = nullptr;
    }

    void shutdown(gn::core::PluginInstance&) override {
        /// Folded into `unregister` for the C ABI.
    }

    void close(gn::core::PluginInstance& /*inst*/, bool /*drained*/) override {
        /// No kernel-side load state to release — the foreign runtime
        /// owns its own resources and dropped them in `unregister`.
    }

    [[nodiscard]] std::string_view name() const noexcept override {
        return kind_;
    }

private:
    std::string                       kind_;
    gn_plugin_runtime_vtable_t        vtable_;
    void*                             ctx_;
    /// Flipped to true once the host's `init` thunk returned GN_OK
    /// (or was NULL). The dtor consults the flag to decide whether
    /// to fire the paired `shutdown` thunk — an unpaired shutdown on
    /// a half-constructed runtime would surprise the host with a
    /// teardown it never set up.
    bool                              init_succeeded_{false};
};

/// Reserved kinds — the kernel ships built-in runtimes for these and
/// `PluginManager::register_runtime` would reject the second
/// `emplace`. We catch the case earlier with a friendlier diagnostic
/// so downstream hosts see `LIMIT_REACHED` from the C ABI rather than
/// finding out at first-load time.
constexpr std::string_view kReservedKinds[] = {"static", "dynamic", "remote"};

}  // namespace

gn_result_t gn_core_register_runtime(
    gn_core_t*                              core,
    const char*                             kind,
    const gn_plugin_runtime_vtable_t*       vtable,
    void*                                   ctx) {
    if (core == nullptr || kind == nullptr || *kind == '\0' ||
        vtable == nullptr) {
        return GN_ERR_NULL_ARG;
    }

    /// `api_size` gate per `abi-evolution.en.md` §3a: the producer-side
    /// size must cover at least every thunk the kernel reads. Smaller
    /// means the vtable is older than this kernel; reject up front
    /// rather than dereference a fragment.
    if (vtable->api_size < GN_PLUGIN_RUNTIME_VTABLE_MIN_SIZE) {
        return GN_ERR_VERSION_MISMATCH;
    }

    /// Reserved-kind shortcut. `PluginManager::register_runtime` will
    /// also reject these — they are populated by the ctor — but
    /// catching here keeps the diagnostic uniform across hosts that
    /// inspect the error code without consulting the manager.
    const std::string_view kind_sv{kind};
    for (const auto reserved : kReservedKinds) {
        if (kind_sv == reserved) return GN_ERR_LIMIT_REACHED;
    }

    /// Duplicate-key check BEFORE firing the `init` thunk. A
    /// duplicate registration must not invoke the host's
    /// runtime-level init — the host would see a paired init/shutdown
    /// pair against a slot it does not own. The lookup is read-only
    /// and races with concurrent registrations, but the manager's
    /// later `emplace` is the source of truth; this is a friendliness
    /// fast-path, not a TOCTOU guard.
    if (core->plugins.runtime_for(kind_sv) != nullptr) {
        return GN_ERR_LIMIT_REACHED;
    }

    /// Construct the adapter on the heap so we can hand a
    /// `unique_ptr<IPluginRuntime>` to the manager. The adapter
    /// captures `vtable` by value and `ctx` by raw pointer; the host
    /// must keep `ctx`'s storage live for the kernel's lifetime.
    auto adapter = std::make_unique<CAbiRuntime>(
        std::string(kind), *vtable, ctx);

    /// Fire the runtime-level `init` thunk now, before handing off to
    /// the manager. A failing init rolls back the registration — the
    /// adapter destructor would call the `shutdown` thunk otherwise,
    /// even though the host's `init` did not succeed. Dropping the
    /// `unique_ptr` here keeps that contract: the dtor still runs but
    /// the `shutdown` thunk only fires when `init` returned GN_OK and
    /// the manager actually owns the adapter.
    if (const auto rc = adapter->dispatch_init(); rc != GN_OK) {
        return rc;
    }

    /// Hand off to the manager. The manager treats the runtime as
    /// owned for the rest of its life (drop at PluginManager dtor).
    /// A duplicate slipping past the pre-check (concurrent host
    /// register from another thread) still surfaces as
    /// `GN_ERR_LIMIT_REACHED`; the adapter dtor then fires the
    /// paired shutdown because init had already succeeded.
    return core->plugins.register_runtime(std::string(kind),
                                            std::move(adapter));
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

namespace {

/// Adapter that wraps a `gn_protocol_layer_vtable_t` + `self` pair
/// behind the C++-side `IProtocolLayer` the protocol-layer registry
/// stores. Plugin-supplied C vtables thread through this; the kernel
/// dispatches the same method shapes whether the layer is C++-native
/// (statically linked into the host program) or C-vtable (registered
/// through `gn_core_register_protocol`).
class VtableProtocolLayer final : public ::gn::IProtocolLayer {
public:
    VtableProtocolLayer(const gn_protocol_layer_vtable_t* vtable,
                         void* self) noexcept
        : vtable_(vtable), self_(self),
          protocol_id_cached_(
              vtable && vtable->protocol_id
                  ? std::string(vtable->protocol_id(self))
                  : std::string{}) {}

    ~VtableProtocolLayer() override {
        if (vtable_ && vtable_->destroy) {
            vtable_->destroy(self_);
        }
    }

    VtableProtocolLayer(const VtableProtocolLayer&)            = delete;
    VtableProtocolLayer& operator=(const VtableProtocolLayer&) = delete;

    [[nodiscard]] std::string_view protocol_id() const noexcept override {
        return protocol_id_cached_;
    }

    [[nodiscard]] std::size_t max_payload_size() const noexcept override {
        return (vtable_ && vtable_->max_payload_size)
            ? vtable_->max_payload_size(self_) : 0;
    }

    [[nodiscard]] std::uint32_t allowed_trust_mask() const noexcept override {
        return (vtable_ && vtable_->allowed_trust_mask)
            ? vtable_->allowed_trust_mask(self_)
            : ::gn::IProtocolLayer::allowed_trust_mask();
    }

    [[nodiscard]] ::gn::Result<::gn::DeframeResult> deframe(
        ::gn::ConnectionContext& ctx,
        std::span<const std::uint8_t> bytes) override {
        if (!vtable_ || !vtable_->deframe) {
            return std::unexpected(::gn::Error{
                GN_ERR_NOT_IMPLEMENTED,
                "vtable protocol layer: deframe slot absent"});
        }
        gn_deframe_result_t out{};
        const auto rc = vtable_->deframe(
            self_, &ctx, bytes.data(), bytes.size(), &out);
        if (rc != GN_OK) {
            return std::unexpected(::gn::Error{
                rc, "vtable protocol layer: deframe failed"});
        }
        return ::gn::DeframeResult{
            .messages       = std::span<const gn_message_t>(
                out.messages, out.count),
            .bytes_consumed = out.bytes_consumed};
    }

    [[nodiscard]] ::gn::Result<std::vector<std::uint8_t>> frame(
        ::gn::ConnectionContext& ctx,
        const gn_message_t& msg) override {
        if (!vtable_ || !vtable_->frame) {
            return std::unexpected(::gn::Error{
                GN_ERR_NOT_IMPLEMENTED,
                "vtable protocol layer: frame slot absent"});
        }
        std::uint8_t* out_bytes = nullptr;
        std::size_t   out_size  = 0;
        void*         out_user_data = nullptr;
        void (*out_free)(void*, std::uint8_t*) = nullptr;
        const auto rc = vtable_->frame(
            self_, &ctx, &msg,
            &out_bytes, &out_size, &out_user_data, &out_free);
        if (rc != GN_OK) {
            return std::unexpected(::gn::Error{
                rc, "vtable protocol layer: frame failed"});
        }
        std::vector<std::uint8_t> buf;
        if (out_bytes && out_size) {
            buf.assign(out_bytes, out_bytes + out_size);
        }
        if (out_free) {
            out_free(out_user_data, out_bytes);
        }
        return buf;
    }

private:
    const gn_protocol_layer_vtable_t* vtable_;
    void*                              self_;
    std::string                        protocol_id_cached_;
};

}  // namespace

gn_result_t gn_core_register_protocol(
    gn_core_t* core,
    const gn_protocol_layer_vtable_t* vtable,
    void* self) {
    if (core == nullptr || vtable == nullptr) return GN_ERR_NULL_ARG;
    /// Defensive size-prefix check — vtable producer must have set
    /// `api_size` to at least the slot offset of every method the
    /// kernel calls. Matches the gate in
    /// `core/registry/handler.cpp` for handler vtables.
    if (vtable->api_size < sizeof(gn_protocol_layer_vtable_t)) {
        return GN_ERR_VERSION_MISMATCH;
    }
    auto layer = std::make_shared<VtableProtocolLayer>(vtable, self);
    gn::core::protocol_layer_id_t id = gn::core::kInvalidProtocolLayerId;
    return core->kernel.protocol_layers().register_layer(
        std::move(layer), &id);
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
