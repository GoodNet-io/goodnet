// SPDX-License-Identifier: Apache-2.0
/// @file   core/kernel/test_bench_helper.hpp
/// @brief  Bench-only kernel/plugin boot helper (A.2 follow-up).
///
/// Spins up a real `gn::core::Kernel` with the gnet protocol layer,
/// the noise security provider (dlopen'd from
/// `GOODNET_NOISE_PLUGIN_PATH`), and a link plugin of the caller's
/// choosing — all inside one process, no manifest or PluginManager.
/// Used by `bench/plugins/bench_real_e2e.cpp` so the RealFixture cases
/// measure the operator-facing send path against the production stack.
///
/// The helper mirrors the shape `tests/integration/test_noise_tcp_e2e.cpp`
/// uses (kernel + identity + GnetProtocol + dlopen'd noise.so + Link
/// vtable registered through `register_vtable`); the integration test
/// is the canonical reference for the boot order.

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <dlfcn.h>

#include <core/identity/node_identity.hpp>
#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/registry/handler.hpp>
#include <core/registry/protocol_layer.hpp>

#include <plugins/protocols/gnet/protocol.hpp>

#include <sdk/cpp/test/poll.hpp>
#include <sdk/cpp/types.hpp>
#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/security.h>
#include <sdk/types.h>

namespace gn::core::test {

/// dlopen wrapper for the noise security provider .so. Constructed
/// once per bench process; each `BenchNode` reuses the resolved
/// entry points to mint its own instance. Compile fails when the
/// build did not surface `GOODNET_NOISE_PLUGIN_PATH` — the helper is
/// only meaningful with a real noise provider.
struct NoisePlugin {
    using SdkVersionFn = void        (*)(std::uint32_t*, std::uint32_t*, std::uint32_t*);
    using InitFn       = gn_result_t (*)(const host_api_t*, void**);
    using RegFn        = gn_result_t (*)(void*);
    using UnregFn      = gn_result_t (*)(void*);
    using ShutFn       = void        (*)(void*);

    void*        handle      = nullptr;
    SdkVersionFn sdk_version = nullptr;
    InitFn       plugin_init = nullptr;
    RegFn        plugin_reg  = nullptr;
    UnregFn      plugin_unreg = nullptr;
    ShutFn       plugin_shut = nullptr;

    explicit NoisePlugin(const char* path) {
        handle = ::dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (!handle) return;
        sdk_version  = reinterpret_cast<SdkVersionFn>(::dlsym(handle, "gn_plugin_sdk_version"));
        plugin_init  = reinterpret_cast<InitFn>(::dlsym(handle, "gn_plugin_init"));
        plugin_reg   = reinterpret_cast<RegFn>(::dlsym(handle, "gn_plugin_register"));
        plugin_unreg = reinterpret_cast<UnregFn>(::dlsym(handle, "gn_plugin_unregister"));
        plugin_shut  = reinterpret_cast<ShutFn>(::dlsym(handle, "gn_plugin_shutdown"));
    }
    NoisePlugin(const NoisePlugin&)            = delete;
    NoisePlugin& operator=(const NoisePlugin&) = delete;
    ~NoisePlugin() { if (handle) ::dlclose(handle); }

    [[nodiscard]] bool ok() const noexcept {
        return handle && plugin_init && plugin_reg
            && plugin_unreg && plugin_shut;
    }
};

namespace detail {

/// Templated link-vtable factory. Every link plugin (`TcpLink`,
/// `UdpLink`, `IpcLink`) carries the same method shape — `listen`,
/// `connect`, `send`, `disconnect`, `set_host_api`, `shutdown` — so a
/// single set of thunks parameterised on the concrete class covers
/// every transport the bench needs without copy-paste. The
/// kernel-facing extension surface is left null; bench fixtures do
/// not exercise the `gn.link.<scheme>` composer slots (that path is
/// covered by `gn::sdk::detail::LinkPluginInstance` in
/// `sdk/cpp/link_plugin.hpp`, used by the real plugin entry points).
template <class Link>
gn_result_t link_send_thunk(void* self, gn_conn_id_t conn,
                             const std::uint8_t* bytes,
                             std::size_t size) {
    if (!self || (!bytes && size > 0)) return GN_ERR_NULL_ARG;
    return static_cast<Link*>(self)->send(
        conn, std::span<const std::uint8_t>(bytes, size));
}

template <class Link>
gn_result_t link_disconnect_thunk(void* self, gn_conn_id_t conn) {
    if (!self) return GN_ERR_NULL_ARG;
    return static_cast<Link*>(self)->disconnect(conn);
}

inline gn_result_t link_send_batch_unused(void*, gn_conn_id_t,
                                           const gn_byte_span_t*, std::size_t) {
    return GN_ERR_NOT_IMPLEMENTED;
}
inline gn_result_t link_listen_unused(void*, const char*) {
    return GN_ERR_NOT_IMPLEMENTED;
}
inline gn_result_t link_connect_unused(void*, const char*) {
    return GN_ERR_NOT_IMPLEMENTED;
}
inline const char* link_ext_name_null(void*)   { return nullptr; }
inline const void* link_ext_vtable_null(void*) { return nullptr; }
inline void        link_destroy_noop(void*)    {}

template <class Link>
gn_link_vtable_t make_link_vtable(const char* scheme) {
    gn_link_vtable_t v{};
    v.api_size         = sizeof(v);
    /// Scheme thunk closes over the literal via a static-storage
    /// stash — bench wires exactly one Link instance per process,
    /// per transport, so the captured pointer remains valid.
    static thread_local const char* tls_scheme;
    tls_scheme = scheme;
    v.scheme           = +[](void*) noexcept -> const char* { return tls_scheme; };
    v.listen           = &link_listen_unused;
    v.connect          = &link_connect_unused;
    v.send             = &link_send_thunk<Link>;
    v.send_batch       = &link_send_batch_unused;
    v.disconnect       = &link_disconnect_thunk<Link>;
    v.extension_name   = &link_ext_name_null;
    v.extension_vtable = &link_ext_vtable_null;
    v.destroy          = &link_destroy_noop;
    return v;
}

}  // namespace detail

/// One bench node — owns a kernel, identity, gnet protocol layer,
/// host_api, dlopen'd noise instance, and a link plugin. Construct
/// one per peer; the two-node loopback shape (`alice` listens,
/// `bob` connects) mirrors the integration test.
///
/// `Link` is the concrete C++ class (`TcpLink`, `UdpLink`,
/// `IpcLink`) — see `sdk/cpp/link_plugin.hpp` for the class concept.
template <class Link>
struct BenchNode {
    std::unique_ptr<Kernel>                            kernel = std::make_unique<Kernel>();
    std::shared_ptr<gn::plugins::gnet::GnetProtocol>   proto  = std::make_shared<gn::plugins::gnet::GnetProtocol>();
    std::shared_ptr<Link>                              link   = std::make_shared<Link>();
    PluginContext                                      ctx;
    host_api_t                                         api{};
    void*                                              noise_self = nullptr;
    NoisePlugin*                                       np         = nullptr;
    gn_link_vtable_t                                   vtable     = {};
    gn_link_id_t                                       link_id    = GN_INVALID_ID;
    ::gn::PublicKey                                    local_pk{};

    BenchNode(NoisePlugin& noise, std::string name, const char* scheme) : np(&noise) {
        ctx.plugin_name = std::move(name);
        ctx.kernel      = kernel.get();

        gn::core::protocol_layer_id_t proto_id = gn::core::kInvalidProtocolLayerId;
        (void)kernel->protocol_layers().register_layer(proto, &proto_id);

        auto ident = gn::core::identity::NodeIdentity::generate(/*expiry*/0);
        if (ident) {
            local_pk = ident->device().public_key();
            kernel->identities().add(local_pk);
            kernel->set_node_identity(std::move(*ident));
        }

        api = build_host_api(ctx);

        /// Noise: one self per node — its handshake state machine
        /// caches the kernel's NodeIdentity at register time.
        if (np->ok()) {
            (void)np->plugin_init(&api, &noise_self);
            if (noise_self) (void)np->plugin_reg(noise_self);
        }

        /// Link: register through the host_api so the kernel's
        /// notify thunks route inbound bytes back through this
        /// instance. The vtable bridges the C ABI onto the C++
        /// `Link::send` / `disconnect` shape.
        link->set_host_api(&api);
        vtable = detail::make_link_vtable<Link>(scheme);
        gn_register_meta_t mt{};
        mt.api_size = sizeof(gn_register_meta_t);
        mt.name     = scheme;
        if (api.register_vtable) {
            (void)api.register_vtable(api.host_ctx, GN_REGISTER_LINK, &mt,
                                       &vtable, link.get(), &link_id);
        }
    }

    BenchNode(const BenchNode&)            = delete;
    BenchNode& operator=(const BenchNode&) = delete;

    ~BenchNode() {
        /// Shutdown ordering matters. The link's asio worker may
        /// have an inbound-bytes callback queued; if we tore the
        /// noise provider down first, the callback would reach
        /// `notify_inbound_bytes → Router::dispatch_chain` with a
        /// stale handler-vtable pointer in the now-unregistered
        /// security session and SEGV inside `safe_call_value`.
        /// Stop the link first (joins its IO threads, drains every
        /// pending inbound), then unhook noise, then let kernel +
        /// other members destruct.
        if (link) link->shutdown();
        if (noise_self && np && np->ok()) {
            (void)np->plugin_unreg(noise_self);
            np->plugin_shut(noise_self);
            noise_self = nullptr;
        }
    }

    /// Walk the kernel's session table for a connection that has
    /// reached `SecurityPhase::Transport`. Returns `GN_INVALID_ID`
    /// while the handshake is still in flight. Linear scan over a
    /// small ID range is fine: bench nodes carry at most one
    /// connection at any point.
    [[nodiscard]] gn_conn_id_t transport_conn() const {
        for (gn_conn_id_t id = 1; id <= 8; ++id) {
            if (auto s = kernel->sessions().find(id);
                s && s->phase() == ::gn::core::SecurityPhase::Transport) {
                return id;
            }
        }
        return GN_INVALID_ID;
    }

    /// Spin-poll until both peers' sessions reach Transport phase,
    /// up to @p timeout. Returns true on success; bench cases call
    /// `SkipWithError` on false.
    static bool wait_both_transport(const BenchNode& a, const BenchNode& b,
                                     std::chrono::milliseconds timeout) {
        return ::gn::sdk::test::wait_for(
            [&] {
                return a.transport_conn() != GN_INVALID_ID
                    && b.transport_conn() != GN_INVALID_ID;
            }, timeout);
    }
};

/// Receive counter — installed on the listener under @p msg_id;
/// every inbound envelope advances `rx_count` so the bench body
/// can confirm forward progress and time send→receive.
///
/// Real-mode bench measures the one-way path bob→alice. Two-way
/// echo (alice→bob) requires the responder to call
/// `api->send(env->conn_id, ...)`, which depends on `env->conn_id`
/// being populated by the protocol layer. The C SDK marks that
/// field as version-gated (`gn_message_t::api_size` check per
/// `abi-evolution.md` §3); the bench stays on the path the
/// protocol-layer ABI guarantees end-to-end and approximates RTT
/// as 2× the one-way figure.
struct RxCounter {
    std::atomic<std::uint64_t>  rx_count{0};
    std::atomic<std::uint64_t>  rx_bytes{0};
};

inline gn_propagation_t rx_handle(void* self, const gn_message_t* env) {
    auto* c = static_cast<RxCounter*>(self);
    if (!c || !env) return GN_PROPAGATION_CONTINUE;
    c->rx_count.fetch_add(1, std::memory_order_relaxed);
    c->rx_bytes.fetch_add(env->payload_size, std::memory_order_relaxed);
    return GN_PROPAGATION_CONSUMED;
}

inline gn_handler_id_t register_rx(Kernel& k, std::uint32_t msg_id,
                                    RxCounter& c) {
    /// HandlerRegistry stores the vtable as a POINTER, not a copy
    /// (see `core/registry/handler.hpp` HandlerEntry::vtable).
    /// A function-local would dangle after `register_rx` returns;
    /// stash the vtable in `static` storage so it outlives every
    /// kernel that registers it across the bench's lifetime.
    static const gn_handler_vtable_t kVtable = [] {
        gn_handler_vtable_t v{};
        v.api_size       = sizeof(v);
        v.handle_message = &rx_handle;
        return v;
    }();
    gn_handler_id_t hid = GN_INVALID_ID;
    (void)k.handlers().register_handler(
        "gnet-v1", msg_id, /*priority*/128, &kVtable, &c, &hid);
    return hid;
}

/// Echo responder — installed on the listener (alice) under
/// @p ping_id. For every inbound envelope, captures the conn_id
/// stamped by gnet protocol layer and synchronously calls
/// `api->send(conn_id, pong_id, payload)` to bounce the bytes
/// back to the sender. Tracks rx volume for sanity.
///
/// This is the track-А shape that lines up with libp2p's
/// `read → echo write` loop in `bench/comparison/p2p/libp2p-echo`
/// — full round-trip through the production stack on both peers.
/// The one-way `RxCounter` measures send→receive once;
/// `RxEchoResponder` adds the reverse leg so the bench body
/// measures wall-clock T0=send → T1=arrival-of-pong, matching
/// what libp2p / iroh runners report.
struct RxEchoResponder {
    const host_api_t*           api      = nullptr;
    std::uint32_t               pong_id  = 0;
    std::atomic<std::uint64_t>  rx_count{0};
    std::atomic<std::uint64_t>  rx_bytes{0};
};

inline gn_propagation_t rx_echo_handle(void* self, const gn_message_t* env) {
    auto* r = static_cast<RxEchoResponder*>(self);
    if (!r || !env) return GN_PROPAGATION_CONTINUE;
    r->rx_count.fetch_add(1, std::memory_order_relaxed);
    r->rx_bytes.fetch_add(env->payload_size, std::memory_order_relaxed);
    /// `env->conn_id` is the inbound-edge conn stamped by gnet
    /// (`sdk/types.h` §gn_message_t.conn_id). Gate on the
    /// envelope's `api_size` so we never read past a producer
    /// built before the conn_id field landed — degrade silently
    /// to no echo per `handler-registration.md` §3a.
    if (r->api && r->api->send
        && env->api_size
               >= offsetof(gn_message_t, conn_id) + sizeof(env->conn_id)
        && env->conn_id != GN_INVALID_ID) {
        (void)r->api->send(r->api->host_ctx, env->conn_id, r->pong_id,
                            env->payload, env->payload_size);
    }
    return GN_PROPAGATION_CONSUMED;
}

inline gn_handler_id_t register_echo_responder(Kernel& k,
                                                std::uint32_t ping_id,
                                                std::uint32_t pong_id,
                                                const host_api_t* api,
                                                RxEchoResponder& r) {
    r.api     = api;
    r.pong_id = pong_id;
    static const gn_handler_vtable_t kVtable = [] {
        gn_handler_vtable_t v{};
        v.api_size       = sizeof(v);
        v.handle_message = &rx_echo_handle;
        return v;
    }();
    gn_handler_id_t hid = GN_INVALID_ID;
    (void)k.handlers().register_handler(
        "gnet-v1", ping_id, /*priority*/128, &kVtable, &r, &hid);
    return hid;
}

}  // namespace gn::core::test
