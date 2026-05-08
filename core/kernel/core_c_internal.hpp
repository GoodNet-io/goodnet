/// @file   core/kernel/core_c_internal.hpp
/// @brief  Private definition of `gn_core_s` and helpers shared
///         across the `core_c.cpp` translation unit.
///
/// `sdk/core.h` forward-declares `struct gn_core_s` only; the
/// layout below is intentionally not in any test layout pin so the
/// kernel can move private fields between minor releases without
/// surface rebuild.

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include <sdk/core.h>

#include "host_api_builder.hpp"
#include "kernel.hpp"
#include "plugin_context.hpp"

#include <core/plugin/plugin_manager.hpp>
#include <plugins/protocols/gnet/protocol.hpp>

/// Library handle the host owns through `gn_core_create`.
///
/// Carries the Kernel, the embedding-side PluginContext (kind
/// `GN_PLUGIN_KIND_UNKNOWN` — permissive across role checks because
/// the host is not a plugin), the locked `host_api_t` table the host
/// can pull through `gn_core_host_api`, the `gnet-v1` protocol layer
/// shared_ptr keeping the canonical mesh-framing instance alive, and
/// the manager the host drives through `gn_core_load_plugin`. A
/// `wait_cv` blocks `gn_core_wait` callers until `gn_core_stop`
/// fires.
struct gn_core_s {
    gn::core::Kernel                                  kernel;
    gn::core::PluginContext                           host_ctx;
    std::shared_ptr<gn::plugins::gnet::GnetProtocol>  protocol;
    host_api_t                                        api{};
    gn::core::PluginManager                           plugins;

    /// Bootstrap-once latch. Flipped by `gn_core_init`; subsequent
    /// init calls return `GN_ERR_INVALID_STATE`.
    std::atomic<bool>                                 init_done{false};

    /// `gn_core_wait` blocks on `wait_cv`; `gn_core_stop` fires after
    /// the kernel reaches `Phase::Shutdown` so all waiters wake.
    std::mutex                                        wait_mu;
    std::condition_variable                           wait_cv;

    /// Subscribers tied to the lifetime of this handle. Each entry
    /// matches one `gn_core_subscribe` / `gn_core_on_conn_state`
    /// call; `gn_core_destroy` walks the lists to release every
    /// registration before the kernel and channels are torn down.
    struct MessageSub {
        std::uint64_t       token;
        gn_handler_id_t     handler_id;
        gn_message_cb_t     cb;
        void*               user;
        std::uint32_t       msg_id;
    };
    struct ConnEventSub {
        std::uint64_t token;
        std::uint64_t channel_token;  /// = SignalChannel::Token alias.
    };
    std::mutex                                                          subs_mu;
    std::vector<std::unique_ptr<MessageSub>>                           message_subs;
    std::vector<ConnEventSub>                                          conn_subs;
    std::atomic<std::uint64_t>                                         next_token{1};

    gn_core_s() : plugins(kernel) {
        host_ctx.plugin_name = "host-embedding";
        host_ctx.kernel      = &kernel;
        host_ctx.kind        = GN_PLUGIN_KIND_UNKNOWN;
        api = gn::core::build_host_api(host_ctx);
    }
};
