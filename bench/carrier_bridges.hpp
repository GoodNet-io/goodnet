// SPDX-License-Identifier: Apache-2.0
/// @file   bench/carrier_bridges.hpp
/// @brief  Reusable carrier bridges for L2 plugin benchmarks.
///
/// TLS, WS, WSS, DTLS, QUIC, and ICE-on-UDP all need an L1 carrier
/// exposed through host_api->query_extension. Each bench used to
/// build its own ~80 LOC bridge; this header centralises the
/// pattern so the per-plugin benches stay focused on the bench
/// itself, not on the fixture plumbing.
///
/// Layout:
///   * `CarrierBridge<L1>` — wraps an L1 plugin instance and emits a
///     `gn_link_api_t` vtable forwarding into its composer surface.
///   * `BridgeHarness<L1>` — couples a BenchKernel with one bridge;
///     `api` is a host_api_t whose `query_extension_checked` resolves
///     `gn.link.<scheme>` to the bridge's vtable.
///
/// Used by bench_ws (TCP carrier), bench_quic (UDP), bench_dtls
/// (UDP), bench_ice-composer (UDP). Keeps each per-plugin bench
/// under ~200 LOC.

#pragma once

#include "bench_harness.hpp"

#include <cstring>
#include <memory>
#include <string>
#include <string_view>

#include <sdk/extensions/link.h>

namespace gn::bench {

/// L1 carrier bridge — wraps a plugin instance and exposes its
/// composer surface through a `gn_link_api_t` vtable. The template
/// `L1` is the plugin class (TcpLink, UdpLink, ...); it has to
/// expose composer_listen / composer_connect / composer_subscribe_data
/// / composer_unsubscribe_data / composer_subscribe_accept /
/// composer_unsubscribe_accept / composer_listen_port plus the basic
/// send / disconnect / capabilities surface.
template <class L1>
struct CarrierBridge {
    std::shared_ptr<L1> plugin = std::make_shared<L1>();
    gn_link_api_t       vt{};

    CarrierBridge() {
        vt.api_size             = sizeof(vt);
        vt.get_capabilities     = &s_caps;
        vt.send                 = &s_send;
        vt.close                = &s_close;
        vt.listen               = &s_listen;
        vt.connect              = &s_connect;
        vt.subscribe_data       = &s_sub_data;
        vt.unsubscribe_data     = &s_unsub_data;
        vt.subscribe_accept     = &s_sub_accept;
        vt.unsubscribe_accept   = &s_unsub_accept;
        vt.composer_listen_port = &s_listen_port;
        vt.ctx                  = this;
    }

    static gn_result_t s_caps(void*, gn_link_caps_t* out) {
        if (out) *out = L1::capabilities();
        return GN_OK;
    }
    static gn_result_t s_send(void* ctx, gn_conn_id_t c,
                               const std::uint8_t* b, std::size_t n) {
        return static_cast<CarrierBridge*>(ctx)->plugin->send(
            c, std::span<const std::uint8_t>(b, n));
    }
    static gn_result_t s_close(void* ctx, gn_conn_id_t c, int) {
        return static_cast<CarrierBridge*>(ctx)->plugin->disconnect(c);
    }
    static gn_result_t s_listen(void* ctx, const char* uri) {
        return static_cast<CarrierBridge*>(ctx)
            ->plugin->composer_listen(uri);
    }
    static gn_result_t s_connect(void* ctx, const char* uri,
                                  gn_conn_id_t* out) {
        return static_cast<CarrierBridge*>(ctx)
            ->plugin->composer_connect(uri, out);
    }
    static gn_result_t s_sub_data(void* ctx, gn_conn_id_t c,
                                    gn_link_data_cb_t cb, void* u) {
        return static_cast<CarrierBridge*>(ctx)
            ->plugin->composer_subscribe_data(c, cb, u);
    }
    static gn_result_t s_unsub_data(void* ctx, gn_conn_id_t c) {
        return static_cast<CarrierBridge*>(ctx)
            ->plugin->composer_unsubscribe_data(c);
    }
    static gn_result_t s_sub_accept(void* ctx, gn_link_accept_cb_t cb,
                                      void* u, gn_subscription_id_t* t) {
        return static_cast<CarrierBridge*>(ctx)
            ->plugin->composer_subscribe_accept(cb, u, t);
    }
    static gn_result_t s_unsub_accept(void* ctx, gn_subscription_id_t t) {
        return static_cast<CarrierBridge*>(ctx)
            ->plugin->composer_unsubscribe_accept(t);
    }
    static gn_result_t s_listen_port(void* ctx, std::uint16_t* out) {
        return static_cast<CarrierBridge*>(ctx)
            ->plugin->composer_listen_port(out);
    }
};

/// Couples a BenchKernel with one CarrierBridge so the L2 plugin
/// under bench can `set_host_api(&harness.api)` and find its
/// underlying L1 through query_extension.
template <class L1>
struct BridgeHarness {
    BenchKernel       kernel;
    CarrierBridge<L1> bridge;
    std::string       scheme;
    host_api_t        api{};

    explicit BridgeHarness(std::string_view scheme_)
        : scheme(scheme_) {
        bridge.plugin->set_host_api(&kernel.api);
        api = kernel.api;
        api.query_extension_checked = &s_query;
        api.host_ctx                = this;
    }

    static gn_result_t s_query(void* host_ctx, const char* name,
                                 std::uint32_t version,
                                 const void** out) {
        if (!out) return GN_ERR_NULL_ARG;
        *out = nullptr;
        if (version != GN_EXT_LINK_VERSION) return GN_ERR_NOT_FOUND;
        auto* h = static_cast<BridgeHarness*>(host_ctx);
        const std::string full = std::string("gn.link.") + h->scheme;
        if (std::string_view(name) == full) {
            *out = &h->bridge.vt;
            return GN_OK;
        }
        return GN_ERR_NOT_FOUND;
    }
};

}  // namespace gn::bench
