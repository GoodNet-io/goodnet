// SPDX-License-Identifier: Apache-2.0
/// @file   bench/test_bench_showcase.hpp
/// @brief  Bench-only kernel scaffold for the free-kernel showcase
///         (track Б of the plan in
///         `~/.claude/plans/crispy-petting-kettle.md`).
///
/// `test_bench_helper.hpp` covers the single-carrier A.2 path; this
/// header extends to the four GoodNet-distinctive moves the
/// showcase bench has to demonstrate:
///   §B.1  multi-connect under one peer identity (TCP + UDP + IPC
///         all registered through the same `host_api`).
///   §B.2  strategy-driven carrier selection through the in-tree
///         `goodnet_float_send_rtt` picker.
///   §B.3  post-handshake security provider handoff Noise→Null —
///         PoC by zeroing the kernel-side InlineCrypto state on an
///         established session (env-gated through
///         `GN_SHOWCASE_ALLOW_INLINE_DOWNGRADE=1`).
///   §B.5  carrier failover via manual `CONN_DOWN` injection (the
///         kernel-side auto-emit hook for `notify_disconnect` is
///         Slice-9-KERNEL pending).
///   §B.6  mobility / LAN shortcut — synthetic second carrier add
///         + `CONN_UP` injection so the strategy flips winner to
///         the new path, mimicking ICE-restart on a fresh
///         interface without the C.4 netlink machinery.
///
/// Everything here lives under `gn::core::test` because some calls
/// poke private kernel state (`SessionRegistry::find`,
/// `SecuritySession::_test_clear_inline_crypto`). Production
/// callers do not link this header — grep
/// `_test_clear_inline_crypto` confirms.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <bench/test_bench_helper.hpp>
#include <core/security/session.hpp>

#include <plugins/links/ipc/ipc.hpp>
#include <plugins/links/tcp/tcp.hpp>
#include <plugins/links/udp/udp.hpp>
#include <plugins/strategies/float_send_rtt/float_send_rtt.hpp>

#include <sdk/extensions/link.h>
#include <sdk/extensions/strategy.h>
#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/types.h>

namespace gn::core::test {

/// `ShowcaseNode` — one kernel + one identity, but THREE link
/// plugins (`TcpLink`, `UdpLink`, `IpcLink`) all registered through
/// the same `host_api` under distinct schemes. The peer
/// (`BenchNode<Link>` from `test_bench_helper.hpp` works as the
/// dialer side because each connect call uses one scheme at a
/// time) ends up with three live connection records under one
/// `remote_pk` — the structural showcase for §B.1.
struct ShowcaseNode {
    std::unique_ptr<Kernel>                            kernel = std::make_unique<Kernel>();
    std::shared_ptr<gn::plugins::gnet::GnetProtocol>   proto  = std::make_shared<gn::plugins::gnet::GnetProtocol>();
    PluginContext                                      ctx;
    host_api_t                                         api{};
    void*                                              noise_self = nullptr;
    NoisePlugin*                                       np         = nullptr;
    ::gn::PublicKey                                    local_pk{};

    /// Each link plugin gets its own vtable (closed via
    /// `make_link_vtable<Link>(scheme)`) and its own
    /// `gn_link_id_t` from `register_vtable`. The kernel's link
    /// registry handles same-process-multiple-schemes natively.
    std::shared_ptr<gn::link::tcp::TcpLink>            tcp = std::make_shared<gn::link::tcp::TcpLink>();
    std::shared_ptr<gn::link::udp::UdpLink>            udp = std::make_shared<gn::link::udp::UdpLink>();
    std::shared_ptr<gn::link::ipc::IpcLink>            ipc = std::make_shared<gn::link::ipc::IpcLink>();
    gn_link_vtable_t                                   tcp_vtable{};
    gn_link_vtable_t                                   udp_vtable{};
    gn_link_vtable_t                                   ipc_vtable{};
    gn_link_id_t                                       tcp_id = GN_INVALID_ID;
    gn_link_id_t                                       udp_id = GN_INVALID_ID;
    gn_link_id_t                                       ipc_id = GN_INVALID_ID;

    ShowcaseNode(NoisePlugin& noise, std::string name) : np(&noise) {
        ctx.plugin_name = std::move(name);
        ctx.kernel      = kernel.get();

        gn::core::protocol_layer_id_t pid = gn::core::kInvalidProtocolLayerId;
        (void)kernel->protocol_layers().register_layer(proto, &pid);

        auto ident = gn::core::identity::NodeIdentity::generate(/*expiry*/0);
        if (ident) {
            local_pk = ident->device().public_key();
            kernel->identities().add(local_pk);
            kernel->set_node_identity(std::move(*ident));
        }

        api = build_host_api(ctx);

        if (np->ok()) {
            (void)np->plugin_init(&api, &noise_self);
            if (noise_self) (void)np->plugin_reg(noise_self);
        }

        register_link(tcp, "tcp", tcp_vtable, tcp_id);
        register_link(udp, "udp", udp_vtable, udp_id);
        register_link(ipc, "ipc", ipc_vtable, ipc_id);
    }

    ShowcaseNode(const ShowcaseNode&)            = delete;
    ShowcaseNode& operator=(const ShowcaseNode&) = delete;

    ~ShowcaseNode() {
        /// Shutdown links FIRST so asio workers drain inbound
        /// callbacks before the noise plugin's per-session
        /// crypto state is unhooked. Same ordering as
        /// `BenchNode::~BenchNode` — same SEGV pattern blocked
        /// by the same fix.
        if (tcp) tcp->shutdown();
        if (udp) udp->shutdown();
        if (ipc) ipc->shutdown();
        if (noise_self && np && np->ok()) {
            (void)np->plugin_unreg(noise_self);
            np->plugin_shut(noise_self);
            noise_self = nullptr;
        }
    }

private:
    template <class Link>
    void register_link(std::shared_ptr<Link>& link, const char* scheme,
                       gn_link_vtable_t& vtable, gn_link_id_t& out_id) {
        link->set_host_api(&api);
        vtable = detail::make_link_vtable<Link>(scheme);
        gn_register_meta_t mt{};
        mt.api_size = sizeof(gn_register_meta_t);
        mt.name     = scheme;
        if (api.register_vtable) {
            (void)api.register_vtable(api.host_ctx, GN_REGISTER_LINK,
                                       &mt, &vtable, link.get(), &out_id);
        }
    }
};

/// ── Strategy hookup (§B.2 / §B.5 / §B.6) ──────────────────────────
///
/// `float_send_rtt` is a singleton-per-node plugin in production
/// (one `gn.strategy.*` extension per kernel). The showcase bench
/// links the plugin's OBJECT lib directly and registers the vtable
/// through `host_api->register_extension`, skipping the dlopen path
/// the production runtime would take. Bob's send-side picks up the
/// strategy when `send_to(peer_pk, ...)` queries
/// `extensions().query_prefix("gn.strategy.")`.

/// Free-function thunks that bridge the C ABI vtable onto
/// `FloatSendRtt::pick_conn` / `on_path_event`. The picker is
/// referenced via `ctx`.
inline gn_result_t showcase_strategy_pick_thunk(
    void* ctx,
    const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
    const gn_path_sample_t* candidates,
    std::size_t count,
    gn_conn_id_t* out_chosen) {
    if (!ctx || !out_chosen) return GN_ERR_NULL_ARG;
    auto* picker = static_cast<
        ::gn::strategy::float_send_rtt::FloatSendRtt*>(ctx);
    return picker->pick_conn(peer_pk, candidates, count, out_chosen);
}

inline gn_result_t showcase_strategy_event_thunk(
    void* ctx,
    const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
    gn_path_event_t ev,
    const gn_path_sample_t* sample) {
    if (!ctx) return GN_ERR_NULL_ARG;
    auto* picker = static_cast<
        ::gn::strategy::float_send_rtt::FloatSendRtt*>(ctx);
    return picker->on_path_event(peer_pk, ev, sample);
}

/// Register @p picker as the active strategy on @p api. The vtable
/// is stashed in `static` storage (mutable; `ctx` is patched per
/// call to the picker pointer) so the address remains valid past
/// the call return — same trap `register_rx` documents for the
/// handler vtable.
inline gn_result_t register_strategy(
    host_api_t& api,
    ::gn::strategy::float_send_rtt::FloatSendRtt& picker) {
    static gn_strategy_api_t kVtable = [] {
        gn_strategy_api_t v{};
        v.api_size      = sizeof(gn_strategy_api_t);
        v.pick_conn     = &showcase_strategy_pick_thunk;
        v.on_path_event = &showcase_strategy_event_thunk;
        return v;
    }();
    kVtable.ctx = &picker;
    if (!api.register_extension) return GN_ERR_NOT_IMPLEMENTED;
    return api.register_extension(api.host_ctx,
        ::gn::strategy::float_send_rtt::kExtensionName,
        ::gn::strategy::float_send_rtt::kExtensionVersion,
        &kVtable);
}

/// Inject a synthetic RTT sample into @p picker so the next
/// `pick_conn` ranks this conn under the new EWMA. The kernel's
/// own RTT measurement source (Slice-9-HEARTBEAT) is pending; the
/// bench drives the picker directly until that lands.
inline void inject_rtt(
    ::gn::strategy::float_send_rtt::FloatSendRtt& picker,
    const ::gn::PublicKey& peer_pk,
    gn_conn_id_t conn,
    std::uint64_t rtt_us,
    std::uint32_t caps = 0) {
    gn_path_sample_t s{};
    s.conn     = conn;
    s.rtt_us   = rtt_us;
    s.caps     = caps;
    (void)picker.on_path_event(peer_pk.data(),
        GN_PATH_EVENT_RTT_UPDATE, &s);
}

/// Inject a CONN_UP — first sample for a freshly discovered path.
/// Used in §B.6 when the LAN-shortcut bench fires a synthetic
/// "new interface arrived". Same shape as `inject_rtt` but a
/// different event kind so the picker treats the EWMA as
/// initialisation, not update.
inline void inject_conn_up(
    ::gn::strategy::float_send_rtt::FloatSendRtt& picker,
    const ::gn::PublicKey& peer_pk,
    gn_conn_id_t conn,
    std::uint64_t rtt_us,
    std::uint32_t caps = 0) {
    gn_path_sample_t s{};
    s.conn     = conn;
    s.rtt_us   = rtt_us;
    s.caps     = caps;
    (void)picker.on_path_event(peer_pk.data(),
        GN_PATH_EVENT_CONN_UP, &s);
}

/// Inject a CONN_DOWN — emits when the kernel disconnects a conn.
/// In production this would be auto-fired from
/// `notify_disconnect`; Slice-9-KERNEL hook is pending so the
/// bench fires manually right after `link->disconnect(conn)`.
inline void inject_conn_down(
    ::gn::strategy::float_send_rtt::FloatSendRtt& picker,
    const ::gn::PublicKey& peer_pk,
    gn_conn_id_t conn) {
    gn_path_sample_t s{};
    s.conn = conn;
    (void)picker.on_path_event(peer_pk.data(),
        GN_PATH_EVENT_CONN_DOWN, &s);
}

/// ── B.3 Provider handoff PoC ──────────────────────────────────────
///
/// Reach into the kernel's `SessionRegistry`, find the session
/// for @p conn, and zero its inline-crypto state. Subsequent
/// encrypt_transport / decrypt_transport on that session fall
/// through to the provider vtable; for `gn.security.null` that
/// vtable is copy-through, so per-frame AEAD cost drops to zero
/// while identity-binding established at Noise handshake survives.
///
/// Env-gated through `_test_clear_inline_crypto` — caller MUST
/// set `GN_SHOWCASE_ALLOW_INLINE_DOWNGRADE=1` before invoking,
/// otherwise the kernel-side guard refuses with
/// `GN_ERR_INVALID_STATE`. The bench process exports the env var
/// from `main` so children inherit; production binaries never set
/// it, so the seam fails closed if accidentally linked.
inline gn_result_t downgrade_inline_crypto(
    Kernel& kernel, gn_conn_id_t conn) {
    auto session = kernel.sessions().find(conn);
    if (!session) return GN_ERR_NOT_FOUND;
    return session->_test_clear_inline_crypto();
}

/// Convenience: clear inline crypto on BOTH halves of an
/// established loopback peer pair. Bench cases call this from the
/// dispatcher thread between iterations so the next round-trip
/// runs through the vtable path. Returns `GN_OK` only when both
/// sides flipped successfully; reports first failure to the caller.
inline gn_result_t downgrade_pair(
    Kernel& a_kernel, gn_conn_id_t a_conn,
    Kernel& b_kernel, gn_conn_id_t b_conn) {
    if (auto rc = downgrade_inline_crypto(a_kernel, a_conn); rc != GN_OK)
        return rc;
    if (auto rc = downgrade_inline_crypto(b_kernel, b_conn); rc != GN_OK)
        return rc;
    return GN_OK;
}

/// ── CSV side-channel for time-series benches (§B.3, §B.5, §B.6) ──
///
/// google-benchmark aggregates `state.counters` across iterations,
/// erasing per-iteration data. Time-series cases write a small
/// CSV file to `/tmp/showcase-<section>-<pid>.csv`; the
/// `showcase_aggregate.py` script picks it up via glob and emits
/// inline ASCII spark plots in the markdown report. Lives in the
/// helper because every section reuses the open/append shape.
class CsvSeries {
public:
    explicit CsvSeries(const char* section_tag) {
        char path[128];
        (void)std::snprintf(path, sizeof(path),
            "/tmp/showcase-%s-%d.csv", section_tag,
            static_cast<int>(::getpid()));
        path_.assign(path);
        fp_ = std::fopen(path, "w");
        /// First line is the schema; aggregator reads it.
        if (fp_) (void)std::fprintf(fp_, "iter,column,value\n");
    }
    ~CsvSeries() {
        if (fp_) (void)std::fclose(fp_);
    }
    CsvSeries(const CsvSeries&)            = delete;
    CsvSeries& operator=(const CsvSeries&) = delete;

    /// Single integer datapoint. Column name lets multiple
    /// time-series share one file (e.g. B.5 carrier-id + latency).
    void emit(std::uint64_t iter, const char* column,
              std::uint64_t value) noexcept {
        if (fp_) {
            (void)std::fprintf(fp_, "%llu,%s,%llu\n",
                static_cast<unsigned long long>(iter),
                column,
                static_cast<unsigned long long>(value));
        }
    }

    [[nodiscard]] const std::string& path() const noexcept { return path_; }

private:
    std::string  path_;
    std::FILE*   fp_ = nullptr;
};

/// Convenience helper — print the CSV path to stderr so the
/// aggregator's glob picks it up via wrapping shell harness.
inline void announce_csv_path(const CsvSeries& csv,
                              const char* section_tag) {
    (void)std::fprintf(stderr, "[showcase] %s csv -> %s\n",
                       section_tag, csv.path().c_str());
}

}  // namespace gn::core::test
