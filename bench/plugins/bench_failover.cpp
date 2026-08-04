// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_failover.cpp
/// @brief  ICE failover policies — restart dispatch cost.
///
/// Failover is fundamentally a wire-level / network-state-driven
/// behaviour: a real TURN allocation has to time out, a netlink
/// RTM_NEWLINK has to fire, a symmetric NAT has to stride. The
/// in-process bench cannot drive those events through real network
/// state without containers (that lives in `tests/docker/ice-3node/`,
/// agent #26). What this bench DOES measure is the kernel-thread
/// dispatch cost on the API surfaces operators touch when wiring
/// up the failover policies:
///
///   * `RestartDispatchCost` — direct `restart()` calls. Pins the
///     strand-side restart bookkeeping (mutex contention,
///     vector-grow on the local_candidates rebuild).
///
/// NOTE: `IceConsentLossRecoveryDispatch` (auto_restart_on_consent_loss
/// policy + notify_consent_loss_for_test) is excluded — those
/// features are post-RC and not yet in the current ICE `main`.

#include "../bench_harness.hpp"

#include <plugins/links/ice/candidate.hpp>
#include <plugins/links/ice/session.hpp>

#include <sdk/cpp/link_carrier.hpp>
#include <sdk/cpp/test/stub_host.hpp>
#include <sdk/extensions/link.h>
#include <sdk/host_api.h>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

namespace {

using namespace gn::bench;
using gn::link::ice::IceConfig;
using gn::link::ice::IceSession;
using gn::link::ice::IceSessionCallbacks;

/// Minimal UDP carrier stub. The failover bench doesn't drive STUN
/// traffic; the carrier is wired only so the session FSM has a
/// non-null `gn.link.udp` resolution during construction.
struct FakeUdpCarrier {
    struct Endpoint {
        std::string         host;
        std::uint16_t       port    = 0;
        gn_link_data_cb_t   data_cb = nullptr;
        void*               data_user = nullptr;
    };

    std::mutex                                       mu;
    std::unordered_map<gn_conn_id_t, Endpoint>       conns;
    std::atomic<gn_conn_id_t>                        next_id{1};
    std::atomic<std::uint16_t>                       listen_port_val{40000};
    gn_link_api_t                                    vt{};

    FakeUdpCarrier() {
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
        if (!out) return GN_ERR_NULL_ARG;
        std::memset(out, 0, sizeof(*out));
        out->flags       = GN_LINK_CAP_DATAGRAM;
        out->max_payload = 1500;
        return GN_OK;
    }
    static gn_result_t s_send(void*, gn_conn_id_t,
                                const std::uint8_t*, std::size_t) {
        return GN_OK;
    }
    static gn_result_t s_close(void* ctx, gn_conn_id_t cid, int) {
        auto* self = static_cast<FakeUdpCarrier*>(ctx);
        std::lock_guard lk(self->mu);
        self->conns.erase(cid);
        return GN_OK;
    }
    static gn_result_t s_listen(void*, const char*) { return GN_OK; }
    static gn_result_t s_connect(void* ctx, const char* uri,
                                   gn_conn_id_t* out_conn) {
        auto* self = static_cast<FakeUdpCarrier*>(ctx);
        std::string_view u(uri);
        const auto pfx = std::string_view("udp://");
        if (u.starts_with(pfx)) u.remove_prefix(pfx.size());
        Endpoint ep;
        const auto colon = u.rfind(':');
        if (colon != std::string_view::npos) {
            ep.host = std::string(u.substr(0, colon));
            try {
                ep.port = static_cast<std::uint16_t>(
                    std::stoul(std::string(u.substr(colon + 1))));
            } catch (...) {
                return GN_ERR_INVALID_ENVELOPE;
            }
        } else {
            ep.host = std::string(u);
        }
        const auto cid = self->next_id.fetch_add(1);
        {
            std::lock_guard lk(self->mu);
            self->conns[cid] = std::move(ep);
        }
        if (out_conn) *out_conn = cid;
        return GN_OK;
    }
    static gn_result_t s_sub_data(void* ctx, gn_conn_id_t cid,
                                    gn_link_data_cb_t cb, void* user) {
        auto* self = static_cast<FakeUdpCarrier*>(ctx);
        std::lock_guard lk(self->mu);
        auto it = self->conns.find(cid);
        if (it == self->conns.end()) return GN_ERR_NOT_FOUND;
        it->second.data_cb   = cb;
        it->second.data_user = user;
        return GN_OK;
    }
    static gn_result_t s_unsub_data(void* ctx, gn_conn_id_t cid) {
        auto* self = static_cast<FakeUdpCarrier*>(ctx);
        std::lock_guard lk(self->mu);
        auto it = self->conns.find(cid);
        if (it == self->conns.end()) return GN_OK;
        it->second.data_cb   = nullptr;
        it->second.data_user = nullptr;
        return GN_OK;
    }
    static gn_result_t s_sub_accept(void*, gn_link_accept_cb_t, void*,
                                      gn_subscription_id_t* tok) {
        if (tok) *tok = 1;
        return GN_OK;
    }
    static gn_result_t s_unsub_accept(void*, gn_subscription_id_t) {
        return GN_OK;
    }
    static gn_result_t s_listen_port(void* ctx, std::uint16_t* out) {
        if (!out) return GN_ERR_NULL_ARG;
        *out = static_cast<FakeUdpCarrier*>(ctx)
                  ->listen_port_val.load(std::memory_order_acquire);
        return GN_OK;
    }
};

struct UdpHarness {
    ::gn::sdk::test::LinkStub          link_stub;
    FakeUdpCarrier                     carrier;
    host_api_t                         api{};

    UdpHarness() {
        api = ::gn::sdk::test::make_link_host_api(link_stub);
        api.query_extension_checked = &s_query;
        api.host_ctx                = this;
    }

    static gn_result_t s_query(void* host_ctx, const char* name,
                                 std::uint32_t version,
                                 const void** out) {
        if (!out) return GN_ERR_NULL_ARG;
        *out = nullptr;
        if (version != GN_EXT_LINK_VERSION) return GN_ERR_NOT_FOUND;
        auto* self = static_cast<UdpHarness*>(host_ctx);
        if (std::string_view(name) == "gn.link.udp") {
            *out = &self->carrier.vt;
            return GN_OK;
        }
        return GN_ERR_NOT_FOUND;
    }
};

struct FailoverFixture : public ::benchmark::Fixture {
    void SetUp(::benchmark::State&) override {
        if (session) return;
        worker = std::thread([this] { ioc.run(); });
        carrier = gn::sdk::LinkCarrier::query(&harness.api, "udp");
        auto* carrier_ptr = carrier.has_value() ? &*carrier : nullptr;
        IceConfig cfg;
        cfg.stun_servers.clear();
        session = std::make_shared<IceSession>(
            ioc, carrier_ptr, nullptr, nullptr, cfg,
            /*peer_id=*/"abcdef0123456789",
            /*controlling=*/true,
            IceSessionCallbacks{});
        session->gather();
    }
    void TearDown(::benchmark::State&) override {
        if (session) session->close();
        session.reset();
        work.reset();
        ioc.stop();
        if (worker.joinable()) worker.join();
        carrier.reset();
    }

    asio::io_context                              ioc;
    asio::executor_work_guard<
        asio::io_context::executor_type>          work{
            asio::make_work_guard(ioc)};
    std::thread                                   worker;
    UdpHarness                                    harness;
    std::optional<gn::sdk::LinkCarrier>           carrier;
    std::shared_ptr<IceSession>                   session;
};

BENCHMARK_DEFINE_F(FailoverFixture, RestartDispatchCost)
    (::benchmark::State& state) {
    ResourceCounters res;
    res.snapshot_start();
    for ([[maybe_unused]] auto _ : state) {
        session->restart();
    }
    res.snapshot_end();
    report_resources(state, res);
}

BENCHMARK_REGISTER_F(FailoverFixture, RestartDispatchCost)
    ->Iterations(1000)
    ->Unit(::benchmark::kMicrosecond);

}  // namespace
