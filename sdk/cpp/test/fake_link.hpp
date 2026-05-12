// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/test/fake_link.hpp
/// @brief  Reusable fake `gn_link_api_t` vtable for unit tests that
///         exercise `LinkCarrier` / `Connection` / composer plumbing
///         without booting a real transport.
///
/// `test_dsl_helpers.cpp`, `test_connection.cpp`, and several
/// composer tests had nearly-identical `FakeLinkProducer` + free-
/// function thunks (subscribe_data / unsubscribe_data / connect /
/// send / close). This header centralises that pattern. The shape
/// is intentionally generous — every slot is wired so consumers
/// don't dive into null-slot diagnostics.

#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>

#include <sdk/extensions/link.h>
#include <sdk/types.h>

namespace gn::sdk::test {

/// State block + thunks for a minimal in-memory fake link. Every
/// op records its call count + last-seen arguments through atomics
/// so tests can poll via `gn::sdk::test::wait_for`.
struct FakeLink {
    std::atomic<int>          data_subs{0};
    std::atomic<int>          data_unsubs{0};
    std::atomic<int>          accept_subs{0};
    std::atomic<int>          accept_unsubs{0};
    std::atomic<int>          connects{0};
    std::atomic<int>          listens{0};
    std::atomic<int>          disconnects{0};
    std::atomic<int>          sends{0};
    std::atomic<int>          send_batches{0};
    std::atomic<gn_conn_id_t> last_conn{GN_INVALID_ID};
    std::atomic<std::size_t>  last_send_bytes{0};
    std::atomic<gn_subscription_id_t> next_accept_token{1};

    /// Synthetic conn id minted on every `connect`. Tests can
    /// override before calling connect for cases that want
    /// distinct ids.
    static constexpr gn_conn_id_t kSynthId = 0x42;
    std::atomic<gn_conn_id_t>          synth_id{kSynthId};

    static gn_result_t get_stats(void*, gn_link_stats_t*) {
        return GN_OK;
    }
    static gn_result_t get_caps(void*, gn_link_caps_t*) {
        return GN_OK;
    }
    static gn_result_t send(void* ctx, gn_conn_id_t c,
                             const std::uint8_t*, std::size_t n) {
        auto* f = static_cast<FakeLink*>(ctx);
        f->sends.fetch_add(1);
        f->last_conn.store(c);
        f->last_send_bytes.store(n);
        return GN_OK;
    }
    static gn_result_t send_batch(void* ctx, gn_conn_id_t,
                                    const gn_byte_span_t*,
                                    std::size_t) {
        static_cast<FakeLink*>(ctx)->send_batches.fetch_add(1);
        return GN_OK;
    }
    static gn_result_t close(void* ctx, gn_conn_id_t, int) {
        static_cast<FakeLink*>(ctx)->disconnects.fetch_add(1);
        return GN_OK;
    }
    static gn_result_t listen(void* ctx, const char*) {
        static_cast<FakeLink*>(ctx)->listens.fetch_add(1);
        return GN_OK;
    }
    static gn_result_t connect(void* ctx, const char*,
                                gn_conn_id_t* out) {
        auto* f = static_cast<FakeLink*>(ctx);
        f->connects.fetch_add(1);
        if (out) *out = f->synth_id.load(std::memory_order_acquire);
        return GN_OK;
    }
    static gn_result_t subscribe_data(void* ctx, gn_conn_id_t,
                                       gn_link_data_cb_t, void*) {
        static_cast<FakeLink*>(ctx)->data_subs.fetch_add(1);
        return GN_OK;
    }
    static gn_result_t unsubscribe_data(void* ctx, gn_conn_id_t) {
        static_cast<FakeLink*>(ctx)->data_unsubs.fetch_add(1);
        return GN_OK;
    }
    static gn_result_t subscribe_accept(void* ctx,
                                         gn_link_accept_cb_t, void*,
                                         gn_subscription_id_t* out) {
        auto* f = static_cast<FakeLink*>(ctx);
        f->accept_subs.fetch_add(1);
        if (out) *out = f->next_accept_token.fetch_add(1);
        return GN_OK;
    }
    static gn_result_t unsubscribe_accept(void* ctx,
                                            gn_subscription_id_t) {
        static_cast<FakeLink*>(ctx)->accept_unsubs.fetch_add(1);
        return GN_OK;
    }
};

/// Build the `gn_link_api_t` vtable for @p f. `api_size` set, all
/// slots wired to FakeLink thunks, `ctx = &f`.
[[nodiscard]] inline gn_link_api_t make_fake_link_vtable(
    FakeLink& f) noexcept {
    gn_link_api_t vt{};
    vt.api_size           = sizeof(vt);
    vt.get_stats          = &FakeLink::get_stats;
    vt.get_capabilities   = &FakeLink::get_caps;
    vt.send               = &FakeLink::send;
    vt.send_batch         = &FakeLink::send_batch;
    vt.close              = &FakeLink::close;
    vt.listen             = &FakeLink::listen;
    vt.connect            = &FakeLink::connect;
    vt.subscribe_data     = &FakeLink::subscribe_data;
    vt.unsubscribe_data   = &FakeLink::unsubscribe_data;
    vt.subscribe_accept   = &FakeLink::subscribe_accept;
    vt.unsubscribe_accept = &FakeLink::unsubscribe_accept;
    vt.ctx                = &f;
    return vt;
}

}  // namespace gn::sdk::test
