// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/test/stub_host.hpp
/// @brief  Shared `host_api_t` stubs for plugin unit tests.
///
/// Each link / handler plugin test file used to declare its own
/// 60–80-LOC `StubHost` struct with the same atomic-counter pattern
/// plus a `make_stub_api(h)` factory. This file centralises the two
/// most common shapes:
///
///   * `LinkStub`    — for link-plugin tests; captures
///                     `notify_connect`, `notify_inbound_bytes`,
///                     `notify_disconnect`, `kick_handshake`.
///   * `HandlerStub` — for handler-plugin tests; captures `send`,
///                     `find_conn_by_pk`, `get_endpoint`.
///
/// Plugins with bespoke needs (e.g. capability_blob bus) compose
/// with `empty_host_api(stub)` and plug additional slots manually.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <sdk/host_api.h>
#include <sdk/types.h>

namespace gn::sdk::test {

/// Build an empty `host_api_t` with `api_size` set and `host_ctx`
/// pointing at @p stub. Caller fills the slots they care about.
template <class Stub>
[[nodiscard]] host_api_t empty_host_api(Stub& stub) noexcept {
    host_api_t api{};
    api.api_size = sizeof(host_api_t);
    api.host_ctx = &stub;
    return api;
}

// ─── LinkStub — link-plugin test surface ──────────────────────────

/// Mirrors the ~80 LOC pattern previously copied into each link
/// plugin's test file (TCP, UDP, TLS, WS, IPC, ICE, QUIC). Each
/// callback writes through `mu_` + atomics so tests poll via
/// `gn::sdk::test::wait_for`.
struct LinkStub {
    std::atomic<int>                       connects{0};
    std::atomic<int>                       disconnects{0};
    std::atomic<int>                       inbound_calls{0};
    std::atomic<int>                       kicks{0};
    std::atomic<gn_conn_id_t>              next_id{1};

    mutable std::mutex                     mu;
    std::vector<gn_conn_id_t>              conns;
    std::vector<gn_handshake_role_t>       roles;
    std::vector<gn_trust_class_t>          trusts;
    std::vector<std::vector<std::uint8_t>> inbound;
    std::vector<gn_conn_id_t>              inbound_owners;

    /// Optional caller-thread pin for the `link.md` §9 regression:
    /// `shutdown()` must fire `notify_disconnect` on the caller's
    /// thread, not through an async strand-bound continuation
    /// (which would drop on `ioc_.stop()`). Tests set
    /// `main_tid = std::this_thread::get_id()` before calling
    /// `shutdown()`; `on_disconnect` then increments
    /// `on_main_disconnects` only when the call lands on the
    /// pinned thread. Lets a count-based assert be deterministic
    /// even when worker threads race the main thread.
    std::thread::id                        main_tid{};
    std::atomic<int>                       on_main_disconnects{0};

    /// Sleep (microseconds) injected inside every `on_inbound`
    /// call. Used by bench backpressure scenarios to deliberately
    /// throttle the consumer so the kernel's send/recv buffers
    /// build up and `pending_queue_bytes_*` gates fire. Zero (the
    /// default) preserves the existing fast-path behaviour for
    /// every other test that uses this stub.
    std::atomic<int>                       inbound_sleep_us{0};

    /// When true, `on_inbound` ONLY bumps the counter and skips
    /// the payload copy into `inbound`. Required for long-running
    /// stress benches that emit millions of frames — without this
    /// the stub's vector grows by `total-bytes-sent`, reading like
    /// a multi-GiB leak in RSS reports. The fast tests + assertion
    /// suites leave this false (default) so existing
    /// `last_payload` / `inbound[idx]` accesses keep working.
    std::atomic<bool>                      inbound_discard_payload{false};

    static gn_result_t on_connect(
        void* host_ctx,
        const std::uint8_t /*remote_pk*/[GN_PUBLIC_KEY_BYTES],
        const char* /*uri*/,
        gn_trust_class_t trust,
        gn_handshake_role_t role,
        gn_conn_id_t* out_conn) {
        auto* h = static_cast<LinkStub*>(host_ctx);
        const auto id = h->next_id.fetch_add(1);
        {
            std::lock_guard lk(h->mu);
            h->conns.push_back(id);
            h->roles.push_back(role);
            h->trusts.push_back(trust);
        }
        if (out_conn) *out_conn = id;
        h->connects.fetch_add(1);
        return GN_OK;
    }

    static gn_result_t on_inbound(void* host_ctx, gn_conn_id_t conn,
                                   const std::uint8_t* bytes,
                                   std::size_t size) {
        auto* h = static_cast<LinkStub*>(host_ctx);
        if (!h->inbound_discard_payload.load(
                std::memory_order_acquire)) {
            std::lock_guard lk(h->mu);
            h->inbound.emplace_back(bytes, bytes + size);
            h->inbound_owners.push_back(conn);
        }
        h->inbound_calls.fetch_add(1);
        if (const int us = h->inbound_sleep_us.load(
                std::memory_order_acquire); us > 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(us));
        }
        return GN_OK;
    }

    static gn_result_t on_disconnect(void* host_ctx,
                                       gn_conn_id_t /*conn*/,
                                       gn_result_t /*reason*/) {
        auto* h = static_cast<LinkStub*>(host_ctx);
        h->disconnects.fetch_add(1);
        if (h->main_tid != std::thread::id{} &&
            std::this_thread::get_id() == h->main_tid) {
            h->on_main_disconnects.fetch_add(1);
        }
        return GN_OK;
    }

    static gn_result_t on_kick(void* host_ctx, gn_conn_id_t /*conn*/) {
        static_cast<LinkStub*>(host_ctx)->kicks.fetch_add(1);
        return GN_OK;
    }
};

/// Build a `host_api_t` with all four link-side slots wired to
/// `LinkStub`'s thunks. Equivalent to the 8-line `make_stub_api`
/// each plugin's tests used to define.
[[nodiscard]] inline host_api_t make_link_host_api(LinkStub& h) noexcept {
    host_api_t api = empty_host_api(h);
    api.notify_connect       = &LinkStub::on_connect;
    api.notify_inbound_bytes = &LinkStub::on_inbound;
    api.notify_disconnect    = &LinkStub::on_disconnect;
    api.kick_handshake       = &LinkStub::on_kick;
    return api;
}

// ─── HandlerStub — handler-plugin test surface ────────────────────

/// Captures `host_api->send` calls + scripts `find_conn_by_pk` and
/// `get_endpoint` against a `peer_map`. Mirrors the 60-LOC pattern
/// in `plugins/handlers/heartbeat/tests/test_heartbeat.cpp`.
struct HandlerStub {
    struct PeerEntry {
        gn_conn_id_t conn;
        std::string  uri;
    };

    std::atomic<int>                         send_calls{0};
    mutable std::mutex                       mu;
    std::vector<std::vector<std::uint8_t>>   sent_payloads;
    std::vector<gn_conn_id_t>                sent_conns;
    std::vector<std::uint32_t>               sent_msg_ids;
    std::unordered_map<std::uint8_t,
                       PeerEntry>            peer_map;

    /// Prime the peer registry. `marker` is `pk[0]`; tests build
    /// envelopes with that single byte as the public key.
    void add_peer(std::uint8_t marker, gn_conn_id_t conn,
                   std::string uri) {
        std::lock_guard lk(mu);
        peer_map[marker] = {conn, std::move(uri)};
    }

    static gn_result_t on_send(void* host_ctx, gn_conn_id_t conn,
                                std::uint32_t msg_id,
                                const std::uint8_t* payload,
                                std::size_t size) {
        auto* h = static_cast<HandlerStub*>(host_ctx);
        {
            std::lock_guard lk(h->mu);
            h->sent_payloads.emplace_back(payload, payload + size);
            h->sent_conns.push_back(conn);
            h->sent_msg_ids.push_back(msg_id);
        }
        h->send_calls.fetch_add(1);
        return GN_OK;
    }

    static gn_result_t on_find_conn(
        void* host_ctx,
        const std::uint8_t pk[GN_PUBLIC_KEY_BYTES],
        gn_conn_id_t* out_conn) {
        auto* h = static_cast<HandlerStub*>(host_ctx);
        std::lock_guard lk(h->mu);
        auto it = h->peer_map.find(pk[0]);
        if (it == h->peer_map.end()) return GN_ERR_NOT_FOUND;
        if (out_conn) *out_conn = it->second.conn;
        return GN_OK;
    }

    static gn_result_t on_get_endpoint(void* host_ctx,
                                         gn_conn_id_t conn,
                                         gn_endpoint_t* out) {
        auto* h = static_cast<HandlerStub*>(host_ctx);
        std::lock_guard lk(h->mu);
        for (auto& [m, p] : h->peer_map) {
            if (p.conn != conn) continue;
            std::memset(out, 0, sizeof(*out));
            out->conn_id = conn;
            const std::size_t n = std::min(
                p.uri.size(),
                static_cast<std::size_t>(GN_ENDPOINT_URI_MAX - 1));
            std::memcpy(out->uri, p.uri.data(), n);
            out->uri[n] = '\0';
            return GN_OK;
        }
        return GN_ERR_NOT_FOUND;
    }
};

/// Build a `host_api_t` with the three handler-side slots wired.
[[nodiscard]] inline host_api_t
make_handler_host_api(HandlerStub& h) noexcept {
    host_api_t api = empty_host_api(h);
    api.send             = &HandlerStub::on_send;
    api.find_conn_by_pk  = &HandlerStub::on_find_conn;
    api.get_endpoint     = &HandlerStub::on_get_endpoint;
    return api;
}

}  // namespace gn::sdk::test
