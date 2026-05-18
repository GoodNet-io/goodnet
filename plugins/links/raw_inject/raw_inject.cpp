// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/raw_inject/raw_inject.cpp
/// @brief  L2 byte-translator over `gn.link.tcp`. Inbound bytes
///         ride `host_api->inject(GN_INJECT_LAYER_MESSAGE)`;
///         outbound bytes ride the TCP carrier's send slot.

#include "raw_inject.hpp"

#include <sdk/convenience.h>
#include <sdk/cpp/uri.hpp>

#include <algorithm>
#include <cstring>
#include <exception>
#include <utility>
#include <vector>

namespace gn::link::raw_inject {
namespace {

struct HostPort {
    std::string  host;
    std::uint16_t port = 0;
    bool         ok   = false;
};

[[nodiscard]] HostPort parse_listen_uri(std::string_view uri) noexcept {
    HostPort r;
    const auto parts = ::gn::parse_uri(uri);
    if (!parts || parts->is_path_style()) return r;
    r.host = parts->host;
    r.port = parts->port;
    r.ok   = true;
    return r;
}

[[nodiscard]] std::string make_tcp_uri(const HostPort& hp) {
    std::string out = "tcp://";
    out += hp.host;
    out += ':';
    out += std::to_string(hp.port);
    return out;
}

[[nodiscard]] std::string make_peer_uri(std::string_view tcp_uri) {
    std::string out;
    if (tcp_uri.starts_with("tcp://")) {
        out  = "raw-inject://";
        out += tcp_uri.substr(6);
    } else {
        out  = "raw-inject://";
        out += tcp_uri;
    }
    return out;
}

}  // namespace

RawInjectLink::RawInjectLink() = default;

RawInjectLink::~RawInjectLink() {
    try {
        shutdown();
    } catch (const std::exception& e) {
        if (api_) {
            gn_log_warn(api_, "raw_inject: shutdown threw: %s", e.what());
        }
    } catch (...) {
        if (api_) {
            gn_log_warn(api_, "raw_inject: shutdown threw non-std");
        }
    }
}

void RawInjectLink::set_host_api(const host_api_t* api) noexcept {
    api_ = api;
    if (!api_) return;

    Config cfg;
    if (api_->config_get) {
        char* str = nullptr;
        void* ud  = nullptr;
        void  (*freefn)(void*, void*) = nullptr;
        if (gn_config_get_string(api_, "raw_inject.listen",
                                  &str, &ud, &freefn) == GN_OK &&
            str != nullptr) {
            cfg.listen_uri = str;
            if (freefn) freefn(ud, str);
        }
        std::int64_t v = 0;
        if (gn_config_get_int64(api_, "raw_inject.default_msg_id", &v) == GN_OK
            && v > 0 && v <= 0xFFFFFFFFLL) {
            cfg.default_msg_id = static_cast<std::uint32_t>(v);
        }
        if (gn_config_get_int64(api_, "raw_inject.rate_limit_per_sec", &v) == GN_OK
            && v >= 0 && v <= 0xFFFFFFFFLL) {
            cfg.rate_limit_per_sec = static_cast<std::uint32_t>(v);
        }
        if (gn_config_get_int64(api_, "raw_inject.max_payload", &v) == GN_OK
            && v >= 0 && v <= 0xFFFFFFFFLL) {
            cfg.max_payload = static_cast<std::uint32_t>(v);
        }
        if (gn_config_get_string(api_, "raw_inject.encode_msg_id",
                                  &str, &ud, &freefn) == GN_OK &&
            str != nullptr) {
            cfg.encode_msg_id = str;
            if (freefn) freefn(ud, str);
        }
    }
    set_config(cfg);
}

void RawInjectLink::set_default_trust_class(gn_trust_class_t t) noexcept {
    default_trust_ = t;
}

void RawInjectLink::set_config(const Config& cfg) noexcept {
    std::lock_guard lk(cfg_mu_);
    cfg_ = cfg;
}

Config RawInjectLink::config() const noexcept {
    std::lock_guard lk(cfg_mu_);
    return cfg_;
}

std::uint16_t RawInjectLink::listen_port() const noexcept {
    return listen_port_.load(std::memory_order_acquire);
}

std::size_t RawInjectLink::session_count() const noexcept {
    std::lock_guard lk(sessions_mu_);
    return by_kernel_.size();
}

RawInjectLink::Stats RawInjectLink::stats() const noexcept {
    Stats s{};
    s.bytes_in           = bytes_in_.load(std::memory_order_relaxed);
    s.bytes_out          = bytes_out_.load(std::memory_order_relaxed);
    s.frames_in          = frames_in_.load(std::memory_order_relaxed);
    s.frames_out         = frames_out_.load(std::memory_order_relaxed);
    s.active_connections = session_count();
    return s;
}

gn_link_caps_t RawInjectLink::capabilities() noexcept {
    gn_link_caps_t c{};
    c.flags       = GN_LINK_CAP_STREAM
                  | GN_LINK_CAP_RELIABLE
                  | GN_LINK_CAP_ORDERED;
    c.max_payload = 0;
    return c;
}

gn_result_t RawInjectLink::ensure_carrier() {
    if (carrier_) return GN_OK;
    if (!api_) return GN_ERR_INVALID_STATE;
    auto opt = gn::sdk::LinkCarrier::query(api_, "tcp");
    if (!opt) return GN_ERR_NOT_FOUND;
    carrier_.emplace(std::move(*opt));
    return GN_OK;
}

gn_result_t RawInjectLink::listen(std::string_view uri_sv) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_INVALID_STATE;

    const auto hp = parse_listen_uri(uri_sv);
    if (!hp.ok) return GN_ERR_INVALID_ENVELOPE;

    if (const auto rc = ensure_carrier(); rc != GN_OK) {
        gn_log_warn(api_,
            "raw_inject: ensure_carrier(tcp) failed rc=%d", rc);
        return rc;
    }

    auto self_weak = weak_from_this();
    const gn_result_t accept_rc = carrier_->on_accept(
        [self_weak](gn_conn_id_t c, std::string_view peer) {
            if (auto t = self_weak.lock()) {
                t->on_carrier_accept(c, peer);
            }
        });
    if (accept_rc != GN_OK) {
        gn_log_warn(api_,
            "raw_inject: carrier on_accept rc=%d", accept_rc);
        return accept_rc;
    }

    const std::string tcp_uri = make_tcp_uri(hp);
    const gn_result_t listen_rc = carrier_->listen(tcp_uri);
    if (listen_rc != GN_OK) {
        gn_log_warn(api_,
            "raw_inject: carrier listen %s rc=%d",
            tcp_uri.c_str(), listen_rc);
        return listen_rc;
    }
    listen_port_.store(carrier_->listen_port(),
                        std::memory_order_release);
    return GN_OK;
}

gn_result_t RawInjectLink::connect(std::string_view /*uri_sv*/) {
    /// `raw_inject` is a one-way bridge: foreign clients dial in, the
    /// kernel routes their bytes through `inject`. Outbound dial is
    /// not part of the contract.
    return GN_ERR_NOT_IMPLEMENTED;
}

void RawInjectLink::on_carrier_accept(gn_conn_id_t carrier_id,
                                       std::string_view peer_uri) {
    if (shutdown_.load(std::memory_order_acquire)) return;
    if (!api_ || !api_->notify_connect) return;
    if (!carrier_) return;

    auto session = std::make_shared<Session>();
    session->carrier_id = carrier_id;
    session->peer_uri   = peer_uri.empty()
        ? std::string{"raw-inject://anonymous"}
        : make_peer_uri(peer_uri);

    std::uint8_t remote_pk[GN_PUBLIC_KEY_BYTES] = {};
    gn_conn_id_t kernel_conn = GN_INVALID_ID;
    const gn_result_t rc = api_->notify_connect(
        api_->host_ctx, remote_pk, session->peer_uri.c_str(),
        default_trust_, GN_ROLE_RESPONDER, &kernel_conn);
    if (rc != GN_OK || kernel_conn == GN_INVALID_ID) {
        (void)carrier_->disconnect(carrier_id, 1);
        return;
    }
    session->kernel_id = kernel_conn;

    {
        std::lock_guard lk(sessions_mu_);
        by_carrier_[carrier_id] = session;
        by_kernel_[kernel_conn] = session;
    }

    auto self_weak = weak_from_this();
    (void)carrier_->on_data(carrier_id,
        [self_weak](gn_conn_id_t c,
                     std::span<const std::uint8_t> bytes) {
            if (auto t = self_weak.lock()) {
                t->on_carrier_data(c, bytes);
            }
        });
}

void RawInjectLink::on_carrier_data(gn_conn_id_t carrier_id,
                                     std::span<const std::uint8_t> bytes) {
    if (shutdown_.load(std::memory_order_acquire)) return;
    auto session = session_by_carrier(carrier_id);
    if (!session) return;
    bytes_in_.fetch_add(bytes.size(), std::memory_order_relaxed);
    frames_in_.fetch_add(1,           std::memory_order_relaxed);
    dispatch_inject(session, bytes);
}

void RawInjectLink::dispatch_inject(
    const std::shared_ptr<Session>& session,
    std::span<const std::uint8_t> bytes) {
    if (!api_ || !api_->inject) return;

    Config cfg = config();

    if (cfg.max_payload != 0 && bytes.size() > cfg.max_payload) {
        if (api_->emit_counter) {
            api_->emit_counter(api_->host_ctx,
                                "raw_inject.drop.too_large");
        }
        return;
    }

    const std::uint8_t* payload = bytes.data();
    std::size_t         size    = bytes.size();
    std::uint32_t       msg_id  = cfg.default_msg_id;

    if (cfg.encode_msg_id == "stream") {
        if (size < 4) {
            if (api_->emit_counter) {
                api_->emit_counter(api_->host_ctx,
                                    "raw_inject.drop.short_stream");
            }
            return;
        }
        msg_id = (static_cast<std::uint32_t>(payload[0]) << 24) |
                 (static_cast<std::uint32_t>(payload[1]) << 16) |
                 (static_cast<std::uint32_t>(payload[2]) << 8)  |
                  static_cast<std::uint32_t>(payload[3]);
        payload += 4;
        size    -= 4;
    }

    const gn_result_t rc = api_->inject(
        api_->host_ctx,
        GN_INJECT_LAYER_MESSAGE,
        session->kernel_id,
        msg_id,
        payload, size);

    if (rc != GN_OK && api_->emit_counter) {
        api_->emit_counter(api_->host_ctx, "raw_inject.inject.error");
    }
}

gn_result_t RawInjectLink::send(gn_conn_id_t conn,
                                 std::span<const std::uint8_t> bytes) {
    auto session = session_by_kernel(conn);
    if (!session) return GN_ERR_NOT_FOUND;
    if (!carrier_) return GN_ERR_INVALID_STATE;
    const gn_result_t rc = carrier_->send(session->carrier_id, bytes);
    if (rc == GN_OK) {
        bytes_out_.fetch_add(bytes.size(), std::memory_order_relaxed);
        frames_out_.fetch_add(1,           std::memory_order_relaxed);
    }
    return rc;
}

gn_result_t RawInjectLink::send_batch(
    gn_conn_id_t conn,
    std::span<const std::span<const std::uint8_t>> frames) {
    if (frames.empty()) return GN_OK;
    if (frames.size() == 1) return send(conn, frames[0]);
    auto session = session_by_kernel(conn);
    if (!session) return GN_ERR_NOT_FOUND;
    std::size_t total = 0;
    for (auto& f : frames) total += f.size();
    std::vector<std::uint8_t> joined;
    joined.reserve(total);
    for (auto& f : frames) {
        joined.insert(joined.end(), f.begin(), f.end());
    }
    return send(conn, joined);
}

gn_result_t RawInjectLink::disconnect(gn_conn_id_t conn) {
    std::shared_ptr<Session> session;
    {
        std::lock_guard lk(sessions_mu_);
        auto it = by_kernel_.find(conn);
        if (it == by_kernel_.end()) return GN_OK;
        session = std::move(it->second);
        by_kernel_.erase(it);
        by_carrier_.erase(session->carrier_id);
    }
    if (carrier_) {
        (void)carrier_->disconnect(session->carrier_id, 0);
    }
    return GN_OK;
}

std::shared_ptr<RawInjectLink::Session>
RawInjectLink::session_by_carrier(gn_conn_id_t carrier_id) const {
    std::lock_guard lk(sessions_mu_);
    auto it = by_carrier_.find(carrier_id);
    return (it == by_carrier_.end()) ? nullptr : it->second;
}

std::shared_ptr<RawInjectLink::Session>
RawInjectLink::session_by_kernel(gn_conn_id_t kernel_id) const {
    std::lock_guard lk(sessions_mu_);
    auto it = by_kernel_.find(kernel_id);
    return (it == by_kernel_.end()) ? nullptr : it->second;
}

void RawInjectLink::shutdown() {
    if (shutdown_.exchange(true, std::memory_order_acq_rel)) return;

    std::vector<std::shared_ptr<Session>> drain;
    {
        std::lock_guard lk(sessions_mu_);
        drain.reserve(by_kernel_.size());
        for (auto& [_, s] : by_kernel_) drain.push_back(s);
        by_kernel_.clear();
        by_carrier_.clear();
    }

    if (carrier_) {
        for (const auto& s : drain) {
            (void)carrier_->disconnect(s->carrier_id, 1);
        }
    }
    if (api_ && api_->notify_disconnect) {
        for (const auto& s : drain) {
            (void)api_->notify_disconnect(
                api_->host_ctx, s->kernel_id, GN_OK);
        }
    }

    /// `LinkCarrier` dtor unsubscribes every per-conn data sub +
    /// the accept-bus sub it installed; the carrier vtable's
    /// `unsubscribe_*` slots wait for in-flight callbacks per
    /// `link.en.md` §8 so the reset is safe even if a callback is
    /// mid-flight.
    carrier_.reset();
}

}  // namespace gn::link::raw_inject
