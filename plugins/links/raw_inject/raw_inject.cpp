// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/raw_inject/raw_inject.cpp
/// @brief  Raw TCP listen + accept; inbound bytes flow through
///         `host_api->inject(GN_INJECT_LAYER_MESSAGE)`, outbound
///         bytes from the handler land on the same TCP socket.

#include "raw_inject.hpp"

#include <sdk/convenience.h>
#include <sdk/cpp/uri.hpp>

#include <asio/bind_executor.hpp>
#include <asio/buffer.hpp>
#include <asio/dispatch.hpp>
#include <asio/post.hpp>
#include <asio/write.hpp>
#include <system_error>

#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <exception>
#include <thread>
#include <utility>
#include <vector>

namespace gn::link::raw_inject {
namespace {

constexpr std::size_t kReadBufferSize = std::size_t{16} * 1024;

/// Map a `raw_inject://host:port` URI to the host / port pair used by
/// the asio resolver. Mirrors `tcp://host:port` parsing but accepts
/// the `raw_inject` scheme up front.
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

}  // namespace

// ── Session ──────────────────────────────────────────────────────────────

class RawInjectLink::Session
    : public std::enable_shared_from_this<Session> {
public:
    Session(asio::ip::tcp::socket sock,
             std::weak_ptr<RawInjectLink> transport)
        : socket_(std::move(sock)),
          strand_(socket_.get_executor()),
          transport_(std::move(transport)) {}

    asio::ip::tcp::socket& socket() noexcept { return socket_; }

    gn_conn_id_t conn_id = GN_INVALID_ID;

    void start_read() {
        socket_.async_read_some(
            asio::buffer(read_buf_),
            asio::bind_executor(strand_,
                [self = shared_from_this()](
                    const std::error_code& ec, std::size_t n) {
                    auto t = self->transport_.lock();
                    if (!t) return;
                    if (ec) {
                        const gn_result_t reason =
                            (ec == asio::error::eof) ? GN_OK
                                                      : GN_ERR_NULL_ARG;
                        if (t->claim_disconnect(self->conn_id) &&
                            t->api_ && t->api_->notify_disconnect) {
                            (void)t->api_->notify_disconnect(
                                t->api_->host_ctx, self->conn_id, reason);
                        }
                        return;
                    }
                    if (n > 0) {
                        t->bytes_in_.fetch_add(n, std::memory_order_relaxed);
                        t->frames_in_.fetch_add(1, std::memory_order_relaxed);
                        self->dispatch_inject(*t, n);
                    }
                    self->start_read();
                }));
    }

    void do_send(std::span<const std::uint8_t> data) {
        auto buf = std::make_shared<std::vector<std::uint8_t>>(
            data.begin(), data.end());
        asio::dispatch(strand_,
            [self = shared_from_this(), buf = std::move(buf)]() mutable {
                self->write_queue_.push_back(std::move(buf));
                self->maybe_start_write();
            });
    }

    void do_close() {
        asio::dispatch(strand_, [self = shared_from_this()] {
            std::error_code ec;
            (void)self->socket_.close(ec);
        });
    }

private:
    void dispatch_inject(RawInjectLink& t, std::size_t n) {
        if (!t.api_ || !t.api_->inject) return;

        Config cfg = t.config();

        if (cfg.max_payload != 0 && n > cfg.max_payload) {
            if (t.api_->emit_counter) {
                t.api_->emit_counter(t.api_->host_ctx,
                                      "raw_inject.drop.too_large");
            }
            return;
        }

        const std::uint8_t* payload = read_buf_.data();
        std::size_t         size    = n;
        std::uint32_t       msg_id  = cfg.default_msg_id;

        if (cfg.encode_msg_id == "stream") {
            if (n < 4) {
                if (t.api_->emit_counter) {
                    t.api_->emit_counter(t.api_->host_ctx,
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

        const gn_result_t rc = t.api_->inject(
            t.api_->host_ctx,
            GN_INJECT_LAYER_MESSAGE,
            conn_id,
            msg_id,
            payload, size);

        if (rc != GN_OK && t.api_->emit_counter) {
            t.api_->emit_counter(t.api_->host_ctx,
                                  "raw_inject.inject.error");
        }
    }

    void maybe_start_write() {
        if (write_in_flight_ || write_queue_.empty()) return;
        write_in_flight_ = true;
        auto buf = write_queue_.front();
        const std::size_t buf_size = buf->size();
        asio::async_write(socket_, asio::buffer(*buf),
            asio::bind_executor(strand_,
                [self = shared_from_this(), buf, buf_size](
                    const std::error_code& ec, std::size_t n) {
                    self->write_queue_.pop_front();
                    self->write_in_flight_ = false;
                    auto t = self->transport_.lock();
                    if (!t) return;
                    if (ec) {
                        if (t->claim_disconnect(self->conn_id) &&
                            t->api_ && t->api_->notify_disconnect) {
                            (void)t->api_->notify_disconnect(
                                t->api_->host_ctx, self->conn_id,
                                GN_ERR_NULL_ARG);
                        }
                        return;
                    }
                    t->bytes_out_.fetch_add(n, std::memory_order_relaxed);
                    t->frames_out_.fetch_add(1, std::memory_order_relaxed);
                    self->maybe_start_write();
                }));
    }

    asio::ip::tcp::socket                                       socket_;
    asio::strand<asio::any_io_executor>                         strand_;
    std::weak_ptr<RawInjectLink>                                transport_;

    std::array<std::uint8_t, kReadBufferSize>                   read_buf_{};
    std::deque<std::shared_ptr<std::vector<std::uint8_t>>>      write_queue_;
    bool                                                        write_in_flight_ = false;
};

// ── RawInjectLink ────────────────────────────────────────────────────────

RawInjectLink::RawInjectLink()
    : ioc_(),
      work_(asio::make_work_guard(ioc_)) {
    const unsigned hc = std::thread::hardware_concurrency();
    const unsigned n  = std::max(1u, hc / 2);
    workers_.reserve(n);
    for (unsigned i = 0; i < n; ++i) {
        workers_.emplace_back([this] { ioc_.run(); });
    }
}

RawInjectLink::~RawInjectLink() {
    try {
        shutdown();
    } catch (const std::exception& e) {
        if (api_) {
            gn_log_warn(api_, "raw_inject: shutdown threw: %s", e.what());
        }
    } catch (...) {
        if (api_) {
            gn_log_warn(api_,
                "raw_inject: shutdown threw non-std exception");
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
    return sessions_.size();
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

gn_result_t RawInjectLink::listen(std::string_view uri_sv) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_INVALID_STATE;

    const auto hp = parse_listen_uri(uri_sv);
    if (!hp.ok) return GN_ERR_INVALID_ENVELOPE;

    std::error_code ec;
    const auto addr = asio::ip::make_address(hp.host, ec);
    if (ec) return GN_ERR_INVALID_ENVELOPE;
    asio::ip::tcp::endpoint ep(addr, hp.port);

    try {
        asio::ip::tcp::acceptor acceptor(ioc_);
        acceptor.open(ep.protocol());
        std::error_code reuse_ec;
        (void)acceptor.set_option(
            asio::ip::tcp::acceptor::reuse_address(true), reuse_ec);
        acceptor.bind(ep);
        acceptor.listen();
        listen_port_.store(acceptor.local_endpoint().port(),
                            std::memory_order_release);
        acceptor_.emplace(std::move(acceptor));
    } catch (const std::exception& e) {
        if (api_) {
            gn_log_warn(api_,
                "raw_inject: listen failed (uri=%.*s): %s",
                static_cast<int>(uri_sv.size()), uri_sv.data(), e.what());
        }
        return GN_ERR_NULL_ARG;
    }

    start_accept();
    return GN_OK;
}

gn_result_t RawInjectLink::connect(std::string_view /*uri_sv*/) {
    /// `raw_inject` is a one-way bridge: foreign clients dial in, the
    /// kernel routes their bytes through `inject`. Outbound dial is
    /// not part of the contract.
    return GN_ERR_NOT_IMPLEMENTED;
}

void RawInjectLink::start_accept() {
    if (shutdown_.load(std::memory_order_acquire) || !acceptor_) return;

    auto session = std::make_shared<Session>(
        asio::ip::tcp::socket(ioc_),
        weak_from_this());

    if (!acceptor_.has_value()) return;
    auto& sock = session->socket();
    acceptor_->async_accept(sock,
        [weak = std::weak_ptr<RawInjectLink>(shared_from_this()),
         session = std::move(session)](
            const std::error_code& ec) mutable {
            if (auto t = weak.lock()) t->on_accept(std::move(session), ec);
        });
}

void RawInjectLink::on_accept(std::shared_ptr<Session> session,
                                const std::error_code& ec) {
    if (ec || shutdown_.load(std::memory_order_acquire)) return;

    if (api_ && api_->notify_connect) {
        /// Anonymous source from the application's POV — but the
        /// kernel router rejects zero-sender envelopes. Derive a
        /// per-session synthetic pk from the listener's wall-clock
        /// snapshot + a session counter so every connection looks
        /// distinct to the kernel without leaking peer identity.
        std::uint8_t remote_pk[GN_PUBLIC_KEY_BYTES] = {};
        {
            static std::atomic<std::uint64_t> tag{1};
            const auto seq = tag.fetch_add(1, std::memory_order_relaxed);
            remote_pk[0]   = 0xFA;  // 'fake anonymous' marker
            remote_pk[1]   = static_cast<std::uint8_t>(seq      );
            remote_pk[2]   = static_cast<std::uint8_t>(seq >>  8);
            remote_pk[3]   = static_cast<std::uint8_t>(seq >> 16);
            remote_pk[4]   = static_cast<std::uint8_t>(seq >> 24);
            remote_pk[5]   = static_cast<std::uint8_t>(seq >> 32);
            remote_pk[6]   = static_cast<std::uint8_t>(seq >> 40);
            remote_pk[7]   = static_cast<std::uint8_t>(seq >> 48);
            remote_pk[8]   = static_cast<std::uint8_t>(seq >> 56);
        }
        gn_conn_id_t conn = GN_INVALID_ID;
        std::error_code re_ec;
        const auto remote = session->socket().remote_endpoint(re_ec);
        std::string uri = "raw-inject://";
        if (!re_ec) {
            if (remote.address().is_v6()) {
                uri += '[';
                uri += remote.address().to_string();
                uri += ']';
            } else {
                uri += remote.address().to_string();
            }
            uri += ':';
            uri += std::to_string(remote.port());
        } else {
            uri += "anonymous";
        }
        const gn_result_t rc = api_->notify_connect(
            api_->host_ctx, remote_pk, uri.c_str(),
            GN_TRUST_LOOPBACK, GN_ROLE_RESPONDER, &conn);
        if (rc == GN_OK && conn != GN_INVALID_ID) {
            session->conn_id = conn;
            register_session(conn, session);
            session->start_read();
        } else {
            session->do_close();
        }
    } else {
        session->do_close();
    }

    start_accept();
}

gn_result_t RawInjectLink::send(gn_conn_id_t conn,
                                  std::span<const std::uint8_t> bytes) {
    auto session = find_session(conn);
    if (!session) return GN_ERR_NOT_FOUND;
    session->do_send(bytes);
    return GN_OK;
}

gn_result_t RawInjectLink::send_batch(
    gn_conn_id_t conn,
    std::span<const std::span<const std::uint8_t>> frames) {
    if (frames.empty()) return GN_OK;
    if (frames.size() == 1) return send(conn, frames[0]);
    auto session = find_session(conn);
    if (!session) return GN_ERR_NOT_FOUND;
    std::size_t total = 0;
    for (auto& f : frames) total += f.size();
    std::vector<std::uint8_t> joined;
    joined.reserve(total);
    for (auto& f : frames) {
        joined.insert(joined.end(), f.begin(), f.end());
    }
    session->do_send(joined);
    return GN_OK;
}

gn_result_t RawInjectLink::disconnect(gn_conn_id_t conn) {
    std::shared_ptr<Session> session;
    {
        std::lock_guard lk(sessions_mu_);
        auto it = sessions_.find(conn);
        if (it == sessions_.end()) return GN_OK;
        session = std::move(it->second);
        sessions_.erase(it);
    }
    session->do_close();
    return GN_OK;
}

void RawInjectLink::register_session(gn_conn_id_t id,
                                       std::shared_ptr<Session> s) {
    std::lock_guard lk(sessions_mu_);
    sessions_[id] = std::move(s);
    published_ids_.push_back(id);
}

bool RawInjectLink::claim_disconnect(gn_conn_id_t id) {
    std::lock_guard lk(sessions_mu_);
    if (shutdown_.load(std::memory_order_acquire)) return false;
    return sessions_.erase(id) > 0;
}

std::shared_ptr<RawInjectLink::Session>
RawInjectLink::find_session(gn_conn_id_t id) const {
    std::lock_guard lk(sessions_mu_);
    auto it = sessions_.find(id);
    return (it == sessions_.end()) ? nullptr : it->second;
}

void RawInjectLink::shutdown() {
    std::vector<gn_conn_id_t> ids_to_emit;
    {
        std::lock_guard lk(sessions_mu_);
        if (shutdown_.exchange(true, std::memory_order_acq_rel)) return;
        ids_to_emit = std::move(published_ids_);
        published_ids_.clear();
        for (auto& [id, s] : sessions_) s->do_close();
        sessions_.clear();
    }

    if (acceptor_) {
        std::error_code ec;
        (void)acceptor_->close(ec);
        acceptor_.reset();
    }

    if (api_ && api_->notify_disconnect) {
        for (const auto id : ids_to_emit) {
            (void)api_->notify_disconnect(api_->host_ctx, id, GN_OK);
        }
    }

    work_.reset();
    ioc_.stop();
    for (auto& w : workers_) {
        if (w.joinable()) w.join();
    }
    workers_.clear();
}

}  // namespace gn::link::raw_inject
