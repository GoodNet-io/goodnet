// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/link_carrier.hpp
/// @brief  RAII wrapper around `gn.link.<scheme>` extension surface.
///
/// `gn::sdk::LinkCarrier` lets a composer plugin (WSS, TLS, ICE,
/// relay) talk to an L1 link without juggling raw `gn_link_api_t`
/// vtable pointers, C callback thunks, or subscription token cleanup.
///
/// Usage:
///
/// @code
/// auto carrier = gn::sdk::LinkCarrier::query(host_api, "tcp");
/// if (!carrier) return GN_ERR_NOT_FOUND;
///
/// (void)carrier->on_accept([](gn_conn_id_t c, std::string_view uri) {
///     // Got a new L1 conn; install a data cb and start handshake.
/// });
/// (void)carrier->listen("tcp://0.0.0.0:8080");
/// @endcode
///
/// Lifetime contract: every subscription installed through
/// `on_data` / `on_accept` is auto-removed on carrier destruction.
/// The lambdas hold their captures via `std::function`; the carrier
/// owns the storage so the captures outlive any in-flight callback
/// invocation (assumes the producer's `unsubscribe_*` waits for
/// in-flight callbacks to drain — see `link.en.md` §8).

#pragma once

#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <sdk/cpp/contract.hpp>
#include <sdk/cpp/uri.hpp>
#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

namespace gn::sdk {

class LinkCarrier {
public:
    using DataFn         = std::move_only_function<void(gn_conn_id_t,
                                                         std::span<const std::uint8_t>)>;
    using AcceptFn       = std::move_only_function<void(gn_conn_id_t, std::string_view)>;
    /// Optional per-subscriber accept filter. Return true to deliver the
    /// event to the paired AcceptFn; return false to skip this subscriber.
    /// A null (default) filter always passes.
    using AcceptFilterFn = std::move_only_function<bool(gn_conn_id_t, std::string_view)>;

    /// Look up `"gn.link.<scheme>"`, version `GN_EXT_LINK_VERSION`.
    /// Returns `nullopt` when the extension is absent or its version
    /// disagrees.
    [[nodiscard]] static std::optional<LinkCarrier>
    query(const host_api_t* api, std::string_view scheme) {
        if (!api || !api->query_extension_checked || scheme.empty()) {
            return std::nullopt;
        }
        std::string name;
        name.reserve(sizeof(GN_EXT_LINK_PREFIX) - 1 + scheme.size());
        name.append(GN_EXT_LINK_PREFIX, sizeof(GN_EXT_LINK_PREFIX) - 1);
        name.append(scheme);

        const void* raw = nullptr;
        const gn_result_t rc = api->query_extension_checked(
            api->host_ctx, name.c_str(), GN_EXT_LINK_VERSION, &raw);
        if (rc != GN_OK || raw == nullptr) {
            return std::nullopt;
        }
        return LinkCarrier(api, static_cast<const gn_link_api_t*>(raw));
    }

    LinkCarrier(const LinkCarrier&)            = delete;
    LinkCarrier& operator=(const LinkCarrier&) = delete;

    LinkCarrier(LinkCarrier&& o) noexcept { steal(std::move(o)); }
    LinkCarrier& operator=(LinkCarrier&& o) noexcept {
        if (this != &o) {
            release();
            steal(std::move(o));
        }
        return *this;
    }
    ~LinkCarrier() { release(); }

    [[nodiscard]] bool valid() const noexcept { return vt_ != nullptr; }

    /// Forward to `gn_link_api_t::listen`.
    [[nodiscard]] gn_result_t listen(std::string_view uri)
        GN_EXPECTS(!uri.empty())
    {
        if (!vt_ || !vt_->listen) return GN_ERR_INVALID_STATE;
        std::string z(uri);
        return vt_->listen(vt_->ctx, z.c_str());
    }

    /// Forward to `gn_link_api_t::connect`.
    [[nodiscard]] gn_result_t connect(std::string_view uri,
                                       gn_conn_id_t* out_conn)
        GN_EXPECTS(!uri.empty())
    {
        if (!vt_ || !vt_->connect) return GN_ERR_INVALID_STATE;
        std::string z(uri);
        return vt_->connect(vt_->ctx, z.c_str(), out_conn);
    }

    /// Forward to `gn_link_api_t::send`.
    [[nodiscard]] gn_result_t send(gn_conn_id_t conn,
                                    std::span<const std::uint8_t> bytes)
        GN_EXPECTS(!bytes.empty())
    {
        if (!vt_ || !vt_->send) return GN_ERR_INVALID_STATE;
        return vt_->send(vt_->ctx, conn, bytes.data(), bytes.size());
    }

    /// Forward to `gn_link_api_t::close`.
    [[nodiscard]] gn_result_t disconnect(gn_conn_id_t conn,
                                          int hard = 0) {
        if (!vt_ || !vt_->close) return GN_ERR_INVALID_STATE;
        return vt_->close(vt_->ctx, conn, hard);
    }

    /// Install a per-conn data callback. Replacing an existing cb on
    /// the same @p conn unsubscribes the prior cb first.
    [[nodiscard]] gn_result_t on_data(gn_conn_id_t conn, DataFn fn) {
        if (!vt_ || !vt_->subscribe_data) return GN_ERR_INVALID_STATE;
        if (!fn) return GN_ERR_NULL_ARG;
        auto holder = std::make_shared<DataFn>(std::move(fn));
        {
            std::lock_guard lk(mu_);
            auto it = data_cbs_.find(conn);
            if (it != data_cbs_.end() && vt_->unsubscribe_data) {
                (void)vt_->unsubscribe_data(vt_->ctx, conn);
            }
            data_cbs_[conn] = holder;
        }
        return vt_->subscribe_data(vt_->ctx, conn,
                                   &on_data_thunk, holder.get());
    }

    /// Remove the data callback installed for @p conn (if any).
    [[nodiscard]] gn_result_t unsubscribe_data(gn_conn_id_t conn) {
        if (!vt_) return GN_ERR_INVALID_STATE;
        std::shared_ptr<DataFn> drop;
        {
            std::lock_guard lk(mu_);
            auto it = data_cbs_.find(conn);
            if (it == data_cbs_.end()) return GN_OK;
            drop = std::move(it->second);
            data_cbs_.erase(it);
        }
        if (vt_->unsubscribe_data) {
            return vt_->unsubscribe_data(vt_->ctx, conn);
        }
        return GN_OK;
    }

    /// Query bound port of the active composer-listen acceptor. Used
    /// by composer plugins (WSS / TLS / ICE) to surface the underlying
    /// L1's ephemeral port through their own `listen_port()` after a
    /// `tcp://host:0`-style listen. Returns 0 when no composer-listen
    /// is active or the carrier link does not expose one.
    [[nodiscard]] std::uint16_t listen_port() const noexcept {
        if (!vt_ || !vt_->composer_listen_port) return 0;
        std::uint16_t port = 0;
        if (vt_->composer_listen_port(vt_->ctx, &port) != GN_OK) return 0;
        return port;
    }

    /// Install an accept-bus subscriber. Multiple `on_accept` calls
    /// stack — every subscriber whose optional @p filter passes is
    /// fired for every accept. @p filter may be null (always passes).
    ///
    /// Typical single-port usage:
    /// @code
    /// carrier->on_accept(
    ///     [this](gn_conn_id_t c, std::string_view) { handle(c); },
    ///     [port = my_port_](gn_conn_id_t, std::string_view uri) {
    ///         auto p = gn::parse_uri(uri);
    ///         return p && p->port == port;
    ///     });
    /// @endcode
    [[nodiscard]] gn_result_t on_accept(AcceptFn fn,
                                         AcceptFilterFn filter = {}) {
        if (!vt_ || !vt_->subscribe_accept) return GN_ERR_INVALID_STATE;
        if (!fn) return GN_ERR_NULL_ARG;
        auto entry = std::make_shared<AcceptEntry>(
            AcceptEntry{GN_INVALID_SUBSCRIPTION_ID,
                        std::make_shared<AcceptFn>(std::move(fn)),
                        filter ? std::make_shared<AcceptFilterFn>(std::move(filter))
                               : nullptr});
        gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
        const gn_result_t rc = vt_->subscribe_accept(
            vt_->ctx, &on_accept_thunk, entry.get(), &token);
        if (rc != GN_OK) return rc;
        entry->token = token;
        std::lock_guard lk(mu_);
        accept_cbs_.push_back(std::move(entry));
        return GN_OK;
    }

private:
    struct AcceptEntry {
        gn_subscription_id_t              token  = GN_INVALID_SUBSCRIPTION_ID;
        std::shared_ptr<AcceptFn>         fn;
        std::shared_ptr<AcceptFilterFn>   filter; // null = always pass
    };

    LinkCarrier(const host_api_t* api,
                const gn_link_api_t* vt) noexcept
        : api_(api), vt_(vt) {}

    void steal(LinkCarrier&& o) noexcept {
        api_         = o.api_;
        vt_          = o.vt_;
        data_cbs_    = std::move(o.data_cbs_);
        accept_cbs_  = std::move(o.accept_cbs_);
        o.api_ = nullptr;
        o.vt_  = nullptr;
    }

    void release() noexcept {
        if (!vt_) return;
        // unsubscribe accept-bus first so no new conns arrive mid-teardown
        if (vt_->unsubscribe_accept) {
            for (auto& e : accept_cbs_) {
                (void)vt_->unsubscribe_accept(vt_->ctx, e->token);
            }
        }
        accept_cbs_.clear();
        if (vt_->unsubscribe_data) {
            for (auto& [conn, _] : data_cbs_) {
                (void)vt_->unsubscribe_data(vt_->ctx, conn);
            }
        }
        data_cbs_.clear();
        api_ = nullptr;
        vt_  = nullptr;
    }

    static void on_data_thunk(void* user, gn_conn_id_t conn,
                              const std::uint8_t* bytes,
                              std::size_t size) noexcept {
        if (!user) return;
        auto* fn = static_cast<DataFn*>(user);
        try {
            (*fn)(conn, std::span<const std::uint8_t>(bytes, size));
        } catch (...) {}  // NOLINT(bugprone-empty-catch)
    }

    static void on_accept_thunk(void* user, gn_conn_id_t conn,
                                const char* peer_uri) noexcept {
        if (!user) return;
        auto* e = static_cast<AcceptEntry*>(user);
        const std::string_view sv = peer_uri ? std::string_view(peer_uri)
                                             : std::string_view{};
        if (e->filter && !(*e->filter)(conn, sv)) return;
        try { (*e->fn)(conn, sv); } catch (...) {}  // NOLINT(bugprone-empty-catch)
    }

    const host_api_t*    api_ = nullptr;
    const gn_link_api_t* vt_  = nullptr;

    mutable std::mutex mu_;
    std::unordered_map<gn_conn_id_t, std::shared_ptr<DataFn>>  data_cbs_;
    std::vector<std::shared_ptr<AcceptEntry>>                   accept_cbs_;
};

} // namespace gn::sdk
