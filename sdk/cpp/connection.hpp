// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/connection.hpp
/// @brief  RAII handle for a single composer-owned connection.
///
/// `gn::sdk::Connection` wraps a `(LinkCarrier&, gn_conn_id_t)` pair
/// and owns the lifecycle: the destructor disconnects the conn and
/// drops the data subscription. The intent is to close the DX gap
/// around manual `conn_id` tracking documented in
/// `docs/architecture/strategies.ru.md` audit (2026-05-12):
///
///   ❌ before — caller drags `gn_conn_id_t` + carrier reference
///       through every send site, must remember to unsubscribe +
///       disconnect on every error path.
///
///   ✅ after — `auto conn = carrier.connect_managed(uri); conn.send(...)`.
///       Connection goes out of scope, carrier disconnects.
///
/// Connection is **move-only**; copying a conn id would let two
/// owners race the disconnect. Move semantics keep the carrier
/// reference stable and zero the source's `id_` so its dtor no-ops.
///
/// **Limitations** (Tier 1 scope):
///   * No `on_close` lambda — needs an ABI slot the carrier doesn't
///     yet have. Tier 2 adds it via `subscribe_conn_state` filter.
///   * `send` reflects the underlying carrier's contract: returns
///     after enqueue, not after wire-ACK. Same caveat as raw
///     `LinkCarrier::send`.

#pragma once

#include <cstdint>
#include <functional>
#include <span>
#include <utility>

#include <sdk/cpp/link_carrier.hpp>
#include <sdk/types.h>

namespace gn::sdk {

class Connection {
public:
    using DataFn = std::function<void(std::span<const std::uint8_t>)>;

    /// Adopt an existing conn id on @p carrier. The carrier reference
    /// must outlive this Connection — typical usage is with a carrier
    /// stored next to it (same class member, lambda capture, etc.).
    Connection(LinkCarrier& carrier, gn_conn_id_t id) noexcept
        : carrier_(&carrier), id_(id) {}

    /// Null state — used as a placeholder before `connect_to` populates
    /// the slot, or when a query returns `nullopt`.
    Connection() noexcept = default;

    Connection(const Connection&)            = delete;
    Connection& operator=(const Connection&) = delete;

    Connection(Connection&& o) noexcept
        : carrier_(o.carrier_), id_(o.id_) {
        o.carrier_ = nullptr;
        o.id_      = GN_INVALID_ID;
    }
    Connection& operator=(Connection&& o) noexcept {
        if (this != &o) {
            close();
            carrier_   = o.carrier_;
            id_        = o.id_;
            o.carrier_ = nullptr;
            o.id_      = GN_INVALID_ID;
        }
        return *this;
    }

    ~Connection() { close(); }

    [[nodiscard]] gn_conn_id_t id() const noexcept { return id_; }
    [[nodiscard]] bool valid() const noexcept {
        return carrier_ != nullptr && id_ != GN_INVALID_ID;
    }
    [[nodiscard]] LinkCarrier* carrier() const noexcept { return carrier_; }

    /// Send bytes through the underlying carrier. Same semantics as
    /// `LinkCarrier::send`. Returns `GN_ERR_INVALID_STATE` on a
    /// closed / moved-from connection.
    [[nodiscard]] gn_result_t send(std::span<const std::uint8_t> bytes) {
        if (!valid()) return GN_ERR_INVALID_STATE;
        return carrier_->send(id_, bytes);
    }

    /// Install / replace the data callback. The lambda receives
    /// inbound bytes only — no conn id, since this Connection
    /// represents exactly one id. Pass `nullptr` to detach.
    [[nodiscard]] gn_result_t on_data(DataFn cb) {
        if (!valid()) return GN_ERR_INVALID_STATE;
        if (!cb) return carrier_->unsubscribe_data(id_);
        const gn_conn_id_t this_id = id_;
        return carrier_->on_data(
            id_,
            [shared = std::move(cb), this_id](
                gn_conn_id_t c,
                std::span<const std::uint8_t> bytes) {
                if (c == this_id) shared(bytes);
            });
    }

    /// Explicit disconnect. Idempotent — second call no-ops. After
    /// this returns the Connection is in the null state and `send`
    /// fails with `INVALID_STATE`.
    gn_result_t close() noexcept {
        if (!carrier_ || id_ == GN_INVALID_ID) return GN_OK;
        const gn_conn_id_t id = id_;
        auto* carrier = carrier_;
        id_      = GN_INVALID_ID;
        carrier_ = nullptr;
        (void)carrier->unsubscribe_data(id);
        return carrier->disconnect(id);
    }

    /// Release the conn without disconnecting — returns the id and
    /// nulls this Connection. Caller takes manual ownership again.
    /// Useful when handing off to an FSM that wants raw conn ids.
    [[nodiscard]] gn_conn_id_t release() noexcept {
        const gn_conn_id_t id = id_;
        id_      = GN_INVALID_ID;
        carrier_ = nullptr;
        return id;
    }

private:
    LinkCarrier*  carrier_ = nullptr;
    gn_conn_id_t  id_      = GN_INVALID_ID;
};

}  // namespace gn::sdk
