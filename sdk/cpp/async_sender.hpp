// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/async_sender.hpp
/// @brief  P2300 sender wrapper around the synchronous host_api send vtable.
///
/// Exposes `gn::sdk::gn_send_sender(api, conn, msg_id, payload)` —
/// a lazy `stdexec::sender` that, when started, calls `api->send` and
/// completes with the resulting `gn_result_t`.  Because the underlying
/// vtable call is synchronous the sender completes inline on the calling
/// scheduler; no allocation occurs.
///
/// Typical use inside a P2300 chain:
/// @code
///   exec::start_detached(
///       gn::sdk::gn_send_sender(api, conn, kMsgId, payload)
///       | stdexec::then([](gn_result_t r) noexcept {
///             if (r != GN_OK) { /* handle */ }
///         })
///   );
/// @endcode
///
/// The span @p payload must remain valid for the duration of the `then`
/// callback — in practice until the sender is started (synchronous
/// completion guarantees this is the same call frame).

#pragma once

#ifndef __EMSCRIPTEN__

#include <stdexec/execution.hpp>

#include <sdk/cpp/convenience.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include <cstdint>
#include <span>

namespace gn::sdk {

/// Returns a P2300 sender that calls `api->send` and completes with
/// `gn_result_t`.  The sender has no scheduler affinity — it runs
/// inline on whichever execution context starts it.
[[nodiscard]] inline auto gn_send_sender(
    const host_api_t*             api,
    gn_conn_id_t                  conn,
    std::uint32_t                 msg_id,
    std::span<const std::uint8_t> payload) noexcept
{
    return stdexec::just()
        | stdexec::then([api, conn, msg_id, payload]() noexcept -> gn_result_t {
            return gn::send(api, conn, msg_id, payload);
        });
}

} // namespace gn::sdk

#endif // __EMSCRIPTEN__
