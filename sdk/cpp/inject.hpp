// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/inject.hpp
/// @brief  Thin wrappers around `host_api->inject` for plugin authors.
///
/// Every plugin that decompresses or bridges data calls `inject` with
/// the same boilerplate: convert `string_view` → NUL-terminated string,
/// guard against null api, cast span to pointer+size. These helpers
/// eliminate that pattern.
///
/// ## Usage
///
/// ```cpp
/// // Instead of:
/// const std::string ns(target_ns);
/// if (!api || !api->inject) return GN_ERR_NOT_IMPLEMENTED;
/// return api->inject(api->host_ctx, GN_INJECT_LAYER_MESSAGE,
///                    source, ns.c_str(), msg_id,
///                    payload.data(), payload.size());
///
/// // Write:
/// return gn::sdk::inject_message(api, source, target_ns, msg_id, payload);
/// ```
///
/// ## Inject depth
///
/// Each `inject_message` / `inject_frame` call fires a new synchronous
/// handler-dispatch pass on the calling thread. The kernel enforces a
/// maximum chain depth (`gn_limits_t::max_inject_depth`, default
/// `GN_INJECT_MAX_DEPTH = 5`) and returns `GN_ERR_LIMIT_REACHED` when
/// exceeded. Declare static inject dependencies via
/// `static constexpr gn_inject_dep_t inject_targets[]` in your handler
/// class so the load-time cycle detector can catch loops before any
/// handler is invoked.

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include <sdk/host_api.h>
#include <sdk/types.h>
#include <sdk/cpp/contract.hpp>

namespace gn::sdk {

/// Inject a fully-framed message into the kernel's handler dispatch.
///
/// Equivalent to `host_api->inject(GN_INJECT_LAYER_MESSAGE, ...)`.
/// The kernel validates `msg_id` (must be non-zero, non-reserved),
/// applies the rate limiter, and routes the envelope through the
/// handler chain registered under @p target_ns.
///
/// @param api        Host API from the plugin's `on_init`.
/// @param source     Connection ID the injected message appears to come from.
/// @param target_ns  Protocol namespace to route into (e.g. `"gnet-v1"`).
/// @param msg_id     Non-zero, non-reserved message type.
/// @param payload    Application payload bytes.
/// @return GN_OK on success; GN_ERR_LIMIT_REACHED if inject depth exceeded.
[[nodiscard]] inline gn_result_t inject_message(
    const host_api_t* api,
    gn_conn_id_t source,
    std::string_view target_ns,
    std::uint32_t msg_id,
    std::span<const std::uint8_t> payload) noexcept
{
    if (!api || !api->inject) return GN_ERR_NOT_IMPLEMENTED;
    if (target_ns.empty()) return GN_ERR_INVALID_ENVELOPE;
    const std::string ns(target_ns);
    return api->inject(api->host_ctx,
                       GN_INJECT_LAYER_MESSAGE,
                       source,
                       ns.c_str(),
                       msg_id,
                       payload.data(),
                       payload.size());
}

/// Inject a raw wire frame into the kernel's deframer + handler dispatch.
///
/// Equivalent to `host_api->inject(GN_INJECT_LAYER_FRAME, ...)`.
/// The kernel deframes @p frame using the protocol layer associated with
/// @p source, filters reserved msg_ids, and routes each envelope through
/// the handler chain registered under @p target_ns.
///
/// @param api        Host API from the plugin's `on_init`.
/// @param source     Connection ID the frame appears to arrive on.
/// @param target_ns  Protocol namespace to route into.
/// @param frame      Raw wire frame bytes (non-empty).
/// @return GN_OK on success; GN_ERR_LIMIT_REACHED if inject depth exceeded.
[[nodiscard]] inline gn_result_t inject_frame(
    const host_api_t* api,
    gn_conn_id_t source,
    std::string_view target_ns,
    std::span<const std::uint8_t> frame) noexcept
{
    if (!api || !api->inject) return GN_ERR_NOT_IMPLEMENTED;
    if (target_ns.empty()) return GN_ERR_INVALID_ENVELOPE;
    if (frame.empty()) return GN_ERR_NULL_ARG;
    const std::string ns(target_ns);
    return api->inject(api->host_ctx,
                       GN_INJECT_LAYER_FRAME,
                       source,
                       ns.c_str(),
                       0,
                       frame.data(),
                       frame.size());
}

} // namespace gn::sdk
