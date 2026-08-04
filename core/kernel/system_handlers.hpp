/// @file   core/kernel/system_handlers.hpp
/// @brief  Kernel system handlers for identity-range msg_ids.
///
/// The kernel is the first handler (priority=255) on 0x11, 0x12, 0x13.
/// Registered at `gn_core_start()` for every active protocol via
/// `register_kernel_system_handlers`. This replaces the hardcoded
/// special-case branches that previously lived in `notify_inbound_bytes`.
///
/// See `docs/contracts/system-handlers.en.md` §1 and §2.

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include <sdk/handler.h>

namespace gn::core {

class Kernel;

/// Register the three kernel system handlers (attestation=0x11,
/// rotation=0x12, capability-blob=0x13) for every protocol_id in
/// @p protocol_ids at priority=255. Uses `allow_kernel_reserved = true`
/// so the registration-blocked check for 0x11 is bypassed.
///
/// Safe to call on every `build_topology()` invocation — including
/// `gn_core_reload_topology()`. Callers must first call
/// `unregister_kernel_system_handlers` with the previous set of ids
/// so old registrations are retired before the new ones land.
///
/// IDs are appended to @p out_ids. The stored `self` pointer is a
/// raw `Kernel*`; the kernel outlives all handler registrations by
/// contract (`gn_core_destroy` joins all in-flight dispatches before
/// returning).
void register_kernel_system_handlers(
    Kernel&                              kernel,
    const std::vector<std::string_view>& protocol_ids,
    std::vector<gn_handler_id_t>&        out_ids);

/// Unregister all kernel system handler ids in @p ids and clear the
/// vector. Safe to call with an empty vector.
void unregister_kernel_system_handlers(
    Kernel&                              kernel,
    std::vector<gn_handler_id_t>&        ids);

} // namespace gn::core
