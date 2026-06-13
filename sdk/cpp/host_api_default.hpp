// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/host_api_default.hpp
/// @brief  Process-wide singleton accessor for a default-constructed
///         `gn::sdk::Core` — the one-liner shape pre-rc examples used.
///
/// Most non-trivial apps want explicit `Core` lifetimes (test
/// isolation, multiple kernels in one binary, identity pinning).
/// But trivial demos and one-line scripts ("install a single
/// subscription, send something, exit") were one function call
/// before the rc rewrite and the public-C-ABI lifecycle made them
/// long. `host_api_default()` restores the one-liner: the first
/// call lazily constructs a `Core` with XDG defaults; subsequent
/// calls return the same `host_api_t*`.
///
/// Lifetime: the singleton lives for the duration of the program.
/// The dtor runs on normal exit through static-storage cleanup;
/// signal-handler exits skip it (same shape as every C++ static).
///
/// Use for one-shot demos / scripts only. Any real application
/// instantiates `Core` explicitly so the lifecycle is visible at
/// the call site.

#pragma once

#include <sdk/host_api.h>

namespace gn::sdk {

/// Returns a `host_api_t*` for the process-wide default `Core`.
/// First call performs the XDG-default construction (and may throw
/// `Error` if the manifest / identity is malformed). Subsequent
/// calls return the same pointer. Thread-safe via
/// `std::call_once`.
host_api_t* host_api_default();

}  // namespace gn::sdk
