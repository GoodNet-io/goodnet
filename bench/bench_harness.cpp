// SPDX-License-Identifier: Apache-2.0
/// @file   bench/bench_harness.cpp
/// @brief  Out-of-line definitions for the bench harness.
///
/// The harness is header-only for the most part — `BenchKernel`,
/// `RoundTripMeter`, and `ResourceCounters` live inline so each
/// per-plugin bench gets the same templated optimisation surface
/// at compile time. This translation unit exists so the harness
/// has its own object file (avoids ODR-style duplication when
/// multiple bench binaries link against the same headers) and so
/// future stateful helpers (file-scoped statics, plugin-load
/// caches) have a home.

#include "bench_harness.hpp"

namespace gn::bench {

// Reserved for follow-up stateful helpers (PluginLoader cache,
// shared latency aggregator, etc.). Intentionally empty so the
// library object exists in the build.

}  // namespace gn::bench
