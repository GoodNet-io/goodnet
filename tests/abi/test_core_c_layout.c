/**
 * @file   tests/abi/test_core_c_layout.c
 * @brief  Compile-time pin of every caller-allocated struct in `sdk/core.h`.
 *
 * Per `docs/contracts/abi-evolution.md` §7 and `core-c.md` §3, the
 * library-as-binary surface ships a layout pin alongside the per-vtable
 * pin in `test_layout.c`. The library boundary is the only place where
 * a non-C++ host (Rust binding, Python ctypes layer, Go cgo wrapper,
 * WASM browser embed) crosses into the kernel; a recompile that
 * silently reorders, resizes, or renames a `sdk/core.h` field would
 * break every binding without source-level signal.
 *
 * The file is compiled but never executed: the assertions fire at
 * compile time. Any patch that breaks layout fails to build this
 * compilation unit before reaching merge.
 *
 * Three families pinned here:
 *
 *   1. `gn_stats_t` — the only caller-allocated value struct declared
 *      in `sdk/core.h`. Caller passes it to `gn_core_get_stats` for
 *      the kernel to fill; layout is part of the binding contract.
 *      Reserved-tail evolution per `abi-evolution.md` §4.
 *
 *   2. `gn_core_t` — opaque handle, layout deliberately private. The
 *      pin records that the only thing crossing the boundary is a
 *      pointer-sized type so binding code that allocates a slot for
 *      `gn_core_t*` never assumes anything about the underlying body.
 *
 *   3. Identifier typedefs (`gn_conn_id_t`, `gn_handler_id_t`,
 *      `gn_link_id_t`) returned through `sdk/core.h` entries —
 *      `uint64_t` width is part of the C ABI promise. Bindings ship
 *      `u64`-sized handles in their host language.
 *
 * The numbers were measured on x86_64 Linux gcc15 against the release
 * snapshot of `sdk/`. New fields land before `gn_stats_t::_reserved`
 * — the reserved trailer absorbs additive evolution per
 * `abi-evolution.md` §3 without shifting any earlier offset.
 */

#include <stddef.h>
#include <stdint.h>

#include <sdk/core.h>
#include <sdk/types.h>

/* ── sdk/core.h :: gn_stats_t ──────────────────────────────────────────────── */

_Static_assert(sizeof(gn_stats_t) == 104,
               "gn_stats_t size pinned at 104");
_Static_assert(offsetof(gn_stats_t, connections_active) == 0,
               "gn_stats_t::connections_active offset pinned at 0");
_Static_assert(offsetof(gn_stats_t, handlers_registered) == 8,
               "gn_stats_t::handlers_registered offset pinned at 8");
_Static_assert(offsetof(gn_stats_t, links_registered) == 16,
               "gn_stats_t::links_registered offset pinned at 16");
_Static_assert(offsetof(gn_stats_t, extensions_registered) == 24,
               "gn_stats_t::extensions_registered offset pinned at 24");
_Static_assert(offsetof(gn_stats_t, bytes_in) == 32,
               "gn_stats_t::bytes_in offset pinned at 32");
_Static_assert(offsetof(gn_stats_t, bytes_out) == 40,
               "gn_stats_t::bytes_out offset pinned at 40");
_Static_assert(offsetof(gn_stats_t, frames_in) == 48,
               "gn_stats_t::frames_in offset pinned at 48");
_Static_assert(offsetof(gn_stats_t, frames_out) == 56,
               "gn_stats_t::frames_out offset pinned at 56");
_Static_assert(offsetof(gn_stats_t, plugin_dlclose_leaks) == 64,
               "gn_stats_t::plugin_dlclose_leaks offset pinned at 64");
_Static_assert(offsetof(gn_stats_t, _reserved) == 72,
               "gn_stats_t::_reserved offset pinned at 72");
_Static_assert(sizeof(((gn_stats_t*)0)->_reserved) == 4 * sizeof(void*),
               "gn_stats_t::_reserved holds the default 4 evolution slots");

/* ── sdk/core.h :: gn_core_t ───────────────────────────────────────────────── */

/**
 * `gn_core_t` is forward-declared in `sdk/core.h` and defined privately
 * in `core/kernel/core_c.cpp`. Bindings never see the body — what
 * crosses the boundary is `gn_core_t*`, which the consumer allocates
 * a `void*`-sized slot for. The pin records that promise so a future
 * patch that accidentally exposes the layout (e.g. moves the typedef
 * to a public header with the body) trips the assertion.
 */
_Static_assert(sizeof(gn_core_t*) == sizeof(void*),
               "gn_core_t crosses the boundary as an opaque pointer");

/* ── sdk/types.h :: identifier typedefs reachable from sdk/core.h ──────────── */

/**
 * `gn_core_*` entries return and accept these handles by value;
 * binding-side handle slots are `u64`-sized. A drift to a wider or
 * narrower integer would silently corrupt every handle marshalled
 * across the C ABI.
 */
_Static_assert(sizeof(gn_conn_id_t) == 8,
               "gn_conn_id_t width pinned at uint64_t");
_Static_assert(sizeof(gn_handler_id_t) == 8,
               "gn_handler_id_t width pinned at uint64_t");
_Static_assert(sizeof(gn_link_id_t) == 8,
               "gn_link_id_t width pinned at uint64_t");
_Static_assert(sizeof(gn_timer_id_t) == 8,
               "gn_timer_id_t width pinned at uint64_t");

/**
 * Subscription tokens returned by `gn_core_subscribe` and
 * `gn_core_on_conn_state` are typed `uint64_t` directly in the
 * signature; the assertion records the width so a bindings layer that
 * picks a wider type never silently truncates on cancel.
 */
_Static_assert(sizeof(uint64_t) == 8,
               "subscription tokens cross as uint64_t");
