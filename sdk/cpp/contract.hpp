// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/contract.hpp
/// @brief  Portable contract annotation macros.
///
/// In C++26 builds with `-fcontracts` the macros expand to `[[expects:]]` /
/// `[[ensures result:]]` attributes — the compiler inserts checks in audit
/// mode and elides them in release.  In C++23 or without the flag the macros
/// expand to nothing; runtime guards in the annotated functions remain as the
/// fallback.

#pragma once

#if defined(__cpp_contracts) && __cpp_contracts >= 202502L
#  define GN_EXPECTS(cond) [[expects: cond]]
#  define GN_ENSURES(cond) [[ensures result: cond]]
#else
#  define GN_EXPECTS(cond)
#  define GN_ENSURES(cond)
#endif
