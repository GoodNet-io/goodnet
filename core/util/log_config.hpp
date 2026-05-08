// SPDX-License-Identifier: Apache-2.0
/// @file   core/util/log_config.hpp
/// @brief  Free function that materialises `gn::log::LogConfig`
///         from the kernel's runtime config.
///
/// `Kernel::apply_log_config` used to walk eleven `log.*` keys
/// inline; the walk has nothing kernel-specific in it and was
/// the only block in `Kernel` that named `gn::log::LogConfig`
/// directly. Hoisting the helper here lets the kernel call site
/// stay two lines and keeps the namespace mapping (which keys
/// fold into which struct field) localised in one TU.

#pragma once

#include <core/util/log.hpp>

namespace gn::core {

class Config;  // core/config/config.hpp

}  // namespace gn::core

namespace gn::core::util {

/// Materialise a `gn::log::LogConfig` from @p cfg by reading
/// the `log.*` namespace. Missing keys leave the corresponding
/// field at its `LogConfig` default; out-of-range numeric
/// values are silently ignored — the same shape the inline
/// version had inside `Kernel`.
[[nodiscard]] gn::log::LogConfig load_log_config(const gn::core::Config& cfg);

}  // namespace gn::core::util
