// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/errors.hpp
/// @brief  Typed exception wrapping `gn_result_t` with an actionable
///         hint per error code.
///
/// The C ABI returns plain `gn_result_t` integers. Beginner-facing
/// C++ apps that go through `sdk/cpp/core.hpp` get the same integers
/// re-thrown as an `Error` so the caller does not have to remember
/// every code on `sdk/types.h`. The error string carries the
/// context the wrapper had at the failure site (e.g. "gn_core_init"
/// or "install_identity_from_file($XDG_CONFIG_HOME/...)"), and
/// `hint()` returns a stable per-code one-liner that points at the
/// likely fix.
///
/// Implementation lives in `sdk/cpp/core.cpp` so the hint table is
/// out-of-line and shared across translation units.

#pragma once

#include <exception>
#include <string>
#include <string_view>

#include <sdk/types.h>

namespace gn::sdk {

/// Thrown by `Core` and friends when a kernel call fails. Plain
/// `std::exception` derivative; bindings that want a typed surface
/// pull `code()` and dispatch on it.
class Error : public std::exception {
public:
    /// @param code       The raw kernel result code.
    /// @param context    Free-form prefix added to `what()` so the
    ///                   caller can see at a glance which step
    ///                   failed (e.g. "gn_core_load_plugins_batch"
    ///                   or "install_identity_from_file:/path").
    Error(gn_result_t code, std::string_view context);

    [[nodiscard]] const char* what() const noexcept override {
        return msg_.c_str();
    }

    [[nodiscard]] gn_result_t code() const noexcept { return code_; }

    /// Actionable hint for the failure code — one short English
    /// sentence per `gn_result_t`. Stable across releases; new codes
    /// fall through to "unknown error".
    [[nodiscard]] std::string_view hint() const noexcept;

    /// Static accessor for the per-code hint table. Lets callers
    /// query the hint without constructing an `Error` (e.g. inside
    /// log formatters or test fixtures).
    [[nodiscard]] static std::string_view hint_for(gn_result_t code) noexcept;

private:
    gn_result_t code_;
    std::string msg_;
};

}  // namespace gn::sdk
