#[==========================================================[
goodnet_apply_pch — wire a project-wide precompiled-header umbrella
on @p target.

Targets the heavy headers that every kernel/plugin/test translation
unit pulls in: standalone Asio (each include is ~30 KLOC after
preprocessor expansion), spdlog/fmt, and the C++23 stdlib slice the
kernel-side code reaches for everywhere (vector / string / span /
memory / atomic / chrono / mutex). Without PCH each TU re-parses
the same ~50 KLOC; on this codebase that is ~30% of clean-build CPU
time.

Gated on `GOODNET_USE_PCH` so a developer chasing clang-tidy
diagnostics (PCH sometimes confuses tidy plugins that read
`compile_commands.json` directly) can opt out with one CLI flag.
]==========================================================]

function(goodnet_apply_pch target)
    if(NOT GOODNET_USE_PCH)
        return()
    endif()
    target_precompile_headers(${target} PRIVATE
        # Standalone Asio — single biggest header in the kernel build.
        <asio.hpp>
        # spdlog + fmt — every logging call site pulls these.
        <spdlog/spdlog.h>
        <fmt/format.h>
        # C++23 stdlib slices that show up in nearly every TU.
        <array>
        <atomic>
        <chrono>
        <cstdint>
        <cstring>
        <expected>
        <functional>
        <memory>
        <mutex>
        <optional>
        <shared_mutex>
        <span>
        <string>
        <string_view>
        <unordered_map>
        <vector>
    )
    # PCH pulls non-inline fmt symbols in lower-optimisation builds
    # (ASan/TSan compile at -O1, where fmt::vformat does not inline);
    # link the runtime libraries alongside the headers so every PCH
    # consumer has the symbols it ends up referencing.
    target_link_libraries(${target} PRIVATE
        asio::asio
        spdlog::spdlog
        fmt::fmt
    )
endfunction()
