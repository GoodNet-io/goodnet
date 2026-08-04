// SPDX-License-Identifier: MIT
/// @file   sdk/cpp/cpu_affinity.hpp
/// @brief  Build a `cpu_set_t` from a user-supplied mask string.
///
/// Supported masks:
///   "p-cores"  — auto-detect CPUs with the highest cpuinfo_max_freq;
///                on hybrid CPUs these are the P-cores.
///   "all"      — no affinity pin (nullptr returned).
///   "0,2,4,6"  — explicit CPU index list.
///   nullptr    — same as "all".

#pragma once

#ifndef __EMSCRIPTEN__
#include <sched.h>
#endif
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string_view>
#include <vector>

namespace gn::sdk {

#ifndef __EMSCRIPTEN__

namespace detail {

inline std::vector<int> detect_p_cores() noexcept {
    unsigned long max_freq = 0;
    struct Entry { int cpu; unsigned long freq; };
    std::vector<Entry> entries;
    for (int cpu = 0; cpu < 1024; ++cpu) {
        char path[128];
        std::snprintf(path, sizeof(path),
            "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", cpu);
        std::ifstream f(path);
        if (!f) break;
        unsigned long freq = 0;
        f >> freq;
        entries.push_back({cpu, freq});
        if (freq > max_freq) max_freq = freq;
    }
    std::vector<int> result;
    for (const auto& e : entries) {
        if (e.freq == max_freq) result.push_back(e.cpu);
    }
    return result;
}

} // namespace detail

/// Build an affinity mask from @p mask and write it into @p cs.
/// Returns a pointer to @p cs when affinity should be applied,
/// or nullptr when no pinning is requested.
[[nodiscard]] inline const cpu_set_t*
build_cpu_affinity(const char* mask, cpu_set_t* cs) noexcept {
    if (!mask || mask[0] == '\0') return nullptr;
    const std::string_view sv{mask};
    if (sv == "all") return nullptr;

    CPU_ZERO(cs);

    if (sv == "p-cores") {
        const auto cpus = detail::detect_p_cores();
        if (cpus.empty()) return nullptr;
        for (int c : cpus) CPU_SET(c, cs);
        return cs;
    }

    // Parse explicit comma-separated list "0,2,4,6".
    bool any = false;
    const char* p = mask;
    while (*p) {
        char* end = nullptr;
        int cpu = static_cast<int>(std::strtol(p, &end, 10));
        if (end == p) break;
        CPU_SET(cpu, cs);
        any = true;
        p = end;
        if (*p == ',') ++p;
    }
    return any ? cs : nullptr;
}

#else // __EMSCRIPTEN__

[[nodiscard]] inline const void*
build_cpu_affinity(const char*, void*) noexcept { return nullptr; }

#endif // __EMSCRIPTEN__

} // namespace gn::sdk
