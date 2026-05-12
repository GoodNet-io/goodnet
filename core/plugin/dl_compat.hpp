/// @file   core/plugin/dl_compat.hpp
/// @brief  Tiny libdl ↔ Win32 LoadLibrary shim so the plugin
///         manager builds on mingw without dragging in `dlfcn-win32`.
///
/// On POSIX targets this is just `<dlfcn.h>`; on Windows the shim
/// translates `dlopen` / `dlsym` / `dlclose` / `dlerror` into
/// `LoadLibraryA` / `GetProcAddress` / `FreeLibrary` /
/// `GetLastError`. The flags `RTLD_NOW` and `RTLD_LOCAL` collapse
/// to no-ops because Windows always resolves all imports at load
/// time and never exports symbols globally.
#ifndef GOODNET_CORE_PLUGIN_DL_COMPAT_HPP
#define GOODNET_CORE_PLUGIN_DL_COMPAT_HPP

#ifdef _WIN32
#  include <windows.h>
#  include <cstdio>

#  ifndef RTLD_NOW
#    define RTLD_NOW   0
#  endif
#  ifndef RTLD_LOCAL
#    define RTLD_LOCAL 0
#  endif
#  ifndef RTLD_LAZY
#    define RTLD_LAZY  0
#  endif

namespace gn::core::detail {

inline void* dlopen_compat(const char* path, int /*flag*/) noexcept {
    return reinterpret_cast<void*>(::LoadLibraryA(path));
}

inline int dlclose_compat(void* handle) noexcept {
    return ::FreeLibrary(reinterpret_cast<HMODULE>(handle)) ? 0 : -1;
}

inline void* dlsym_compat(void* handle, const char* name) noexcept {
    return reinterpret_cast<void*>(::GetProcAddress(
        reinterpret_cast<HMODULE>(handle), name));
}

inline const char* dlerror_compat() noexcept {
    static thread_local char buf[256];
    const DWORD err = ::GetLastError();
    std::snprintf(buf, sizeof(buf),
        "Win32 LoadLibrary error: 0x%08lx",
        static_cast<unsigned long>(err));
    return buf;
}

} // namespace gn::core::detail

#  define dlopen   ::gn::core::detail::dlopen_compat
#  define dlclose  ::gn::core::detail::dlclose_compat
#  define dlsym    ::gn::core::detail::dlsym_compat
#  define dlerror  ::gn::core::detail::dlerror_compat
#else
#  include <dlfcn.h>
#endif

#endif // GOODNET_CORE_PLUGIN_DL_COMPAT_HPP