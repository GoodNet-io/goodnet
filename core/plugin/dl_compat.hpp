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
///
/// WASI / Emscripten path: WASI 1.0 has no `dlopen` (preview2 ships
/// an experimental component-model loader that the kernel does not
/// integrate against). Browser-side Emscripten with `MAIN_MODULE` /
/// `SIDE_MODULE` can do dynamic linking but is out of scope for
/// the kernel-core cross-build. Both platforms get a stub that
/// fails every call cleanly so the calling code returns
/// `GN_ERR_NOT_FOUND` instead of dragging in a libdl link
/// dependency that the wasi-sysroot does not provide.
#ifndef GOODNET_CORE_PLUGIN_DL_COMPAT_HPP
#define GOODNET_CORE_PLUGIN_DL_COMPAT_HPP

#if defined(__wasi__) || defined(__EMSCRIPTEN__)
// WASI / Emscripten: no `dlopen`. The dynamic-runtime TU is
// excluded from the WASM kernel-core sources at the build-system
// layer (see `nix/goodnet-wasm.nix`); this stub keeps the header
// pre-processable for any TU that transitively pulls it in so the
// kernel surface compiles even when callers don't fully tree-shake.
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

inline void* dlopen_compat(const char*, int) noexcept { return nullptr; }
inline int   dlclose_compat(void*)         noexcept { return -1; }
inline void* dlsym_compat(void*, const char*) noexcept { return nullptr; }
inline const char* dlerror_compat() noexcept {
    return "dlopen unavailable on WASI / Emscripten";
}

} // namespace gn::core::detail

#  define dlopen   ::gn::core::detail::dlopen_compat
#  define dlclose  ::gn::core::detail::dlclose_compat
#  define dlsym    ::gn::core::detail::dlsym_compat
#  define dlerror  ::gn::core::detail::dlerror_compat
#elif defined(_WIN32)
// `<windows.h>` pulls in the legacy `<winsock.h>` by default. Asio's
// `socket_types.hpp` requires `<winsock2.h>` and trips on the legacy
// header being present. WIN32_LEAN_AND_MEAN tells the SDK headers to
// skip winsock.h; asio still gets to drag in winsock2.h on its own.
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
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