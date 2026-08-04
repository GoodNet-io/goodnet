// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/security_plugin.hpp
/// @brief  `GN_SECURITY_PLUGIN(Class, "plugin_name", "version")` —
///         collapses single-provider security plugin boilerplate into
///         one macro instantiation.
///
/// What the macro generates:
///   1. Five `gn_plugin_*` extern "C" entry points.
///   2. `gn_security_provider_vtable_t` with thunks bridging the C
///      ABI to the class's method shapes.
///   3. Auto-populated `provides_flags` and `allowed_trust_mask` slots
///      when the class defines matching `static constexpr` members.
///   4. `gn_plugin_descriptor_t` with kind = `GN_PLUGIN_KIND_SECURITY`.
///
/// ## Class concept
///
/// ```cpp
/// class MyProvider {
/// public:
///     explicit MyProvider(const host_api_t* api);
///
///     static constexpr const char* provider_id() { return "my-provider"; }
///
///     /// Optional — auto-wired via if constexpr when present:
///     static constexpr uint32_t provides_flags() {
///         return GN_SEC_PROVIDES_E2E_ENCRYPTION | ...;
///     }
///     static constexpr uint32_t allowed_trust_mask() {
///         return (1u << GN_TRUST_PEER) | (1u << GN_TRUST_UNTRUSTED);
///     }
///
///     gn_result_t handshake_open(gn_conn_id_t conn,
///                                gn_trust_class_t trust,
///                                gn_handshake_role_t role,
///                                const uint8_t* local_sk,
///                                const uint8_t* local_pk,
///                                const uint8_t* remote_pk,
///                                void** out_state);
///     gn_result_t handshake_step(void* state,
///                                const uint8_t* in, size_t in_sz,
///                                gn_secure_buffer_t* out);
///     int         handshake_complete(void* state);
///     gn_result_t export_transport_keys(void* state,
///                                       gn_handshake_keys_t* out);
///     gn_result_t encrypt(void* state,
///                         const uint8_t* pt, size_t pt_sz,
///                         gn_secure_buffer_t* out);
///     gn_result_t decrypt(void* state,
///                         const uint8_t* ct, size_t ct_sz,
///                         gn_secure_buffer_t* out);
///     gn_result_t rekey(void* state);
///     void        handshake_close(void* state);
/// };
/// ```

#pragma once

#include <cstdint>
#include <memory>
#include <new>
#include <type_traits>

#include <sdk/abi.h>
#include <sdk/cpp/contract.hpp>
#include <sdk/cpp/dispatcher.hpp>
#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/security.h>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::sdk::detail {

template <class T>
struct SecurityPluginInstance {
    const host_api_t*  api      = nullptr;
    void*              host_ctx = nullptr;
    std::unique_ptr<T> provider;
};

} // namespace gn::sdk::detail

// ---------------------------------------------------------------------------
// Helper: cast vtable `self` to the wrapped provider instance.
// Lives inside the macro's anonymous namespace so two security plugins
// loaded simultaneously each get their own typed specialisation.
// ---------------------------------------------------------------------------

/// Expand to one fully-specified security plugin.
///
/// @param Class          C++ class implementing the concept above.
/// @param NameStrLiteral Plugin name string literal, e.g. `"gn-security-noise"`.
/// @param VerStrLiteral  SemVer string literal, e.g. `"0.1.0"`.
#define GN_SECURITY_PLUGIN(Class, NameStrLiteral, VerStrLiteral)               \
    namespace {                                                                 \
                                                                               \
    using _gn_sec_inst_t = ::gn::sdk::detail::SecurityPluginInstance<Class>;  \
                                                                               \
    inline Class& _gn_sec_of(void* s) noexcept {                              \
        return *static_cast<_gn_sec_inst_t*>(s)->provider;                    \
    }                                                                          \
                                                                               \
    static constexpr const char _gn_sec_plugin_name[] = NameStrLiteral;       \
                                                                               \
    gn_security_provider_vtable_t _gn_sec_make_vtable() noexcept {            \
        gn_security_provider_vtable_t v{};                                    \
        v.api_size = sizeof(gn_security_provider_vtable_t);                   \
                                                                               \
        v.provider_id = [](void*) noexcept -> const char* {                   \
            return Class::provider_id();                                       \
        };                                                                     \
                                                                               \
        v.handshake_open = [](void* s, gn_conn_id_t conn,                     \
                               gn_trust_class_t trust,                        \
                               gn_handshake_role_t role,                      \
                               const uint8_t* lsk, const uint8_t* lpk,        \
                               const uint8_t* rpk,                            \
                               void** out) noexcept -> gn_result_t {          \
            return _gn_sec_of(s).handshake_open(conn, trust, role,            \
                                                lsk, lpk, rpk, out);          \
        };                                                                     \
                                                                               \
        v.handshake_step = [](void* s, void* state,                           \
                               const uint8_t* in, size_t insz,                \
                               gn_secure_buffer_t* out) noexcept              \
                               -> gn_result_t {                               \
            return _gn_sec_of(s).handshake_step(state, in, insz, out);        \
        };                                                                     \
                                                                               \
        v.handshake_complete = [](void* s, void* state) noexcept -> int {     \
            return _gn_sec_of(s).handshake_complete(state);                   \
        };                                                                     \
                                                                               \
        v.export_transport_keys = [](void* s, void* state,                    \
                                      gn_handshake_keys_t* out) noexcept      \
                                      -> gn_result_t {                        \
            return _gn_sec_of(s).export_transport_keys(state, out);           \
        };                                                                     \
                                                                               \
        v.encrypt = [](void* s, void* state,                                  \
                        const uint8_t* pt, size_t psz,                        \
                        gn_secure_buffer_t* out) noexcept -> gn_result_t {    \
            return _gn_sec_of(s).encrypt(state, pt, psz, out);                \
        };                                                                     \
                                                                               \
        v.decrypt = [](void* s, void* state,                                  \
                        const uint8_t* ct, size_t csz,                        \
                        gn_secure_buffer_t* out) noexcept -> gn_result_t {    \
            return _gn_sec_of(s).decrypt(state, ct, csz, out);                \
        };                                                                     \
                                                                               \
        v.rekey = [](void* s, void* state) noexcept -> gn_result_t {         \
            return _gn_sec_of(s).rekey(state);                                \
        };                                                                     \
                                                                               \
        v.handshake_close = [](void* s, void* state) noexcept {              \
            _gn_sec_of(s).handshake_close(state);                             \
        };                                                                     \
                                                                               \
        v.destroy = [](void* s) noexcept {                                    \
            delete static_cast<_gn_sec_inst_t*>(s);                           \
        };                                                                     \
                                                                               \
        if constexpr (requires {                                               \
            { Class::allowed_trust_mask() }                                    \
                -> std::convertible_to<std::uint32_t>;                        \
        }) {                                                                   \
            v.allowed_trust_mask = [](void*) noexcept -> std::uint32_t {      \
                return Class::allowed_trust_mask();                            \
            };                                                                 \
        }                                                                      \
                                                                               \
        if constexpr (requires {                                               \
            { Class::provides_flags() }                                        \
                -> std::convertible_to<std::uint32_t>;                        \
        }) {                                                                   \
            v.provides_flags = [](void*) noexcept -> std::uint32_t {          \
                return Class::provides_flags();                                \
            };                                                                 \
        }                                                                      \
                                                                               \
        return v;                                                              \
    }                                                                          \
                                                                               \
    const gn_security_provider_vtable_t _gn_sec_kVtable =                    \
        _gn_sec_make_vtable();                                                 \
                                                                               \
    const char* const _gn_sec_kProvides[] = {                                 \
        "gn.security." NameStrLiteral, nullptr,                               \
    };                                                                         \
                                                                               \
    const gn_plugin_descriptor_t _gn_sec_kDescriptor = {                      \
        /* name            */ _gn_sec_plugin_name,                            \
        /* version         */ VerStrLiteral,                                  \
        /* hot_reload_safe */ 0,                                              \
        /* ext_requires    */ nullptr,                                        \
        /* ext_provides    */ _gn_sec_kProvides,                              \
        /* kind            */ GN_PLUGIN_KIND_SECURITY,                        \
        /* inject_targets  */ nullptr,                                        \
        /* _reserved       */ {},                                              \
    };                                                                         \
                                                                               \
    } /* anonymous namespace */                                                \
                                                                               \
    extern "C" {                                                               \
                                                                               \
    GN_PLUGIN_EXPORT void GN_PLUGIN_SDK_VERSION_NAME(                         \
            std::uint32_t* major,                                              \
            std::uint32_t* minor,                                              \
            std::uint32_t* patch) {                                            \
        if (major) *major = GN_SDK_VERSION_MAJOR;                             \
        if (minor) *minor = GN_SDK_VERSION_MINOR;                             \
        if (patch) *patch = GN_SDK_VERSION_PATCH;                             \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_INIT_NAME(                        \
            const host_api_t* api, void** out_self) {                         \
        if (!api || !out_self) return GN_ERR_NULL_ARG;                        \
        auto* inst = new (std::nothrow) _gn_sec_inst_t{};                     \
        if (!inst) return GN_ERR_OUT_OF_MEMORY;                               \
        inst->provider = std::make_unique<Class>(api);                        \
        if (!inst->provider) { delete inst; return GN_ERR_OUT_OF_MEMORY; }   \
        inst->api      = api;                                                  \
        inst->host_ctx = api->host_ctx;                                        \
        *out_self = inst;                                                      \
        return GN_OK;                                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_REGISTER_NAME(void* self) {       \
        if (!self) return GN_ERR_NULL_ARG;                                    \
        auto* inst = static_cast<_gn_sec_inst_t*>(self);                      \
        if (!inst->api || !inst->api->register_security)                      \
            return GN_ERR_NOT_IMPLEMENTED;                                    \
        return inst->api->register_security(                                   \
            inst->host_ctx, Class::provider_id(),                             \
            &_gn_sec_kVtable, self);                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_UNREGISTER_NAME(void* self) {     \
        if (!self) return GN_ERR_NULL_ARG;                                    \
        auto* inst = static_cast<_gn_sec_inst_t*>(self);                      \
        if (!inst->api || !inst->api->unregister_security) return GN_OK;      \
        (void)inst->api->unregister_security(                                  \
            inst->host_ctx, Class::provider_id());                            \
        return GN_OK;                                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT void GN_PLUGIN_SHUTDOWN_NAME(void* self) {              \
        delete static_cast<_gn_sec_inst_t*>(self);                            \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT const gn_plugin_descriptor_t*                            \
    GN_PLUGIN_DESCRIPTOR_NAME(void) {                                         \
        return &_gn_sec_kDescriptor;                                          \
    }                                                                          \
                                                                               \
    } /* extern "C" */

/// Multi-provider security plugin.
///
/// Like `GN_SECURITY_PLUGIN` but REGISTER/UNREGISTER delegate to static
/// methods on @p Class, so the class can call `api->register_security`
/// any number of times. No limit on provider count.
///
/// ## Required class interface
///
/// ```cpp
/// struct MyPlugin {
///     explicit MyPlugin(const host_api_t* api);
///
///     // Called before constructor. Return false → INIT returns error.
///     // Use for one-time lib init (sodium_init, etc.). Optional.
///     static bool pre_init(const host_api_t* api);
///
///     // Return null-terminated list of "gn.security.*" capability strings.
///     static const char* const* security_ext_provides();
///
///     // Call api->register_security() as many times as needed.
///     static gn_result_t register_providers(
///         const host_api_t* api, void* host_ctx, void* self);
///
///     // Call api->unregister_security() for each registered provider.
///     static void unregister_providers(
///         const host_api_t* api, void* host_ctx);
/// };
/// ```
#define GN_SECURITY_PLUGIN_MULTI(Class, NameStrLiteral, VerStrLiteral)        \
    namespace {                                                                 \
                                                                               \
    using _gn_secm_inst_t = ::gn::sdk::detail::SecurityPluginInstance<Class>; \
    static constexpr const char _gn_secm_plugin_name[] = NameStrLiteral;      \
                                                                               \
    } /* anonymous namespace */                                                \
                                                                               \
    extern "C" {                                                               \
                                                                               \
    GN_PLUGIN_EXPORT void GN_PLUGIN_SDK_VERSION_NAME(                         \
            std::uint32_t* major,                                              \
            std::uint32_t* minor,                                              \
            std::uint32_t* patch) {                                            \
        if (major) *major = GN_SDK_VERSION_MAJOR;                             \
        if (minor) *minor = GN_SDK_VERSION_MINOR;                             \
        if (patch) *patch = GN_SDK_VERSION_PATCH;                             \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_INIT_NAME(                        \
            const host_api_t* api, void** out_self) {                         \
        if (!api || !out_self) return GN_ERR_NULL_ARG;                        \
        if constexpr (requires {                                               \
            { Class::pre_init(api) } -> std::convertible_to<bool>;            \
        }) {                                                                   \
            if (!Class::pre_init(api)) return GN_ERR_NULL_ARG;               \
        }                                                                      \
        auto* inst = new (std::nothrow) _gn_secm_inst_t{};                    \
        if (!inst) return GN_ERR_OUT_OF_MEMORY;                               \
        inst->provider = std::make_unique<Class>(api);                        \
        if (!inst->provider) { delete inst; return GN_ERR_OUT_OF_MEMORY; }   \
        inst->api      = api;                                                  \
        inst->host_ctx = api->host_ctx;                                        \
        *out_self = inst;                                                      \
        return GN_OK;                                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_REGISTER_NAME(void* self) {       \
        if (!self) return GN_ERR_NULL_ARG;                                    \
        auto* inst = static_cast<_gn_secm_inst_t*>(self);                     \
        if (!inst->api) return GN_ERR_NOT_IMPLEMENTED;                        \
        return Class::register_providers(inst->api, inst->host_ctx, self);   \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_UNREGISTER_NAME(void* self) {     \
        if (!self) return GN_ERR_NULL_ARG;                                    \
        auto* inst = static_cast<_gn_secm_inst_t*>(self);                     \
        if (!inst->api) return GN_OK;                                         \
        Class::unregister_providers(inst->api, inst->host_ctx);               \
        return GN_OK;                                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT void GN_PLUGIN_SHUTDOWN_NAME(void* self) {              \
        delete static_cast<_gn_secm_inst_t*>(self);                           \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT const gn_plugin_descriptor_t*                            \
    GN_PLUGIN_DESCRIPTOR_NAME(void) {                                         \
        static const gn_plugin_descriptor_t desc = {                          \
            _gn_secm_plugin_name,                                             \
            VerStrLiteral,                                                     \
            0, nullptr,                                                        \
            Class::security_ext_provides(),                                   \
            GN_PLUGIN_KIND_SECURITY,                                          \
            nullptr, nullptr, 0, 0, {},                                        \
        };                                                                     \
        return &desc;                                                          \
    }                                                                          \
                                                                               \
    } /* extern "C" */
