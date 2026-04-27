/// @file   plugins/security/null/null.cpp
/// @brief  Null security provider — pass-through encrypt / decrypt.
///
/// For loopback, IPC, intra-node, and the "I trust this link"
/// paths permitted by `security-trust.md` §4 with explicit opt-in.
/// Handshake is a single no-op step that returns "complete" right
/// away; encrypt / decrypt copy the input buffer to a fresh
/// allocation so the kernel's contract on plugin-allocated output
/// (paired with @ref free_fn) holds uniformly across providers.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>

#include <sdk/abi.h>
#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/security.h>

namespace {

/// Provider-private state. Carries nothing beyond the api pointer
/// the plugin needs to register the vtable. Per-connection state
/// is also empty for this provider.
struct NullPlugin {
    const host_api_t* api      = nullptr;
    void*             host_ctx = nullptr;
};

constexpr const char* kProviderId = "null";

const char* null_provider_id(void* /*self*/) {
    return kProviderId;
}

gn_result_t null_handshake_open(void* /*self*/,
                                gn_conn_id_t /*conn*/,
                                gn_trust_class_t /*trust*/,
                                void** out_state) {
    if (!out_state) return GN_ERR_NULL_ARG;
    /// No per-connection state for null security.
    *out_state = nullptr;
    return GN_OK;
}

gn_result_t null_handshake_step(void* /*self*/,
                                void* /*state*/,
                                const std::uint8_t* /*incoming*/,
                                std::size_t /*incoming_size*/,
                                gn_secure_buffer_t* out_message) {
    if (!out_message) return GN_ERR_NULL_ARG;
    /// Nothing to send; handshake already complete.
    out_message->bytes   = nullptr;
    out_message->size    = 0;
    out_message->free_fn = nullptr;
    return GN_OK;
}

int null_handshake_complete(void* /*self*/, void* /*state*/) {
    /// Always complete — no rounds to run.
    return 1;
}

gn_result_t null_export_transport_keys(void* /*self*/,
                                       void* /*state*/,
                                       gn_handshake_keys_t* out_keys) {
    if (!out_keys) return GN_ERR_NULL_ARG;
    /// Zero keys for the no-encryption path. The kernel still
    /// records identity-binding through other means.
    std::memset(out_keys, 0, sizeof(*out_keys));
    return GN_OK;
}

void null_free_buffer(std::uint8_t* p) {
    std::free(p);
}

[[nodiscard]] gn_result_t null_copy_through(const std::uint8_t* in,
                                             std::size_t in_size,
                                             gn_secure_buffer_t* out) {
    if (!out) return GN_ERR_NULL_ARG;
    if (in_size == 0) {
        out->bytes   = nullptr;
        out->size    = 0;
        out->free_fn = nullptr;
        return GN_OK;
    }
    auto* heap = static_cast<std::uint8_t*>(std::malloc(in_size));
    if (!heap) return GN_ERR_OUT_OF_MEMORY;
    std::memcpy(heap, in, in_size);
    out->bytes   = heap;
    out->size    = in_size;
    out->free_fn = &null_free_buffer;
    return GN_OK;
}

gn_result_t null_encrypt(void* /*self*/,
                         void* /*state*/,
                         const std::uint8_t* plaintext,
                         std::size_t plaintext_size,
                         gn_secure_buffer_t* out) {
    return null_copy_through(plaintext, plaintext_size, out);
}

gn_result_t null_decrypt(void* /*self*/,
                         void* /*state*/,
                         const std::uint8_t* ciphertext,
                         std::size_t ciphertext_size,
                         gn_secure_buffer_t* out) {
    return null_copy_through(ciphertext, ciphertext_size, out);
}

gn_result_t null_rekey(void* /*self*/, void* /*state*/) {
    /// No keys to rotate.
    return GN_OK;
}

void null_handshake_close(void* /*self*/, void* /*state*/) {
    /// State is always nullptr.
}

void null_destroy(void* self) {
    delete static_cast<NullPlugin*>(self);
}

gn_security_provider_vtable_t make_null_vtable() {
    gn_security_provider_vtable_t v{};
    v.api_size              = sizeof(gn_security_provider_vtable_t);
    v.provider_id           = &null_provider_id;
    v.handshake_open        = &null_handshake_open;
    v.handshake_step        = &null_handshake_step;
    v.handshake_complete    = &null_handshake_complete;
    v.export_transport_keys = &null_export_transport_keys;
    v.encrypt               = &null_encrypt;
    v.decrypt               = &null_decrypt;
    v.rekey                 = &null_rekey;
    v.handshake_close       = &null_handshake_close;
    v.destroy               = &null_destroy;
    return v;
}

const gn_security_provider_vtable_t kVtable = make_null_vtable();

const char* const kProvidesList[] = {
    "gn.security.null",
    nullptr,
};

const gn_plugin_descriptor_t kDescriptor = {
    /* name              */ "goodnet_security_null",
    /* version           */ "0.1.0",
    /* hot_reload_safe   */ 1,
    /* ext_requires      */ nullptr,
    /* ext_provides      */ kProvidesList,
    /* _reserved         */ {nullptr, nullptr, nullptr, nullptr},
};

} // namespace

extern "C" {

GN_PLUGIN_EXPORT void gn_plugin_sdk_version(std::uint32_t* major,
                                            std::uint32_t* minor,
                                            std::uint32_t* patch) {
    if (major) *major = GN_SDK_VERSION_MAJOR;
    if (minor) *minor = GN_SDK_VERSION_MINOR;
    if (patch) *patch = GN_SDK_VERSION_PATCH;
}

GN_PLUGIN_EXPORT gn_result_t gn_plugin_init(const host_api_t* api,
                                            void** out_self) {
    if (!api || !out_self) return GN_ERR_NULL_ARG;
    auto* p = new (std::nothrow) NullPlugin{};
    if (!p) return GN_ERR_OUT_OF_MEMORY;
    p->api      = api;
    p->host_ctx = api->host_ctx;
    *out_self   = p;
    return GN_OK;
}

GN_PLUGIN_EXPORT gn_result_t gn_plugin_register(void* self) {
    if (!self) return GN_ERR_NULL_ARG;
    auto* p = static_cast<NullPlugin*>(self);
    if (!p->api || !p->api->register_security) return GN_ERR_NOT_IMPLEMENTED;
    return p->api->register_security(p->host_ctx, kProviderId, &kVtable, p);
}

GN_PLUGIN_EXPORT gn_result_t gn_plugin_unregister(void* self) {
    if (!self) return GN_ERR_NULL_ARG;
    auto* p = static_cast<NullPlugin*>(self);
    if (!p->api || !p->api->unregister_security) return GN_OK;
    return p->api->unregister_security(p->host_ctx, kProviderId);
}

GN_PLUGIN_EXPORT void gn_plugin_shutdown(void* self) {
    delete static_cast<NullPlugin*>(self);
}

GN_PLUGIN_EXPORT const gn_plugin_descriptor_t* gn_plugin_descriptor(void) {
    return &kDescriptor;
}

} // extern "C"
