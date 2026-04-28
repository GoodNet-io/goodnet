// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/security/noise/noise.cpp
/// @brief  Noise security provider — gn_security_provider_vtable
///         bound to the XX state machines under this directory.
///
/// Per `noise-handshake.md` the wire pattern is fixed at
/// `Noise_XX_25519_ChaChaPoly_BLAKE2b`. Future work registers a second
/// provider for IK; the SDK already accommodates two with distinct
/// `provider_id` strings.
///
/// Identity bridge: the kernel hands the provider Ed25519 keys (the
/// canonical mesh-address material). The Noise framework operates on
/// X25519, so the plugin converts each side via libsodium's
/// `crypto_sign_ed25519_*_to_curve25519` at handshake_open time.

#include "cipher.hpp"
#include "handshake.hpp"
#include "transport.hpp"

#include <sodium.h>

#include <sdk/abi.h>
#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/security.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#include <span>
#include <vector>

namespace {

using gn::noise::CipherKey;
using gn::noise::HandshakeState;
using gn::noise::Keypair;
using gn::noise::Pattern;
using gn::noise::PublicKey;
using gn::noise::TransportState;

constexpr const char* kProviderId = "noise";

/// Per-connection state owned by the kernel through `void* state`.
struct NoiseSession {
    HandshakeState                handshake;
    TransportState                transport;
    gn::noise::Pattern            pattern   = gn::noise::Pattern::XX;
    gn_handshake_role_t           role      = GN_ROLE_INITIATOR;
    int                           total_steps = 3;   ///< XX: 3, IK: 2
    bool                          split_done  = false;
    PublicKey                     local_pk{};        ///< X25519 form
    bool                          peer_pk_present = false;
    PublicKey                     peer_x25519_pk{}; ///< filled at split

    NoiseSession(Pattern p, bool initiator,
                  const Keypair& static_keypair,
                  std::optional<PublicKey> remote_static_pk)
        : handshake(p, initiator, static_keypair, remote_static_pk),
          pattern(p),
          role(initiator ? GN_ROLE_INITIATOR : GN_ROLE_RESPONDER),
          total_steps(p == Pattern::IK ? 2 : 3),
          local_pk(static_keypair.pk) {}
};

/// Convert an Ed25519 keypair (libsodium 64-byte sk + 32-byte pk) to
/// the X25519 form Noise expects. Returns the X25519 keypair, or
/// nullopt if either conversion fails (e.g. malformed input).
std::optional<Keypair> ed25519_to_x25519(
    std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES> ed_sk,
    std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>  ed_pk)
{
    Keypair kp;
    if (crypto_sign_ed25519_sk_to_curve25519(kp.sk.data(), ed_sk.data()) != 0) {
        return std::nullopt;
    }
    if (crypto_sign_ed25519_pk_to_curve25519(kp.pk.data(), ed_pk.data()) != 0) {
        return std::nullopt;
    }
    return kp;
}

/// Convert a peer's Ed25519 pk to its X25519 form.
std::optional<PublicKey> ed25519_pk_to_x25519(
    std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES> ed_pk)
{
    PublicKey out;
    if (crypto_sign_ed25519_pk_to_curve25519(out.data(), ed_pk.data()) != 0) {
        return std::nullopt;
    }
    return out;
}

void free_buffer(std::uint8_t* p) { std::free(p); }

/// Wrap a vector's payload into a plugin-owned `gn_secure_buffer_t`.
/// The kernel calls `free_fn` once it is done with the bytes.
gn_result_t emit_buffer(std::vector<std::uint8_t>&& src,
                         gn_secure_buffer_t* out) {
    if (!out) return GN_ERR_NULL_ARG;
    if (src.empty()) {
        out->bytes   = nullptr;
        out->size    = 0;
        out->free_fn = nullptr;
        return GN_OK;
    }
    auto* heap = static_cast<std::uint8_t*>(std::malloc(src.size()));
    if (!heap) return GN_ERR_OUT_OF_MEMORY;
    std::memcpy(heap, src.data(), src.size());
    out->bytes   = heap;
    out->size    = src.size();
    out->free_fn = &free_buffer;
    return GN_OK;
}

// ── vtable entries ──────────────────────────────────────────────────

const char* noise_provider_id(void* /*self*/) {
    return kProviderId;
}

gn_result_t noise_handshake_open(void* /*self*/,
                                  gn_conn_id_t /*conn*/,
                                  gn_trust_class_t /*trust*/,
                                  gn_handshake_role_t role,
                                  const std::uint8_t* local_static_sk,
                                  const std::uint8_t* local_static_pk,
                                  const std::uint8_t* remote_static_pk,
                                  void** out_state) {
    if (!out_state || !local_static_sk || !local_static_pk) return GN_ERR_NULL_ARG;

    auto static_kp = ed25519_to_x25519(
        std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES>(local_static_sk, GN_PRIVATE_KEY_BYTES),
        std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>(local_static_pk, GN_PUBLIC_KEY_BYTES));
    if (!static_kp) return GN_ERR_INVALID_ENVELOPE;

    /// Pattern selection: when the kernel hands a known peer pk we
    /// could pick IK to save one round-trip, but XX accepts either
    /// scenario (it just learns the static during the handshake) and
    /// keeps the surface uniform. Future work splits into two
    /// providers; for now everything runs on XX.
    std::optional<PublicKey> peer_x;
    if (remote_static_pk != nullptr) {
        peer_x = ed25519_pk_to_x25519(
            std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>(remote_static_pk, GN_PUBLIC_KEY_BYTES));
        if (!peer_x) return GN_ERR_INVALID_ENVELOPE;
    }

    auto* session = new (std::nothrow) NoiseSession(
        Pattern::XX,
        role == GN_ROLE_INITIATOR,
        *static_kp,
        peer_x);
    if (!session) return GN_ERR_OUT_OF_MEMORY;

    *out_state = session;
    return GN_OK;
}

/// Drive one handshake message. The reader/writer alternation follows
/// the symmetric formula `initiator XOR (step % 2)` — at even steps
/// the initiator writes, at odd steps the responder writes.
gn_result_t noise_handshake_step(void* /*self*/,
                                  void* state,
                                  const std::uint8_t* incoming,
                                  std::size_t incoming_size,
                                  gn_secure_buffer_t* out_message) {
    if (!state || !out_message) return GN_ERR_NULL_ARG;
    auto* s = static_cast<NoiseSession*>(state);

    out_message->bytes   = nullptr;
    out_message->size    = 0;
    out_message->free_fn = nullptr;

    /// Reader's branch: incoming bytes mean the peer just wrote a
    /// handshake message; consume it before deciding whether we write.
    if (incoming_size > 0) {
        auto plain = s->handshake.read_message(
            std::span<const std::uint8_t>(incoming, incoming_size));
        if (!plain) return GN_ERR_INVALID_ENVELOPE;
        if (s->handshake.is_complete()) {
            return GN_OK;
        }
    }

    /// At this point the local side may need to write the next
    /// pattern message. `step()` is the count of completed messages;
    /// a fresh handshake starts at 0 with the initiator on duty.
    const bool initiator_writes_next = (s->handshake.step() % 2) == 0;
    const bool writer_turn =
        initiator_writes_next == (s->role == GN_ROLE_INITIATOR);

    if (!writer_turn) {
        return GN_OK;  /// waiting for inbound
    }

    auto produced = s->handshake.write_message({});
    if (!produced) return GN_ERR_INVALID_ENVELOPE;
    return emit_buffer(std::move(*produced), out_message);
}

int noise_handshake_complete(void* /*self*/, void* state) {
    if (!state) return 0;
    return static_cast<NoiseSession*>(state)->handshake.is_complete() ? 1 : 0;
}

gn_result_t noise_export_transport_keys(void* /*self*/,
                                         void* state,
                                         gn_handshake_keys_t* out_keys) {
    if (!state || !out_keys) return GN_ERR_NULL_ARG;
    auto* s = static_cast<NoiseSession*>(state);
    if (!s->handshake.is_complete()) return GN_ERR_INVALID_ENVELOPE;
    if (s->split_done) return GN_ERR_INVALID_ENVELOPE;

    auto pair = s->handshake.split();
    s->transport = TransportState(std::move(pair.send), std::move(pair.recv));
    s->split_done = true;

    /// Copy SDK-visible material. Cipher keys are zero here — the
    /// session keeps the live cipher state internally; the export is
    /// for channel-binding and peer-pk surfacing only.
    std::memset(out_keys, 0, sizeof(*out_keys));
    /// peer X25519 pk (Noise static), surfaced for the kernel.
    s->peer_x25519_pk = s->handshake.peer_static_public_key();
    std::memcpy(out_keys->peer_static_pk, s->peer_x25519_pk.data(),
                GN_PUBLIC_KEY_BYTES);
    /// Channel binding: first GN_HASH_BYTES (32) of the 64-byte
    /// handshake hash — see noise-handshake.md §2.
    auto h = s->handshake.handshake_hash();
    std::memcpy(out_keys->handshake_hash, h.data(), GN_HASH_BYTES);
    return GN_OK;
}

gn_result_t noise_encrypt(void* /*self*/,
                           void* state,
                           const std::uint8_t* plaintext,
                           std::size_t plaintext_size,
                           gn_secure_buffer_t* out) {
    if (!state) return GN_ERR_NULL_ARG;
    auto* s = static_cast<NoiseSession*>(state);
    if (!s->split_done) return GN_ERR_INVALID_ENVELOPE;

    auto cipher = s->transport.encrypt(
        std::span<const std::uint8_t>(plaintext, plaintext_size));
    return emit_buffer(std::move(cipher), out);
}

gn_result_t noise_decrypt(void* /*self*/,
                           void* state,
                           const std::uint8_t* ciphertext,
                           std::size_t ciphertext_size,
                           gn_secure_buffer_t* out) {
    if (!state) return GN_ERR_NULL_ARG;
    auto* s = static_cast<NoiseSession*>(state);
    if (!s->split_done) return GN_ERR_INVALID_ENVELOPE;

    auto plain = s->transport.decrypt(
        std::span<const std::uint8_t>(ciphertext, ciphertext_size));
    if (!plain) return GN_ERR_INVALID_ENVELOPE;
    return emit_buffer(std::move(*plain), out);
}

gn_result_t noise_rekey(void* /*self*/, void* state) {
    if (!state) return GN_ERR_NULL_ARG;
    auto* s = static_cast<NoiseSession*>(state);
    if (!s->split_done) return GN_ERR_INVALID_ENVELOPE;
    s->transport.rekey();
    return GN_OK;
}

void noise_handshake_close(void* /*self*/, void* state) {
    delete static_cast<NoiseSession*>(state);
}

/// Provider-level destroy fires symmetrically with `gn_plugin_init`'s
/// allocation; the kernel's plugin manager owns the call sequence
/// (`unregister → shutdown`). Cleanup of the NoisePlugin instance
/// happens in `gn_plugin_shutdown`, so this entry stays a no-op to
/// avoid a double-delete if both arrive.
void noise_destroy(void* /*self*/) {}

/// Noise provider authenticates and encrypts every direction; safe
/// on every trust class. The kernel may still choose `null+raw` on
/// loopback when latency matters (per `security-trust.md` §4 default
/// stacks); the mask declares capability, not policy.
std::uint32_t noise_allowed_trust_mask(void* /*self*/) {
    return (1u << GN_TRUST_UNTRUSTED) |
           (1u << GN_TRUST_PEER)      |
           (1u << GN_TRUST_LOOPBACK)  |
           (1u << GN_TRUST_INTRA_NODE);
}

gn_security_provider_vtable_t make_vtable() {
    gn_security_provider_vtable_t v{};
    v.api_size              = sizeof(gn_security_provider_vtable_t);
    v.provider_id           = &noise_provider_id;
    v.handshake_open        = &noise_handshake_open;
    v.handshake_step        = &noise_handshake_step;
    v.handshake_complete    = &noise_handshake_complete;
    v.export_transport_keys = &noise_export_transport_keys;
    v.encrypt               = &noise_encrypt;
    v.decrypt               = &noise_decrypt;
    v.rekey                 = &noise_rekey;
    v.handshake_close       = &noise_handshake_close;
    v.destroy               = &noise_destroy;
    v.allowed_trust_mask    = &noise_allowed_trust_mask;
    return v;
}

const gn_security_provider_vtable_t kVtable = make_vtable();

const char* const kProvidesList[] = {
    "gn.security.noise",
    nullptr,
};

const gn_plugin_descriptor_t kDescriptor = {
    /* name              */ "goodnet_security_noise",
    /* version           */ "0.1.0",
    /* hot_reload_safe   */ 0,  /// active sessions hold pointers into provider data
    /* ext_requires      */ nullptr,
    /* ext_provides      */ kProvidesList,
    /* kind              */ GN_PLUGIN_KIND_SECURITY,
    /* _reserved         */ {nullptr, nullptr, nullptr, nullptr},
};

struct NoisePlugin {
    const host_api_t* api      = nullptr;
    void*             host_ctx = nullptr;
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
    if (sodium_init() < 0) return GN_ERR_NULL_ARG;
    auto* p = new (std::nothrow) NoisePlugin{};
    if (!p) return GN_ERR_OUT_OF_MEMORY;
    p->api      = api;
    p->host_ctx = api->host_ctx;
    *out_self   = p;
    return GN_OK;
}

GN_PLUGIN_EXPORT gn_result_t gn_plugin_register(void* self) {
    if (!self) return GN_ERR_NULL_ARG;
    auto* p = static_cast<NoisePlugin*>(self);
    if (!p->api || !p->api->register_security) return GN_ERR_NOT_IMPLEMENTED;
    return p->api->register_security(p->host_ctx, kProviderId, &kVtable, p);
}

GN_PLUGIN_EXPORT gn_result_t gn_plugin_unregister(void* self) {
    if (!self) return GN_ERR_NULL_ARG;
    auto* p = static_cast<NoisePlugin*>(self);
    if (!p->api || !p->api->unregister_security) return GN_OK;
    return p->api->unregister_security(p->host_ctx, kProviderId);
}

GN_PLUGIN_EXPORT void gn_plugin_shutdown(void* self) {
    delete static_cast<NoisePlugin*>(self);
}

GN_PLUGIN_EXPORT const gn_plugin_descriptor_t* gn_plugin_descriptor(void) {
    return &kDescriptor;
}

} // extern "C"
