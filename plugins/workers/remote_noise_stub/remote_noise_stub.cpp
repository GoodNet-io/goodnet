/// @file   plugins/workers/remote_noise_stub/remote_noise_stub.cpp
/// @brief  Subprocess worker exercising the SECURITY proxy slots.
///
/// Implements a deterministic three-step handshake state machine
/// (initiator side of a Noise XX-shaped exchange). The crypto is
/// stubbed — each `handshake_step` increments an internal counter
/// and emits a fixed-shape outgoing buffer. The point is the wire
/// round trip: every PLUGIN_CALL slot 0x300..0x308 lands here and
/// the response rides back through HOST_REPLY.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/security.h>
#include <sdk/trust.h>

#include <sdk/cpp/remote_plugin.hpp>

namespace {

struct StubState {
    int  step                 = 0;
    bool completed            = false;
    gn_handshake_role_t role  = GN_ROLE_INITIATOR;
};

const char* stub_provider_id(void* /*self*/) {
    return "remote_noise_stub";
}

std::uint32_t stub_allowed_trust_mask(void* /*self*/) {
    return (1u << GN_TRUST_UNTRUSTED) | (1u << GN_TRUST_PEER) |
           (1u << GN_TRUST_LOOPBACK)  | (1u << GN_TRUST_INTRA_NODE);
}

gn_result_t stub_handshake_open(void* /*self*/,
                                gn_conn_id_t /*conn*/,
                                gn_trust_class_t /*trust*/,
                                gn_handshake_role_t role,
                                const uint8_t /*local_sk*/[GN_PRIVATE_KEY_BYTES],
                                const uint8_t /*local_pk*/[GN_PUBLIC_KEY_BYTES],
                                const uint8_t* /*remote_pk*/,
                                void** out_state) {
    auto* s = new StubState{};
    s->role = role;
    *out_state = s;
    return GN_OK;
}

gn_result_t stub_handshake_step(void* /*self*/,
                                void* state,
                                const uint8_t* /*incoming*/, size_t /*in_size*/,
                                gn_secure_buffer_t* out_message) {
    auto* s = static_cast<StubState*>(state);
    s->step++;
    // Three-step XX handshake: initiator writes on steps 1 and 3,
    // responder writes on step 2.
    const bool writes = (s->role == GN_ROLE_INITIATOR && (s->step == 1 || s->step == 3)) ||
                        (s->role == GN_ROLE_RESPONDER && s->step == 2);
    if (writes) {
        // Fixed 8-byte stub frame whose first byte carries the step
        // number — gives the test a deterministic shape to assert on.
        auto* buf = static_cast<std::uint8_t*>(std::malloc(8));
        std::memset(buf, 0, 8);
        buf[0] = static_cast<std::uint8_t>(s->step);
        out_message->bytes = buf;
        out_message->size  = 8;
        out_message->free_fn = [](void* /*ud*/, std::uint8_t* p) {
            std::free(p);
        };
    } else {
        out_message->bytes = nullptr;
        out_message->size  = 0;
        out_message->free_fn = nullptr;
    }
    if (s->step >= 3) {
        s->completed = true;
    }
    return GN_OK;
}

int stub_handshake_complete(void* /*self*/, void* state) {
    return static_cast<StubState*>(state)->completed ? 1 : 0;
}

gn_result_t stub_export_transport_keys(void* /*self*/,
                                        void* state,
                                        gn_handshake_keys_t* out_keys) {
    auto* s = static_cast<StubState*>(state);
    if (!s->completed) return GN_ERR_INVALID_STATE;
    out_keys->api_size = sizeof(gn_handshake_keys_t);
    for (size_t i = 0; i < GN_CIPHER_KEY_BYTES; ++i) {
        out_keys->send_cipher_key[i] = static_cast<std::uint8_t>(0x10 + i);
        out_keys->recv_cipher_key[i] = static_cast<std::uint8_t>(0x20 + i);
    }
    out_keys->initial_send_nonce = 0;
    out_keys->initial_recv_nonce = 0;
    for (size_t i = 0; i < GN_HASH_BYTES; ++i) {
        out_keys->handshake_hash[i] = static_cast<std::uint8_t>(0x30 + i);
    }
    for (size_t i = 0; i < GN_PUBLIC_KEY_BYTES; ++i) {
        out_keys->peer_static_pk[i] = static_cast<std::uint8_t>(0x40 + i);
    }
    return GN_OK;
}

gn_result_t stub_encrypt(void* /*self*/, void* /*state*/,
                         const uint8_t* plaintext, size_t plaintext_size,
                         gn_secure_buffer_t* out) {
    // XOR with 0x55 — stub authenticated encryption stand-in.
    auto* buf = static_cast<std::uint8_t*>(std::malloc(plaintext_size));
    for (size_t i = 0; i < plaintext_size; ++i) {
        buf[i] = static_cast<std::uint8_t>(plaintext[i] ^ 0x55);
    }
    out->bytes = buf;
    out->size  = plaintext_size;
    out->free_fn = [](void* /*ud*/, std::uint8_t* p) { std::free(p); };
    return GN_OK;
}

gn_result_t stub_decrypt(void* self, void* state,
                         const uint8_t* ciphertext, size_t ciphertext_size,
                         gn_secure_buffer_t* out) {
    return stub_encrypt(self, state, ciphertext, ciphertext_size, out);
}

gn_result_t stub_rekey(void* /*self*/, void* /*state*/) {
    return GN_OK;
}

void stub_handshake_close(void* /*self*/, void* state) {
    delete static_cast<StubState*>(state);
}

void stub_destroy(void* /*self*/) {}

constexpr gn_security_provider_vtable_t kVtable{
    .api_size              = sizeof(gn_security_provider_vtable_t),
    .provider_id           = &stub_provider_id,
    .handshake_open        = &stub_handshake_open,
    .handshake_step        = &stub_handshake_step,
    .handshake_complete    = &stub_handshake_complete,
    .export_transport_keys = &stub_export_transport_keys,
    .encrypt               = &stub_encrypt,
    .decrypt               = &stub_decrypt,
    .rekey                 = &stub_rekey,
    .handshake_close       = &stub_handshake_close,
    .destroy               = &stub_destroy,
    .allowed_trust_mask    = &stub_allowed_trust_mask,
    ._reserved             = {nullptr, nullptr, nullptr, nullptr},
};

}  // namespace

int main() {
    gn::sdk::remote::WorkerConfig cfg{};
    cfg.plugin_name     = "remote_noise_stub";
    cfg.kind            = GN_PLUGIN_KIND_SECURITY;
    cfg.security_vtable = &kVtable;
    cfg.security_self   = nullptr;
    return gn::sdk::remote::run_worker(cfg);
}
