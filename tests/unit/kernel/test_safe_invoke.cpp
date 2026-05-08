/// @file   tests/unit/kernel/test_safe_invoke.cpp
/// @brief  Regression test for `safe_invoke.hpp` exception containment.
///
/// The C ABI does not specify exception propagation. A plugin that
/// throws across `extern "C"` corrupts the kernel's stack; the
/// `safe_call_*` wrappers in `core/kernel/safe_invoke.hpp` catch every
/// exception type and convert it to a documented error code. This test
/// pins the router's behaviour on the wrapped path: a misbehaving
/// handler whose `handle_message` throws `std::runtime_error` does not
/// crash the kernel — the router catches the exception, treats the
/// slot as having returned `GN_PROPAGATION_REJECT`, and surfaces the verdict
/// as `RouteOutcome::Rejected`.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string_view>

#include <core/kernel/identity_set.hpp>
#include <core/kernel/router.hpp>
#include <core/registry/handler.hpp>
#include <sdk/cpp/types.hpp>
#include <sdk/handler.h>
#include <sdk/types.h>

namespace gn::core {
namespace {

constexpr std::string_view kProtocol = "gnet-v1";

/// Faux handler whose `handle_message` always throws. Mimics a
/// misbehaving plugin that escaped a `std::runtime_error` past its
/// own `extern "C"` boundary.
gn_propagation_t throwing_handle(void* /*self*/, const gn_message_t* /*env*/) {
    throw std::runtime_error("plugin pretends C ABI is exception-friendly");
}

/// `on_result` companion. Records the propagation value the router
/// substituted when the wrapper caught the throw.
struct OnResultLog {
    bool             called = false;
    gn_propagation_t value  = GN_PROPAGATION_CONTINUE;
};

void recording_on_result(void* self, const gn_message_t* /*env*/,
                          gn_propagation_t result) {
    auto* log = static_cast<OnResultLog*>(self);
    log->called = true;
    log->value  = result;
}

const gn_handler_vtable_t* throwing_vtable() {
    static const gn_handler_vtable_t vt = []() {
        gn_handler_vtable_t v{};
        v.api_size       = sizeof(gn_handler_vtable_t);
        v.handle_message = &throwing_handle;
        v.on_result      = &recording_on_result;
        return v;
    }();
    return &vt;
}

/// Build a deterministic public key — same helper shape as
/// `test_router.cpp` so test scaffolding stays uniform.
PublicKey pk_from_byte(std::uint8_t seed) noexcept {
    PublicKey pk{};
    for (std::size_t i = 0; i < pk.size(); ++i) {
        pk[i] = static_cast<std::uint8_t>(seed + i);
    }
    return pk;
}

void fill_envelope(gn_message_t&    env,
                   const PublicKey& sender,
                   const PublicKey& receiver,
                   std::uint32_t    msg_id) noexcept {
    std::memset(&env, 0, sizeof(env));
    std::memcpy(env.sender_pk,   sender.data(),   GN_PUBLIC_KEY_BYTES);
    std::memcpy(env.receiver_pk, receiver.data(), GN_PUBLIC_KEY_BYTES);
    env.msg_id       = msg_id;
    env.payload      = nullptr;
    env.payload_size = 0;
}

TEST(SafeInvoke_Router, ThrowingHandlerSurfacesAsRejected) {
    HandlerRegistry  registry;
    LocalIdentityRegistry identities;
    Router           router{identities, registry};

    const auto local  = pk_from_byte(0x11);
    const auto sender = pk_from_byte(0x22);
    identities.add(local);

    OnResultLog on_result_log;
    gn_handler_id_t hid = GN_INVALID_ID;
    ASSERT_EQ(registry.register_handler(kProtocol, 0x42, 128,
                                         throwing_vtable(),
                                         &on_result_log, &hid),
              GN_OK);

    gn_message_t env{};
    fill_envelope(env, sender, local, 0x42);

    /// The router would crash here without `safe_call_value`.
    /// With the wrapper, the throw is caught, the slot is treated as
    /// having returned `GN_PROPAGATION_REJECT`, and the chain breaks with
    /// `RouteOutcome::Rejected`.
    EXPECT_EQ(router.route_inbound(kProtocol, env),
              RouteOutcome::Rejected);

    /// `on_result` still fires — the wrapper does not skip the result
    /// callback when `handle_message` throws. The substituted value
    /// is `GN_PROPAGATION_REJECT`, matching the chain-break semantics.
    EXPECT_TRUE(on_result_log.called)
        << "on_result must run even after handle_message throws";
    EXPECT_EQ(on_result_log.value, GN_PROPAGATION_REJECT);
}

/// Faux handler whose `on_result` (a void-returning slot) throws.
/// Pins `safe_call_void` from the wrapper trio.
void throwing_on_result(void* /*self*/, const gn_message_t* /*env*/,
                          gn_propagation_t /*result*/) {
    throw std::runtime_error("on_result also pretends");
}

gn_propagation_t consuming_handle(void* /*self*/,
                                    const gn_message_t* /*env*/) {
    return GN_PROPAGATION_CONSUMED;
}

const gn_handler_vtable_t* throwing_on_result_vtable() {
    static const gn_handler_vtable_t vt = []() {
        gn_handler_vtable_t v{};
        v.api_size       = sizeof(gn_handler_vtable_t);
        v.handle_message = &consuming_handle;
        v.on_result      = &throwing_on_result;
        return v;
    }();
    return &vt;
}

TEST(SafeInvoke_Router, ThrowingOnResultDoesNotCrash) {
    /// `safe_call_void` swallows exceptions from void slots and
    /// logs the site tag. The route still reports the verdict
    /// `handle_message` returned — `Consumed` here, since the
    /// throw is in `on_result`, not `handle_message`.
    HandlerRegistry  registry;
    LocalIdentityRegistry identities;
    Router           router{identities, registry};

    const auto local  = pk_from_byte(0x33);
    const auto sender = pk_from_byte(0x44);
    identities.add(local);

    gn_handler_id_t hid = GN_INVALID_ID;
    ASSERT_EQ(registry.register_handler(kProtocol, 0x77, 128,
                                         throwing_on_result_vtable(),
                                         nullptr, &hid),
              GN_OK);

    gn_message_t env{};
    fill_envelope(env, sender, local, 0x77);

    EXPECT_NO_THROW({
        const auto outcome = router.route_inbound(kProtocol, env);
        EXPECT_EQ(outcome, RouteOutcome::DispatchedLocal);
    });
}

}  // namespace
}  // namespace gn::core
