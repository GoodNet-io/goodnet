/// @file   core/identity/node_identity.cpp
/// @brief  Aggregated node identity construction.

#include "node_identity.hpp"

namespace gn::core::identity {

::gn::Result<NodeIdentity> NodeIdentity::generate(std::int64_t expiry_unix_ts) {
    auto user_kp = KeyPair::generate();
    if (!user_kp) return std::unexpected(user_kp.error());

    auto device_kp = KeyPair::generate();
    if (!device_kp) return std::unexpected(device_kp.error());

    return compose(std::move(*user_kp), std::move(*device_kp),
                   expiry_unix_ts);
}

::gn::Result<NodeIdentity> NodeIdentity::compose(
    KeyPair&& user, KeyPair&& device, std::int64_t expiry_unix_ts) {

    NodeIdentity out;
    out.user_   = std::move(user);
    out.device_ = std::move(device);

    auto att = Attestation::create(out.user_, out.device_.public_key(),
                                    expiry_unix_ts);
    if (!att) return std::unexpected(att.error());
    out.att_ = *att;

    out.address_ = derive_address(out.user_.public_key(),
                                   out.device_.public_key());
    return out;
}

} // namespace gn::core::identity
