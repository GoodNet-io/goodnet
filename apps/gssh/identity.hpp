/// @file   apps/gssh/identity.hpp
/// @brief  Operator identity loading helpers.
///
/// `gssh` always wants the operator's persistent identity:
/// reusing the same Ed25519 keypair across runs is what makes
/// `peer_pk` a stable address. The wrapper resolves the path
/// (`--identity` override or `~/.config/goodnet/identity.bin` default),
/// loads the 77-byte blob through `core::identity::NodeIdentity`, and
/// installs it on the kernel handle before `gn_core_init` runs.
///
/// `sdk/core.h` v1.0 has no C ABI slot for identity loading from
/// disk — `gn_core_init` always generates a fresh ephemeral keypair.
/// This wrapper reaches into the kernel C++ API directly, which is
/// permitted because the goodnet binary already links against
/// `goodnet_kernel` for the protocol layer. A future SDK release
/// will add `gn_core_load_identity_from_file` and this file shrinks
/// to a thin call into that slot.

#pragma once

#include <expected>
#include <string>

#include <core/identity/node_identity.hpp>
#include <sdk/types.h>

namespace gn::core { class Kernel; }

namespace gn::apps::gssh {

/// Resolve the identity file path. `--identity` override wins; falls
/// back to `~/.config/goodnet/identity.bin`.
[[nodiscard]] std::string default_identity_path();

/// Load the identity from disk and install it on the freshly-built
/// `gn::core::Kernel` reachable through the C ABI handle. Returns
/// `GN_OK` on success, or one of:
/// - `GN_ERR_NOT_FOUND` when the file is absent. The bridge prints a
///   hint pointing at `goodnet identity gen --out <path>`.
/// - `GN_ERR_INTEGRITY_FAILED` when the file is present but the magic
///   prefix or attestation signature fail verification.
/// - `GN_ERR_INVALID_STATE` when the kernel handle is null.
[[nodiscard]] gn_result_t install_identity_on_kernel(
    gn::core::Kernel& kernel,
    const std::string& path,
    std::string& diagnostic);

}  // namespace gn::apps::gssh
