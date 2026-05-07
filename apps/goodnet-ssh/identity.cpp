/// @file   apps/goodnet-ssh/identity.cpp
/// @brief  Implementation of the identity loader.

#include "identity.hpp"

#include <cstdlib>
#include <filesystem>
#include <pwd.h>
#include <unistd.h>

#include <core/identity/node_identity.hpp>
#include <core/kernel/kernel.hpp>

namespace gn::apps::goodnet_ssh {

namespace {

std::string resolve_home_dir() {
    if (const char* env = std::getenv("HOME"); env != nullptr && env[0] != '\0') {
        return std::string{env};
    }
    if (auto* pwd = ::getpwuid(::getuid()); pwd != nullptr && pwd->pw_dir != nullptr) {
        return std::string{pwd->pw_dir};
    }
    return std::string{"/"};
}

}  // namespace

std::string default_identity_path() {
    namespace fs = std::filesystem;
    return (fs::path{resolve_home_dir()} / ".config" / "goodnet" / "identity.bin")
        .string();
}

gn_result_t install_identity_on_kernel(gn::core::Kernel& kernel,
                                        const std::string& path,
                                        std::string& diagnostic) {
    diagnostic.clear();
    auto identity = gn::core::identity::NodeIdentity::load_from_file(path);
    if (!identity) {
        diagnostic = identity.error().what.empty()
                          ? std::string{"identity load failed"}
                          : identity.error().what;
        // The kernel error path returns NOT_FOUND for absent files
        // and INTEGRITY_FAILED for tampered ones. The wrapped error
        // already carries the right code; preserve it.
        const auto rc = identity.error().code;
        if (rc != GN_OK) return rc;
        return GN_ERR_INTEGRITY_FAILED;
    }
    kernel.identities().add(identity->device().public_key());
    kernel.set_node_identity(std::move(*identity));
    return GN_OK;
}

}  // namespace gn::apps::goodnet_ssh
