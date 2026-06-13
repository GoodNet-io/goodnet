// SPDX-License-Identifier: MIT
/// @file   sdk/cpp/mdns.hpp
/// @brief  C++ wrapper types for the `gn.discovery.mdns` extension.
///
/// Provides the C++ counterparts of the C vtable types in
/// <sdk/extensions/mdns.h>: a std::vector-based result struct and
/// an std::function callback alias. Both plugins that deal with mDNS
/// (discovery/mdns and links/ice) include this header so the types
/// are defined exactly once.

#pragma once

#include <functional>
#include <string>
#include <vector>

namespace gn::link::ice {

struct MdnsResolveResult {
    std::vector<std::string> ipv4;
    std::vector<std::string> ipv6;
    bool resolved = false;
};

using MdnsResolveCallback = std::function<void(const MdnsResolveResult&)>;

}  // namespace gn::link::ice
