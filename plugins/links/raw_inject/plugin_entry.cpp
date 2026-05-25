// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/raw_inject/plugin_entry.cpp
/// @brief  C ABI entry points produced by `GN_LINK_PLUGIN_EX`.
///
/// raw_inject uses `raw-v1` as its transport protocol (byte-transparent
/// reply path, no GNET framing on outbound). Each accepted connection
/// receives a deterministic non-zero pk derived from the peer URI so
/// handlers can identify the source without a Noise handshake.
/// Trust class is `GN_TRUST_LOOPBACK` — admitted by the null security
/// provider without a handshake.

#include "raw_inject.hpp"

#include <sdk/cpp/link_plugin.hpp>

GN_LINK_PLUGIN_EX(::gn::link::raw_inject::RawInjectLink,
                  "raw-inject",
                  ::gn::link::raw_inject::kProtocolId,
                  GN_TRUST_LOOPBACK)
