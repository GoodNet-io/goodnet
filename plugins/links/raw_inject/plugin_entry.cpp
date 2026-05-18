// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/raw_inject/plugin_entry.cpp
/// @brief  C ABI entry points produced by `GN_LINK_PLUGIN_EX`.
///
/// raw_inject declares the `raw-v1` protocol layer (byte-transparent
/// reply, no GNET header on outbound) and the
/// `GN_TRUST_ANONYMOUS_LOOPBACK` default trust class (the router
/// relaxation accepts the resulting zero-`sender_pk` envelopes
/// only on loopback-scope carriers). Both are baked into the
/// descriptor by the EX variant of the macro.

#include "raw_inject.hpp"

#include <sdk/cpp/link_plugin.hpp>

GN_LINK_PLUGIN_EX(::gn::link::raw_inject::RawInjectLink,
                  "raw-inject",
                  ::gn::link::raw_inject::kProtocolId,
                  GN_TRUST_ANONYMOUS_LOOPBACK)
