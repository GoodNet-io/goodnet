/// @file   apps/goodnet-ssh/peers.hpp
/// @brief  Peer-pk → URI lookup with a flat JSON catalogue.
///
/// `~/.config/goodnet/peers.json` is the operator's address book.
/// One entry per known peer; each entry pins one or more transport
/// URIs the bridge can dial. The lookup picks the first reachable
/// URI in the order the catalogue lists them — operators put the
/// preferred path first (LAN, then ICE, then relay) and the bridge
/// honours that ordering.
///
/// File format (parsed once per bridge invocation):
///
/// @code
/// {
///   "peers": [
///     { "pk": "<base32-pk>",
///       "uris": ["tcp://192.168.1.5:9000", "ice://"],
///       "name": "alice-laptop" }
///   ]
/// }
/// @endcode
///
/// The catalogue is operator-curated: a missing peer is a deploy-
/// time error, not a runtime fault, so the bridge prints a clear
/// «add an entry» hint instead of falling back to a nameservice.

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace gn::apps::goodnet_ssh {

/// One peer record loaded from the catalogue.
struct PeerEntry {
    std::string              pk;     //< base32-encoded Ed25519 device pk
    std::string              name;   //< optional friendly label
    std::vector<std::string> uris;   //< ordered transport URIs
};

/// Resolve `~/.config/goodnet/peers.json` (or the override path).
/// Returns an absolute path; tilde-expansion uses `$HOME` when set,
/// or the user's `getpwuid(getuid())->pw_dir` as a fallback.
[[nodiscard]] std::string default_peers_path();

/// Parse @p path into a flat vector of `PeerEntry`. Missing file
/// returns an empty vector — the catch site in `mode_bridge.cpp`
/// prints the «add an entry» hint with the resolved path so the
/// operator knows where to write the file. Malformed JSON returns
/// an empty vector with a diagnostic written to @p diagnostic.
[[nodiscard]] std::vector<PeerEntry>
parse_peers(const std::string& path, std::string& diagnostic);

/// Pick the URI for @p peer_pk_str out of the catalogue.
///
/// The selection order follows the catalogue: the first entry whose
/// scheme is dialable wins. Schemes the kernel recognises (no plugin
/// or extension check is performed here — the bridge attempts the
/// dial and lets `gn_core_connect` surface the failure) are `tcp`,
/// `udp`, `ws`, `ipc`, `tls`. `ice://` requires the ICE plugin to be
/// loaded; the bridge's dial attempt fails with `GN_ERR_NOT_FOUND`
/// when the plugin is absent and the operator falls back to a tcp
/// URI on the next bridge invocation.
///
/// Returns `nullopt` when no entry matches @p peer_pk_str. The bridge
/// prints the resolved peers.json path in the diagnostic so the
/// operator's edit lands in the right place.
[[nodiscard]] std::optional<std::string>
resolve_peer_uri(std::string_view peer_pk_str,
                 const std::vector<PeerEntry>& peers);

}  // namespace gn::apps::goodnet_ssh
