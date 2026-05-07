/// @file   apps/gssh/peers.cpp
/// @brief  Implementation of the peers.json catalogue parser.
///
/// Uses `nlohmann::json` to keep the parser short and the error
/// reporting accurate. The catalogue is small (typical operator has
/// fewer than 100 known peers) so a one-shot parse on every bridge
/// invocation is cheaper than caching, and avoids stale-cache bugs
/// when the operator edits the file mid-session.

#include "peers.hpp"

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <pwd.h>
#include <sstream>
#include <unistd.h>

#include <nlohmann/json.hpp>

namespace gn::apps::gssh {

namespace {

/// Resolve `$HOME` with a `getpwuid` fallback. The fallback covers
/// the systemd-service case where the unit file forgot to set `User=`
/// and the resulting environment has no `$HOME`.
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

std::string default_peers_path() {
    namespace fs = std::filesystem;
    return (fs::path{resolve_home_dir()} / ".config" / "goodnet" / "peers.json")
        .string();
}

std::vector<PeerEntry>
parse_peers(const std::string& path, std::string& diagnostic) {
    std::vector<PeerEntry> out;
    diagnostic.clear();

    std::ifstream f(path, std::ios::binary);
    if (!f) {
        // Missing file is not an error here — caller decides whether
        // to fail the operation or fall back to the override URI.
        return out;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    const auto blob = ss.str();

    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(blob, /*cb*/ nullptr, /*allow_exceptions*/ true,
                                     /*ignore_comments*/ true);
    } catch (const std::exception& ex) {
        diagnostic = std::string{"parse error: "} + ex.what();
        return out;
    }
    if (!doc.is_object()) {
        diagnostic = "top-level JSON must be an object";
        return out;
    }
    const auto it = doc.find("peers");
    if (it == doc.end()) {
        diagnostic = "missing required key \"peers\"";
        return out;
    }
    if (!it->is_array()) {
        diagnostic = "\"peers\" must be an array";
        return out;
    }

    out.reserve(it->size());
    for (const auto& entry : *it) {
        if (!entry.is_object()) {
            diagnostic = "every \"peers\" element must be an object";
            out.clear();
            return out;
        }
        PeerEntry pe;
        if (auto pk_it = entry.find("pk");
            pk_it != entry.end() && pk_it->is_string()) {
            pe.pk = pk_it->get<std::string>();
        } else {
            diagnostic = "every entry needs a \"pk\" string";
            out.clear();
            return out;
        }
        if (auto name_it = entry.find("name");
            name_it != entry.end() && name_it->is_string()) {
            pe.name = name_it->get<std::string>();
        }
        if (auto uris_it = entry.find("uris");
            uris_it != entry.end() && uris_it->is_array()) {
            pe.uris.reserve(uris_it->size());
            for (const auto& u : *uris_it) {
                if (u.is_string()) pe.uris.push_back(u.get<std::string>());
            }
        }
        out.push_back(std::move(pe));
    }
    return out;
}

std::optional<std::string>
resolve_peer_uri(std::string_view peer_pk_str,
                 const std::vector<PeerEntry>& peers) {
    for (const auto& pe : peers) {
        if (pe.pk == peer_pk_str && !pe.uris.empty()) {
            // First URI wins. The catalogue is operator-curated; if
            // the operator wants ICE preferred over a stale TCP, they
            // list `ice://` first.
            return pe.uris.front();
        }
    }
    return std::nullopt;
}

}  // namespace gn::apps::gssh
