/// @file   core/kernel/service_resolver.cpp
/// @brief  Implementation of the ext-graph toposort + inject-cycle check.

#include "service_resolver.hpp"

#include <cstdint>
#include <flat_map>
#include <queue>
#include <unordered_set>

namespace gn::core {

namespace {

void note(std::string* sink, std::string_view msg) {
    if (sink) *sink = msg;
}

} // namespace

gn_result_t ServiceResolver::resolve(
    std::span<const ServiceDescriptor> input,
    std::vector<ServiceDescriptor>& out_ordered,
    std::string* out_diagnostic) {

    out_ordered.clear();
    if (input.empty()) return GN_OK;

    /// Map every provided extension name to the plugin index that
    /// provides it. Duplicate provider → reject.
    std::flat_map<std::string, std::size_t, std::less<>> provider_of_ext;
    for (std::size_t i = 0; i < input.size(); ++i) {
        for (const auto& ext : input[i].ext_provides) {
            auto [it, inserted] = provider_of_ext.try_emplace(ext, i);
            if (!inserted) {
                std::string diag = "duplicate provider for extension '";
                diag += ext;
                diag += "': ";
                diag += input[it->second].plugin_name;
                diag += " and ";
                diag += input[i].plugin_name;
                note(out_diagnostic, diag);
                return GN_ERR_LIMIT_REACHED;
            }
        }
    }

    /// Adjacency: provider plugin index → consumers that require
    /// extensions from that provider.
    std::vector<std::vector<std::size_t>> consumers(input.size());
    std::vector<std::size_t>              in_degree(input.size(), 0);

    for (std::size_t i = 0; i < input.size(); ++i) {
        for (const auto& req : input[i].ext_requires) {
            auto it = provider_of_ext.find(req);
            if (it == provider_of_ext.end()) {
                std::string diag = "unresolved extension '";
                diag += req;
                diag += "' required by ";
                diag += input[i].plugin_name;
                note(out_diagnostic, diag);
                return GN_ERR_NOT_FOUND;
            }
            const std::size_t provider_idx = it->second;
            if (provider_idx == i) continue; // self-provide is fine
            consumers[provider_idx].push_back(i);
            in_degree[i]++;
        }
    }

    /// Kahn's algorithm: queue every node with no unsatisfied
    /// requirement, then drain by decrementing consumer degrees.
    std::queue<std::size_t> ready;
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (in_degree[i] == 0) ready.push(i);
    }

    out_ordered.reserve(input.size());
    while (!ready.empty()) {
        const std::size_t i = ready.front();
        ready.pop();
        out_ordered.push_back(input[i]);
        for (std::size_t j : consumers[i]) {
            if (--in_degree[j] == 0) ready.push(j);
        }
    }

    if (out_ordered.size() != input.size()) {
        /// Whatever remains is part of one or more cycles.
        std::string diag = "cycle through plugins:";
        for (std::size_t i = 0; i < input.size(); ++i) {
            if (in_degree[i] > 0) {
                diag += ' ';
                diag += input[i].plugin_name;
            }
        }
        note(out_diagnostic, diag);
        out_ordered.clear();
        return GN_ERR_INVALID_ENVELOPE;
    }

    // ── Inject-cycle pass ─────────────────────────────────────────────────────
    // Build a directed graph: plugin A → plugin B when A injects into a
    // (protocol_id, msg_id) pair that B handles. A wildcard msg_id (0) on
    // either side creates an edge to/from every handler of that protocol.
    // Then run Kahn's algorithm on the inject graph to detect cycles.
    //
    // Plugins that declare neither inject_targets nor inject_handles do not
    // participate in this graph and are skipped.

    // Map (protocol_id, msg_id==0=wildcard) → list of handler plugin indices.
    // Exact match wins; wildcard 0 covers any msg_id in that protocol.
    std::flat_map<std::string, std::vector<std::size_t>, std::less<>> handlers_by_proto;
    std::flat_map<std::string, std::vector<std::size_t>, std::less<>> handlers_by_exact; // "proto:msgid"

    auto exact_key = [](const std::string& proto, std::uint32_t msg) {
        return proto + ':' + std::to_string(msg);
    };

    for (std::size_t i = 0; i < input.size(); ++i) {
        for (const auto& [proto, msg] : input[i].inject_handles) {
            handlers_by_proto[proto].push_back(i);
            if (msg != 0)
                handlers_by_exact[exact_key(proto, msg)].push_back(i);
        }
    }

    // Build inject adjacency list: injector → set of handlers it feeds.
    std::vector<std::vector<std::size_t>> inject_consumers(input.size());
    std::vector<std::size_t>              inject_in_degree(input.size(), 0);

    for (std::size_t i = 0; i < input.size(); ++i) {
        std::unordered_set<std::size_t> seen;
        for (const auto& [proto, msg] : input[i].inject_targets) {
            // Wildcard injector (msg==0): edge to every handler of proto.
            if (msg == 0) {
                auto it = handlers_by_proto.find(proto);
                if (it != handlers_by_proto.end()) {
                    for (std::size_t j : it->second) {
                        if (j != i && seen.insert(j).second) {
                            inject_consumers[i].push_back(j);
                            inject_in_degree[j]++;
                        }
                    }
                }
            } else {
                // Exact match.
                auto it = handlers_by_exact.find(exact_key(proto, msg));
                if (it != handlers_by_exact.end()) {
                    for (std::size_t j : it->second) {
                        if (j != i && seen.insert(j).second) {
                            inject_consumers[i].push_back(j);
                            inject_in_degree[j]++;
                        }
                    }
                }
                // Also include wildcard handlers for this protocol.
                auto wit = handlers_by_proto.find(proto);
                if (wit != handlers_by_proto.end()) {
                    for (std::size_t j : wit->second) {
                        if (j != i && seen.insert(j).second) {
                            inject_consumers[i].push_back(j);
                            inject_in_degree[j]++;
                        }
                    }
                }
            }
        }
    }

    // Kahn's on inject graph — skip nodes with no inject edges.
    std::queue<std::size_t> inject_ready;
    std::size_t inject_node_count = 0;
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (!input[i].inject_targets.empty() || !input[i].inject_handles.empty()) {
            ++inject_node_count;
            if (inject_in_degree[i] == 0) inject_ready.push(i);
        }
    }

    std::size_t inject_visited = 0;
    while (!inject_ready.empty()) {
        const std::size_t i = inject_ready.front();
        inject_ready.pop();
        ++inject_visited;
        for (std::size_t j : inject_consumers[i]) {
            if (--inject_in_degree[j] == 0) inject_ready.push(j);
        }
    }

    if (inject_visited < inject_node_count) {
        std::string diag = "inject cycle through plugins:";
        for (std::size_t i = 0; i < input.size(); ++i) {
            if (inject_in_degree[i] > 0) {
                diag += ' ';
                diag += input[i].plugin_name;
            }
        }
        note(out_diagnostic, diag);
        out_ordered.clear();
        return GN_ERR_INVALID_ENVELOPE;
    }

    return GN_OK;
}

} // namespace gn::core
