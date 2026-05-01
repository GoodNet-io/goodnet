/// @file   core/kernel/service_resolver.cpp
/// @brief  Implementation of the ext-graph toposort.

#include "service_resolver.hpp"

#include <queue>
#include <unordered_map>
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
    std::unordered_map<std::string, std::size_t> provider_of_ext;
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

    return GN_OK;
}

} // namespace gn::core
