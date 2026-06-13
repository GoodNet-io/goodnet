// SPDX-License-Identifier: Apache-2.0
/// @file   tests/vectors/gen_capability_blob.cpp
/// @brief  Generator for `tests/vectors/capability_blob.json`.
///
/// Capability TLV blobs per `docs/contracts/capability-tlv.en.md`:
/// each record is `[type:u16 BE][length:u16 BE][value:length bytes]`.
/// The kernel intercepts msg_id `0x13` after deframe and the host_api
/// fans the bytes (minus the 8-byte BE expiry prefix) out to
/// subscribers.
///
/// We emit three samples:
///   - empty blob (zero records).
///   - kernel-allocated bitmap records: `transport-set` (0x0000),
///     `protocol-set` (0x0001), `protocol-list` (0x0002).
///   - kernel + core ranges combined with a `heartbeat-interval-ms`
///     (0x0200) entry.

#include "hex_util.hpp"

#include <sdk/cpp/capability_tlv.hpp>

#include <cstdio>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <vector>

namespace {

std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (char c : s) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

std::vector<std::uint8_t> u32_be(std::uint32_t v) {
    return {
        static_cast<std::uint8_t>((v >> 24) & 0xFFu),
        static_cast<std::uint8_t>((v >> 16) & 0xFFu),
        static_cast<std::uint8_t>((v >>  8) & 0xFFu),
        static_cast<std::uint8_t>( v        & 0xFFu),
    };
}

std::vector<std::uint8_t> i64_be(std::int64_t v) {
    auto u = static_cast<std::uint64_t>(v);
    return {
        static_cast<std::uint8_t>((u >> 56) & 0xFFu),
        static_cast<std::uint8_t>((u >> 48) & 0xFFu),
        static_cast<std::uint8_t>((u >> 40) & 0xFFu),
        static_cast<std::uint8_t>((u >> 32) & 0xFFu),
        static_cast<std::uint8_t>((u >> 24) & 0xFFu),
        static_cast<std::uint8_t>((u >> 16) & 0xFFu),
        static_cast<std::uint8_t>((u >>  8) & 0xFFu),
        static_cast<std::uint8_t>( u        & 0xFFu),
    };
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <out.json>\n", argv[0]);
        return 1;
    }

    using gn::sdk::TlvRecord;
    using gn::vectors::hex_encode;

    auto hex = [](std::span<const std::uint8_t> b) {
        return json_escape(hex_encode(b));
    };

    // Sample 1: empty blob.
    std::vector<TlvRecord> empty_records;

    // Sample 2: kernel-range records.
    // `transport-set` (0x0000): bitmap "TCP|UDP|IPC" = 0x07.
    // `protocol-set`  (0x0001): bitmap "gnet-v1" only = 0x01.
    // `protocol-list` (0x0002): UTF-8 newline-separated list.
    std::vector<TlvRecord> kernel_records = {
        TlvRecord{0x0000u, u32_be(0x00000007u)},
        TlvRecord{0x0001u, u32_be(0x00000001u)},
        TlvRecord{0x0002u, {'g','n','e','t','-','v','1','\n'}},
    };

    // Sample 3: kernel + core ranges with heartbeat-interval-ms.
    std::vector<TlvRecord> full_records = {
        TlvRecord{0x0000u, u32_be(0x00000007u)},
        TlvRecord{0x0001u, u32_be(0x00000001u)},
        TlvRecord{0x0002u, {'g','n','e','t','-','v','1','\n'}},
        TlvRecord{0x0200u, u32_be(15000u)},  // heartbeat 15s
    };

    // Sample 4: forward-compat — unknown type 0x1000 in application
    // range with arbitrary value. Consumer must skip the record.
    std::vector<TlvRecord> with_unknown = {
        TlvRecord{0x0000u, u32_be(0x00000007u)},
        TlvRecord{0x1000u, {'u','n','k','n','o','w','n','-','v','a','l','u','e'}},
        TlvRecord{0x0200u, u32_be(30000u)},
    };

    auto encode_or_die = [&](std::span<const TlvRecord> recs) {
        auto enc = gn::sdk::encode_tlv(recs);
        if (!enc) {
            std::fprintf(stderr, "encode_tlv failed\n");
            std::exit(1);
        }
        return *enc;
    };

    auto empty_blob   = encode_or_die(empty_records);
    auto kernel_blob  = encode_or_die(kernel_records);
    auto full_blob    = encode_or_die(full_records);
    auto unknown_blob = encode_or_die(with_unknown);

    // host_api ships the blob prefixed with the 8-byte BE expiry. The
    // generator commits the prefix-form alongside the bare blob so a
    // language binding can replay either path.
    constexpr std::int64_t kExpiryUnixTs = 2'000'000'000;
    auto with_prefix = [&](const std::vector<std::uint8_t>& blob) {
        auto prefix = i64_be(kExpiryUnixTs);
        std::vector<std::uint8_t> out;
        out.reserve(8 + blob.size());
        out.insert(out.end(), prefix.begin(), prefix.end());
        out.insert(out.end(), blob.begin(), blob.end());
        return out;
    };
    auto kernel_wire  = with_prefix(kernel_blob);
    auto full_wire    = with_prefix(full_blob);
    auto unknown_wire = with_prefix(unknown_blob);

    auto render_records = [&](std::span<const TlvRecord> recs, int indent) {
        std::string pad(indent, ' ');
        std::string out;
        out += pad + "[\n";
        for (std::size_t i = 0; i < recs.size(); ++i) {
            out += pad + "  {\n";
            out += pad + "    " + json_escape("type")
                + ": " + std::to_string(recs[i].type) + ",\n";
            out += pad + "    " + json_escape("type_hex") + ": "
                 + json_escape([&] {
                       std::array<std::uint8_t, 2> tb = {
                           static_cast<std::uint8_t>(recs[i].type >> 8),
                           static_cast<std::uint8_t>(recs[i].type & 0xFFu),
                       };
                       return hex_encode(tb);
                   }()) + ",\n";
            out += pad + "    " + json_escape("value_len")
                + ": " + std::to_string(recs[i].value.size()) + ",\n";
            out += pad + "    " + json_escape("value")
                + ": " + json_escape(hex_encode(recs[i].value)) + "\n";
            out += pad + "  }" + (i + 1 < recs.size() ? "," : "") + "\n";
        }
        out += pad + "]";
        return out;
    };

    std::string body;
    body += "{\n";
    body += "  " + std::string(json_escape("schema")) + ": "
         + json_escape("capability-tlv/v1") + ",\n";
    body += "  " + std::string(json_escape("description")) + ": "
         + json_escape(
            "Capability TLV blobs per docs/contracts/capability-tlv.en.md. "
            "Each record is [type:u16 BE][length:u16 BE][value]. "
            "The on-wire host_api form prefixes the blob with an 8-byte "
            "big-endian expiry_unix_ts; the 'wire_with_prefix' field "
            "carries that variant.") + ",\n";
    body += "  " + std::string(json_escape("system_msg_id")) + ": 19,\n";
    body += "  " + std::string(json_escape("expiry_unix_ts_for_prefix"))
         + ": " + std::to_string(kExpiryUnixTs) + ",\n";

    body += "  " + std::string(json_escape("samples")) + ": [\n";

    body += "    {\n";
    body += "      " + std::string(json_escape("tag")) + ": "
         + json_escape("empty") + ",\n";
    body += "      " + std::string(json_escape("description")) + ": "
         + json_escape("baseline build emits no records — peer parses "
                       "to zero records") + ",\n";
    body += "      " + std::string(json_escape("records")) + ":\n";
    body += render_records(empty_records, 6) + ",\n";
    body += "      " + std::string(json_escape("blob")) + ": "
         + hex(empty_blob) + "\n";
    body += "    },\n";

    body += "    {\n";
    body += "      " + std::string(json_escape("tag")) + ": "
         + json_escape("kernel_records") + ",\n";
    body += "      " + std::string(json_escape("description")) + ": "
         + json_escape("transport-set + protocol-set + protocol-list "
                       "(kernel range 0x0000..0x00ff)") + ",\n";
    body += "      " + std::string(json_escape("records")) + ":\n";
    body += render_records(kernel_records, 6) + ",\n";
    body += "      " + std::string(json_escape("blob")) + ": "
         + hex(kernel_blob) + ",\n";
    body += "      " + std::string(json_escape("wire_with_prefix")) + ": "
         + hex(kernel_wire) + "\n";
    body += "    },\n";

    body += "    {\n";
    body += "      " + std::string(json_escape("tag")) + ": "
         + json_escape("kernel_plus_core") + ",\n";
    body += "      " + std::string(json_escape("description")) + ": "
         + json_escape("kernel range entries + heartbeat-interval-ms "
                       "(0x0200, core range)") + ",\n";
    body += "      " + std::string(json_escape("records")) + ":\n";
    body += render_records(full_records, 6) + ",\n";
    body += "      " + std::string(json_escape("blob")) + ": "
         + hex(full_blob) + ",\n";
    body += "      " + std::string(json_escape("wire_with_prefix")) + ": "
         + hex(full_wire) + "\n";
    body += "    },\n";

    body += "    {\n";
    body += "      " + std::string(json_escape("tag")) + ": "
         + json_escape("with_unknown_application_type") + ",\n";
    body += "      " + std::string(json_escape("description")) + ": "
         + json_escape("known record + application-range unknown type "
                       "0x1000 + heartbeat — consumer must skip the "
                       "unknown record and parse the rest") + ",\n";
    body += "      " + std::string(json_escape("records")) + ":\n";
    body += render_records(with_unknown, 6) + ",\n";
    body += "      " + std::string(json_escape("blob")) + ": "
         + hex(unknown_blob) + ",\n";
    body += "      " + std::string(json_escape("wire_with_prefix")) + ": "
         + hex(unknown_wire) + "\n";
    body += "    }\n";

    body += "  ]\n";
    body += "}\n";

    std::ofstream out(argv[1]);
    if (!out) {
        std::fprintf(stderr, "cannot open %s\n", argv[1]);
        return 1;
    }
    out << body;
    out.close();

    std::cout << "wrote " << argv[1] << " (" << body.size() << " bytes)\n";
    return 0;
}
