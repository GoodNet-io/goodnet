#include <cstddef>
#include <cstdint>
#include <span>

#include <plugins/protocols/gnet/wire.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    gn::plugins::gnet::wire::ParsedHeader hdr{};
    (void) gn::plugins::gnet::wire::parse_header(
        std::span<const std::uint8_t>(data, size), hdr);
    return 0;
}
