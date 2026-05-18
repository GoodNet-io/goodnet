#include <cstddef>
#include <cstdint>
#include <span>

#include <plugins/links/ice/mdns.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    (void) gn::link::ice::parse_dns_message(
        std::span<const std::uint8_t>(data, size));
    return 0;
}
