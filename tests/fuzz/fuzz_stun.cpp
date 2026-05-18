#include <cstddef>
#include <cstdint>
#include <span>

#include <plugins/links/ice/stun.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const auto bytes = std::span<const uint8_t>(data, size);
    (void) gn::link::ice::parse_stun(bytes);
    (void) gn::link::ice::parse_channel_data(bytes);
    (void) gn::link::ice::is_channel_data(bytes);
    return 0;
}
