#include <cstddef>
#include <cstdint>
#include <span>

#include <plugins/links/ws/wire.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    (void) gn::link::ws::wire::parse_frame_header(
        std::span<const std::uint8_t>(data, size));
    return 0;
}
