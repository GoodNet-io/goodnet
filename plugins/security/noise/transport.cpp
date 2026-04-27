// SPDX-License-Identifier: Apache-2.0
#include "transport.hpp"

// All transport-state operations are inline in the header. This .cpp
// exists so the build system has a translation unit per declared source
// in `CMakeLists.txt`, keeping the build-system listing symmetric with
// the rest of the plugin's primitives.

namespace gn::noise {
} // namespace gn::noise
