# Null security provider — loopback / debug pass-through. Per
# `security-trust.md` §4-§5 only permitted on Loopback / IntraNode
# trust classes by default; production deployments do not load this
# plugin.

add_plugin(goodnet_security_null
    null.cpp
)

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
