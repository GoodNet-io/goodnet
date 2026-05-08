# Standalone Nix derivation for the goodnet-protocol-gnet plugin.
# Pulls the kernel SDK + AddPlugin.cmake helper through `goodnet-core`'s
# `propagatedBuildInputs` (asio / libsodium / openssl / spdlog / fmt /
# nlohmann_json). Build artefacts: `lib<goodnet_protocol_gnet>.so`
# + plugin manifest line.
{ stdenv
, cmake
, ninja
, pkg-config
, gtest
, rapidcheck
, goodnet-core
, lib
}:

stdenv.mkDerivation {
  pname   = "goodnet-protocol-gnet";
  version = "0.1.0";
  src     = ./.;
  nativeBuildInputs = [ cmake ninja pkg-config ];
  buildInputs       = [ goodnet-core gtest rapidcheck ];
  cmakeFlags = [
    "-DCMAKE_BUILD_TYPE=Release"
    "-DBUILD_TESTING=OFF"
  ];
  doCheck = false;

  meta = {
    description = "GoodNet plugin: goodnet-protocol-gnet";
    license = lib.licenses.gpl2Only;  # GPL-2.0 with Linking Exception (see LICENSE)
    platforms = lib.platforms.linux;
  };
}
