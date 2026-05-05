# Standalone Nix derivation for the goodnet-link-tcp plugin.
# Pulls the kernel SDK + AddPlugin.cmake helper through `goodnet-core`'s
# `propagatedBuildInputs` (asio / libsodium / openssl / spdlog / fmt /
# nlohmann_json). Build artefacts: `lib<goodnet_link_tcp>.so`
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
  pname   = "goodnet-link-tcp";
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
    description = "GoodNet plugin: goodnet-link-tcp";
    license = lib.licenses.asl20;
    platforms = lib.platforms.linux;
  };
}
