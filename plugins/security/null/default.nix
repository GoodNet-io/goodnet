# Standalone Nix derivation for the goodnet-security-null plugin.
# Pulls the kernel SDK + AddPlugin.cmake helper through `goodnet-core`'s
# `propagatedBuildInputs` (asio / libsodium / openssl / spdlog / fmt /
# nlohmann_json). Build artefacts: `lib<goodnet_security_null>.so`
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
  pname   = "goodnet-security-null";
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
    description = "GoodNet plugin: goodnet-security-null";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
}
