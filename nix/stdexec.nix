{ pkgs }:
# NVIDIA stdexec (P2300 std::execution reference implementation).
# Header-only library; installs include/ and CMake config.
# Used under -DGOODNET_CXX26_EXEC=ON for P2300 migration (Slice 1+).
pkgs.stdenv.mkDerivation {
  pname   = "stdexec";
  version = "0-unstable-2025-06-03";

  src = pkgs.fetchFromGitHub {
    owner  = "NVIDIA";
    repo   = "stdexec";
    rev    = "61fb73d74782869f774ea3bfacfe5d3470de4d4d";
    sha256 = "08w6iqmlm25rjyxsgj1r58ax1if0w4dixnwzfx45bvqm2vnii46c";
  };

  nativeBuildInputs = with pkgs; [ cmake ninja ];

  cmakeFlags = [
    "-DSTDEXEC_BUILD_TESTS=OFF"
    "-DSTDEXEC_BUILD_EXAMPLES=OFF"
    "-DCMAKE_CXX_SCAN_FOR_MODULES=OFF"
  ];

  meta = {
    description = "NVIDIA stdexec — P2300 std::execution reference implementation";
    homepage    = "https://github.com/NVIDIA/stdexec";
    license     = pkgs.lib.licenses.asl20;
  };
}
