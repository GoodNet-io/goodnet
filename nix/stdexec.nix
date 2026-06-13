{ pkgs }:
# NVIDIA stdexec (P2300 std::execution reference implementation).
# Header-only library. We skip the upstream CMake build (it requires
# rapids-cmake) and install headers + a minimal config manually.
pkgs.stdenv.mkDerivation {
  pname   = "stdexec";
  version = "0-unstable-2025-06-03";

  src = pkgs.fetchFromGitHub {
    owner  = "NVIDIA";
    repo   = "stdexec";
    rev    = "61fb73d74782869f774ea3bfacfe5d3470de4d4d";
    sha256 = "08w6iqmlm25rjyxsgj1r58ax1if0w4dixnwzfx45bvqm2vnii46c";
  };

  dontBuild    = true;
  dontConfigure = true;

  installPhase = ''
    runHook preInstall

    mkdir -p $out/include $out/lib/cmake/stdexec

    cp -r include/stdexec $out/include/
    cp -r include/exec    $out/include/

    # Hardcode the Nix store path — fine because this is a Nix-only build.
    cat > $out/lib/cmake/stdexec/stdexec-config.cmake << EOF
if(TARGET STDEXEC::stdexec)
  return()
endif()
add_library(STDEXEC::stdexec INTERFACE IMPORTED)
target_include_directories(STDEXEC::stdexec INTERFACE "$out/include")
target_compile_features(STDEXEC::stdexec INTERFACE cxx_std_23)
EOF

    runHook postInstall
  '';

  meta = {
    description = "NVIDIA stdexec — P2300 std::execution reference implementation";
    homepage    = "https://github.com/NVIDIA/stdexec";
    license     = pkgs.lib.licenses.asl20;
  };
}
