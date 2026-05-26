{ stdenv, cmake, ninja, pkg-config
, goodnet-core, protocol-gnet, link-tcp, security-noise
, libsodium
}:

stdenv.mkDerivation {
  pname   = "goodnet-examples";
  version = "1.0.0";

  src = ./.;

  nativeBuildInputs = [ cmake ninja pkg-config ];
  buildInputs       = [ goodnet-core protocol-gnet link-tcp security-noise libsodium ];

  cmakeFlags = [
    "-DGOODNET_NOISE_PLUGIN_PATH=${security-noise}/lib/libgoodnet_security_noise.so"
    "-DGOODNET_TCP_PLUGIN_PATH=${link-tcp}/lib/libgoodnet_link_tcp.so"
  ];

  installPhase = ''
    runHook preInstall
    install -Dm755 bin/goodnet-demo        "$out/bin/goodnet-demo"
    install -Dm755 bin/hello-echo-client   "$out/bin/hello-echo-client"
    install -Dm755 bin/hello-echo-server   "$out/bin/hello-echo-server"
    runHook postInstall
  '';

  meta = {
    description = "GoodNet SDK examples (two_node, hello-echo).";
  };
}
