{
  lib,
  stdenv,
  cmake,
  ninja,
}:
stdenv.mkDerivation {
  pname = "mithril";
  version = "0.2.1";
  src = ./.;

  nativeBuildInputs = [
    cmake
    ninja
  ];

  cmakeFlags = [
    "-DCMAKE_BUILD_TYPE=Release"
  ];

  meta = with lib; {
    description = "IoT static scanner for secrets, SBOM, CVEs and more";
    homepage = "https://github.com/nmatt0/mithril";
    license = licenses.mit;
    maintainers = [ ];
    platforms = platforms.unix;
    mainProgram = "mithril";
  };
}
