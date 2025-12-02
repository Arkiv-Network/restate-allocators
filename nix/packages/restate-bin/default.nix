{ pkgs, system }:
let
  version = "v1.5.0";

  restateBinVersions = builtins.fromJSON (builtins.readFile (toString ./hashes.json));

  fetchBin =
    { component, system }:
    let
      downloadSpec = restateBinVersions.${system};
      versionSpec = downloadSpec.hashes;
    in
    pkgs.fetchurl {
      url = "https://restate.gateway.scarf.sh/${version}/restate-${component}-${downloadSpec.platformSuffix}.tar.xz";
      hash = versionSpec.${component};
    };
in
pkgs.stdenvNoCC.mkDerivation {
  name = "restate-bin";
  inherit version;

  src = [
    (fetchBin {
      component = "cli";
      inherit system;
    })
    (fetchBin {
      component = "server";
      inherit system;
    })
  ];

  sourceRoot = ".";

  installPhase = ''
    mkdir -p $out/bin
    ls -alsph "."
    cp -v ./restate-cli-${restateBinVersions.${system}.platformSuffix}/restate $out/bin/restate
    cp -v ./restate-server-${
      restateBinVersions.${system}.platformSuffix
    }/restate-server $out/bin/restate-server
  '';
}
