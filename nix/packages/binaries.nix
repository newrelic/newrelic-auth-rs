# The `newrelic-auth-cli` binary: native `default` for the current system and, on Linux, the
# statically linked musl build the container images ship.
_: {
  perSystem =
    {
      config,
      pkgs,
      lib,
      system,
      ...
    }:
    let
      inherit (config) rustLib;

      mkPackage =
        craneLib: extraArgs:
        let
          args = rustLib.commonArgs // extraArgs // { cargoExtraArgs = "--bin newrelic-auth-cli"; };
        in
        craneLib.buildPackage (
          args
          // {
            cargoArtifacts = craneLib.buildDepsOnly args;
            doCheck = false;
            meta.mainProgram = "newrelic-auth-cli";
          }
        );

      muslTargets = {
        x86_64-linux = {
          triple = "x86_64-unknown-linux-musl";
          targetCc = pkgs.pkgsCross.musl64.stdenv.cc;
        };
        aarch64-linux = {
          triple = "aarch64-unknown-linux-musl";
          targetCc = pkgs.pkgsCross.aarch64-multiplatform-musl.stdenv.cc;
        };
      };

      mkMusl =
        { triple, targetCc }:
        let
          envTriple = lib.replaceStrings [ "-" ] [ "_" ] triple;
          cc = "${targetCc}/bin/${targetCc.targetPrefix}cc";
        in
        mkPackage (rustLib.mkCraneLib [ triple ]) {
          nativeBuildInputs = [ targetCc ];
          CARGO_BUILD_TARGET = triple;
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
          HOST_CC = "${pkgs.stdenv.cc}/bin/cc";
          "CC_${envTriple}" = cc;
          "CARGO_TARGET_${lib.toUpper envTriple}_LINKER" = cc;
        };
    in
    {
      packages = {
        default = mkPackage rustLib.craneLib { };
      }
      // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
        cli-musl = mkMusl muslTargets.${system};
      };
    };
}
