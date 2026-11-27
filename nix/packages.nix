# The `newrelic-auth-cli` binary and its container images. On Linux the binary is linked statically
# against musl, so an image needs nothing but the binary and the CA bundle: no shell, no package
# manager and no libc.
_: {
  perSystem =
    {
      pkgs,
      lib,
      craneLib,
      mkCraneLib,
      commonArgs,
      config,
      ...
    }:
    let
      args = commonArgs // {
        cargoExtraArgs = "--bin newrelic-auth-cli";
      };
      build =
        craneLib: extraArgs:
        craneLib.buildPackage (
          args
          // extraArgs
          // {
            cargoArtifacts = craneLib.buildDepsOnly (args // extraArgs);
            doCheck = false;
            meta.mainProgram = "newrelic-auth-cli";
          }
        );

      # Static build for the architecture of the host.
      static = pkgs.pkgsStatic;
      triple = static.stdenv.hostPlatform.rust.rustcTarget;
      envTriple = lib.replaceStrings [ "-" ] [ "_" ] triple;
      cc = "${static.stdenv.cc}/bin/${static.stdenv.cc.targetPrefix}cc";
      cliStatic = build (mkCraneLib [ triple ]) {
        nativeBuildInputs = [ static.stdenv.cc ];
        CARGO_BUILD_TARGET = triple;
        CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        HOST_CC = "${pkgs.stdenv.cc}/bin/cc";
        "CC_${envTriple}" = cc;
        "CARGO_TARGET_${lib.toUpper envTriple}_LINKER" = cc;
      };

      mkImage =
        extraContents:
        pkgs.dockerTools.buildLayeredImage {
          name = "newrelic/agent-control-system-identity-registration";
          tag = "nix";
          contents = [ cliStatic ] ++ extraContents;
          config = {
            Entrypoint = [ "${cliStatic}/bin/newrelic-auth-cli" ];
            # `nobody`, by id: there is no passwd file to resolve the name.
            User = "65534:65534";
            Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
          };
        };
    in
    {
      packages = {
        default = build craneLib { };
      }
      // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
        cli-static = cliStatic;
        docker-image = mkImage [ ];
        # What the Dockerfile ships: kubectl and jq are kept for older init containers.
        docker-image-with-kubectl = mkImage [
          pkgs.kubectl
          pkgs.jq
        ];
      };
    };
}
