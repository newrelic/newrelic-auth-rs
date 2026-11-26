# Container images of the CLI, for the architecture of the build host. Each image holds the static
# binary, the CA bundle it needs to reach New Relic, and nothing else: no shell, no package manager
# and no libc.
_: {
  perSystem =
    {
      config,
      pkgs,
      lib,
      ...
    }:
    let
      cli = config.packages.cli-musl;
      caBundle = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";

      mkImage =
        extraContents:
        pkgs.dockerTools.buildLayeredImage {
          name = "newrelic/agent-control-system-identity-registration";
          tag = "nix";
          contents = [ cli ] ++ extraContents;
          config = {
            Entrypoint = [ "${cli}/bin/newrelic-auth-cli" ];
            # Same as `nobody`, by id: there is no passwd file to resolve the name.
            User = "65534:65534";
            Env = [
              "SSL_CERT_FILE=${caBundle}"
            ];
          };
        };
    in
    {
      packages = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
        docker-image = mkImage [ ];

        # What the Dockerfile ships: kubectl is kept for the init containers of older
        # agent-control-deployment charts, and jq with it.
        docker-image-with-kubectl = mkImage [
          pkgs.kubectl
          pkgs.jq
        ];
      };
    };
}
