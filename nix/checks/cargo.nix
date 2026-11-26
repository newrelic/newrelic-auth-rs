# Cargo steps of CI that `nix flake check` runs: rustfmt, clippy and the tests.
# treefmt and git-hooks contribute their own checks from their modules.
_: {
  perSystem =
    { config, pkgs, ... }:
    let
      inherit (config) rustLib;
      inherit (rustLib) craneLib;
      workspaceArgs = rustLib.commonArgs // {
        cargoExtraArgs = "--all-features";
        # Tests rely on debug assertions, as in CI.
        CARGO_PROFILE = "dev";
      };
      cargoArtifacts = craneLib.buildDepsOnly workspaceArgs;
    in
    {
      checks = {
        cargo-clippy = craneLib.cargoClippy (
          workspaceArgs
          // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- -D warnings -D clippy::all";
          }
        );

        cargo-nextest = craneLib.cargoNextest (
          workspaceArgs
          // {
            inherit cargoArtifacts;
            # The HTTP client tests talk to a mock server on localhost, which the macOS sandbox blocks by default.
            __darwinAllowLocalNetworking = true;
            # The HTTP clients load the system CA roots when built, and the sandbox has none.
            SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
            cargoNextestExtraArgs = "--all-targets --no-fail-fast --retries 2";
          }
        );

        cargo-doc-tests = craneLib.cargoDocTest (workspaceArgs // { inherit cargoArtifacts; });

        cargo-fmt = craneLib.cargoFmt {
          inherit (rustLib) src;
          inherit (rustLib.commonArgs) pname version;
        };
      };
    };
}
