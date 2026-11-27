# The steps of CI that `nix flake check` runs. treefmt and git-hooks add their own checks.
_: {
  perSystem =
    {
      craneLib,
      commonArgs,
      ...
    }:
    let
      # Tests rely on debug assertions, as in CI.
      args = commonArgs // {
        CARGO_PROFILE = "dev";
        cargoExtraArgs = "--all-features";
      };
      cargoArtifacts = craneLib.buildDepsOnly args;
    in
    {
      checks = {
        cargo-clippy = craneLib.cargoClippy (
          args
          // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- -D warnings -D clippy::all";
          }
        );

        cargo-nextest = craneLib.cargoNextest (
          args
          // {
            inherit cargoArtifacts;
            # The HTTP client tests talk to a mock server on localhost.
            __darwinAllowLocalNetworking = true;
            cargoNextestExtraArgs = "--all-targets --no-fail-fast --retries 2";
          }
        );

        cargo-doc-tests = craneLib.cargoDocTest (args // { inherit cargoArtifacts; });
      };
    };
}
