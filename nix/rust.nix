# The Rust toolchain at the `rust-version` of Cargo.toml, shared by the other modules as module
# arguments: `rustToolchain`, `craneLib`, `mkCraneLib` (for cross targets) and `commonArgs`.
{ inputs, ... }:
{
  perSystem =
    { system, lib, ... }:
    let
      pkgs = import inputs.nixpkgs {
        inherit system;
        overlays = [ inputs.rust-overlay.overlays.default ];
      };
      cargoToml = fromTOML (builtins.readFile ../Cargo.toml);

      mkToolchain =
        targets:
        pkgs.rust-bin.stable.${cargoToml.package.rust-version}.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
            "llvm-tools"
          ];
          inherit targets;
        };
      mkCraneLib = targets: (inputs.crane.mkLib pkgs).overrideToolchain (_: mkToolchain targets);
      craneLib = mkCraneLib [ ];
    in
    {
      _module.args = {
        inherit pkgs craneLib mkCraneLib;
        rustToolchain = mkToolchain [ ];
        commonArgs = {
          src = craneLib.cleanCargoSource ../.;
          strictDeps = true;
          pname = "newrelic-auth-cli";
          inherit (cargoToml.package) version;
          buildInputs = lib.optional pkgs.stdenv.hostPlatform.isDarwin pkgs.libiconv;
          # The HTTP client loads the system CA roots when built, and the sandbox has none.
          SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
        };
      };
    };
}
