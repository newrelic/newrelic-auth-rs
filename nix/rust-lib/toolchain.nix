# Values of the `rustLib` options (see options.nix): the Rust toolchain, crane and the sources and
# arguments of the builds.
{ inputs, ... }:
{
  perSystem =
    { pkgs, lib, ... }:
    let
      cargoToml = fromTOML (builtins.readFile ../../Cargo.toml);
      rustVersion = cargoToml.package.rust-version;

      mkToolchain =
        targets:
        pkgs.rust-bin.stable.${rustVersion}.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
            "llvm-tools"
          ];
          inherit targets;
        };

      mkCraneLib = targets: (inputs.crane.mkLib pkgs).overrideToolchain (_: mkToolchain targets);

      toolchain = mkToolchain [ ];
      craneLib = mkCraneLib [ ];

      src = craneLib.cleanCargoSource ../../.;

      commonArgs = {
        inherit src;
        strictDeps = true;
        pname = "newrelic-auth-cli";
        inherit (cargoToml.package) version;
        buildInputs = lib.optionals pkgs.stdenv.hostPlatform.isDarwin [ pkgs.libiconv ];
      };
    in
    {
      config.rustLib = {
        inherit
          rustVersion
          toolchain
          mkCraneLib
          craneLib
          src
          commonArgs
          ;
      };
    };
}
