# `nix develop`: the pinned toolchain and the tools the Makefile and CI use. Entering the shell
# also installs the git hooks and provides `nix fmt`'s tools.
_: {
  perSystem =
    {
      config,
      pkgs,
      craneLib,
      ...
    }:
    {
      devShells.default = craneLib.devShell {
        inputsFrom = [
          config.treefmt.build.devShell
          config.pre-commit.devShell
        ];
        packages = with pkgs; [
          actionlint
          cargo-deny
          cargo-llvm-cov
          cargo-nextest
          gnumake
        ];
      };
    };
}
