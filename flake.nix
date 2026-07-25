{
  description = "chainql";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/release-26.05";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };
  outputs =
    {
      nixpkgs,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
        rust = (
          pkgs.rust-bin.stable.latest.default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
            ];
            targets = [
              "x86_64-unknown-linux-musl"
              "x86_64-unknown-linux-gnu"
            ];
            enableLibsecret = false;
          }
        );
      in
      rec {
        devShell = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            rust
            gdb
            just
            llvmPackages_22.libllvm.out
          ];
        };
      }
    );
}
