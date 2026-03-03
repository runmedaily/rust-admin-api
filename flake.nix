{
  description = "Rust Admin API — admin panel with forward auth for reverse proxies";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, fenix, crane, flake-utils }:
    let
      perSystem = flake-utils.lib.eachDefaultSystem (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          toolchain = fenix.packages.${system}.stable.toolchain;
          craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;

          # Include HTML templates, CSS, and Cargo sources in the build
          src = let
            webFilter = path: _type:
              builtins.match ".*\\.(html|css)$" path != null;
            webOrCargo = path: type:
              (webFilter path type) || (craneLib.filterCargoSources path type);
          in pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = webOrCargo;
          };

          rust-admin-api = craneLib.buildPackage {
            inherit src;
            strictDeps = true;
          };
        in
        {
          packages.default = rust-admin-api;

          devShells.default = craneLib.devShell {
            packages = with pkgs; [
              rust-analyzer
              sqlite
              wl-clipboard
            ];
            shellHook = ''
              echo "🦀 Rust Admin API dev shell"
              echo "  cargo build  — compile"
              echo "  cargo run    — start server"
            '';
          };
        });
    in
    perSystem // {
      nixosModules.rust-admin-api = import ./nix/module.nix self;
    };
}
