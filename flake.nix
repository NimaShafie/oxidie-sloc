{
  description = "oxide-sloc — IEEE 1045-1992 SLOC analysis, test detection, and code metrics workbench";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        # Pin to the toolchain version declared in rust-toolchain.toml
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        nativeBuildInputs = with pkgs; [
          rustToolchain
          pkg-config
        ];

        buildInputs = with pkgs; [
          openssl
        ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
          wayland
          libxkbcommon
          gtk3
          xdotool
        ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
          darwin.apple_sdk.frameworks.AppKit
          darwin.apple_sdk.frameworks.CoreFoundation
        ];

      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "oxide-sloc";
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;

          src = pkgs.lib.cleanSource ./.;

          cargoLock.lockFile = ./Cargo.lock;

          inherit nativeBuildInputs buildInputs;

          # rfd (native file picker) is not needed for CLI-only builds
          buildFeatures = [];
          cargoBuildFlags = [ "-p" "oxide-sloc" "--no-default-features" ];

          meta = with pkgs.lib; {
            description = "IEEE 1045-1992 SLOC analysis, test detection, and code metrics workbench";
            homepage = "https://github.com/oxide-sloc/oxide-sloc";
            license = licenses.agpl3Plus;
            maintainers = [ maintainers.NimaShafie ];
            mainProgram = "oxide-sloc";
          };
        };

        devShells.default = pkgs.mkShell {
          inherit buildInputs;
          nativeBuildInputs = nativeBuildInputs ++ (with pkgs; [
            rust-analyzer
            clippy
            cargo-watch
            cargo-llvm-cov
          ]);
          RUST_LOG = "warn";
          RUST_BACKTRACE = "1";
        };

        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/oxide-sloc";
        };
      }
    );
}
