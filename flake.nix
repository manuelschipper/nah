{
  description = "Action-aware permissions for coding agents.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs { inherit system; };
      mkNahApp = package: {
        type = "app";
        program = "${package}/bin/nah";
        meta.description = "Run the nah CLI";
      };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          nah = pkgs.callPackage ./default.nix { };
          nahCore = pkgs.callPackage ./default.nix {
            withConfig = false;
            withKeys = false;
            pname = "nah-core";
          };
        in
        {
          default = nah;
          inherit nah;
          "nah-core" = nahCore;
        }
      );

      apps = forAllSystems (
        system:
        let
          packages = self.packages.${system};
        in
        {
          default = mkNahApp packages.nah;
          nah = mkNahApp packages.nah;
          "nah-core" = mkNahApp packages."nah-core";
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          packages = self.packages.${system};
          smoke = pkgs.runCommand "nah-nix-smoke" { nativeBuildInputs = [ packages.nah ]; } ''
            set -eu

            nah --version
            nah types >/dev/null
            nah test "python3 -c 'print(1)'" >/dev/null

            export HOME="$TMPDIR/home"
            mkdir -p "$HOME"
            nah allow git_safe >/dev/null
            test -f "$HOME/.config/nah/config.yaml"
            grep -F "git_safe: allow" "$HOME/.config/nah/config.yaml" >/dev/null

            if nah key status | grep -F "pip install 'nah[keys]'"; then
              echo "default Nix package is missing Python keyring integration" >&2
              exit 1
            fi

            touch "$out"
          '';
        in
        {
          default = smoke;
          inherit (packages) nah;
          "nah-core" = packages."nah-core";
          nah-smoke = smoke;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          python = pkgs.python3.withPackages (
            ps: with ps; [
              build
              hatchling
              keyring
              mkdocs-material
              pyyaml
              pytest
            ]
          );
        in
        {
          default = pkgs.mkShell {
            packages = [
              python
              pkgs.nixfmt
            ];
          };
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt);
    };
}
