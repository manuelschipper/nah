{
  description = "nah";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      mkOutputs = system:
        let
          pkgs = import nixpkgs { inherit system; };
          nah = pkgs.callPackage ./default.nix {};
        in
        {
          packages = {
            default = nah;
            nah = nah;
          };
          apps = {
            default = {
              type = "app";
              program = "${nah}/bin/nah";
            };
          };
          checks = {
            default = nah;
          };
          devShells.default = pkgs.mkShell {
            packages = [ nah ];
          };
        };
    in
    {
      packages = builtins.listToAttrs (map (system: {
        name = system;
        value = (mkOutputs system).packages;
      }) systems);
      apps = builtins.listToAttrs (map (system: {
        name = system;
        value = (mkOutputs system).apps;
      }) systems);
      checks = builtins.listToAttrs (map (system: {
        name = system;
        value = (mkOutputs system).checks;
      }) systems);
      devShells = builtins.listToAttrs (map (system: {
        name = system;
        value = (mkOutputs system).devShells;
      }) systems);
    };
}
