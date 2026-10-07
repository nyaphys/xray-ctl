{
  description = "xray-ctl package and NixOS module";

  inputs.nixpkgs.url = "tarball+https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";

  outputs = { nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in rec {
          xray-ctl = pkgs.callPackage ./nix/package.nix { };
          blancctl = xray-ctl;
          default = xray-ctl;
        });

      nixosModules = {
        xray-ctl = import ./nix/module.nix;
        blancctl = import ./nix/module.nix;
        default = import ./nix/module.nix;
      };

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt-tree);
    };
}
