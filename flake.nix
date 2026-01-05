{
    description = "Python script to scan /home";

    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    };

    outputs = { self, nixpkgs }:
    let
        system = "x86_64-linux";
        pkgs = import nixpkgs { inherit system; };
    in {
        packages.${system}.default =
            pkgs.python3Packages.buildPythonApplication {
                pname = "scan-home";
                version = "1.0";

                src = ./.;

                format = "other";

                installPhase = ''
                mkdir -p $out/bin
                cp scan_home.py $out/bin/scan-home
                chmod +x $out/bin/scan-home
                '';
            };

        apps.${system}.default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/scan-home";
        };

        devShells.${system}.default = pkgs.mkShell {
            packages = [
                pkgs.python3
            ];
        };
    };
}
