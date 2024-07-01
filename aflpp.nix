let
  pkgs = import <nixpkgs> { };
in
pkgs.mkShell {
  packages = [
    pkgs.llvm_18
    pkgs.lld_18
    pkgs.clang_18
    pkgs.ccache
    pkgs.gmp
    pkgs.capstone_4
    pkgs.python3
  ];
  shellHook = ''
    export LLVM_CONFIG=llvm-config;
    export PATH=${pkgs.lld_18}/bin:${pkgs.ccache}/bin:${pkgs.llvm_18}/bin:${pkgs.clang_18}/bin:$PATH;
    export LIBRARY_PATH=${pkgs.gmp}/lib:${pkgs.capstone_4}/lib:$LIBRARY_PATH;
  '';
}
