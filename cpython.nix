{ py_ver_str ? "3.11.9" }:
let
  pkgs = import <nixpkgs> { };
  python_custom_plain = import ./plain_python.nix py_ver_str;
  python_pkgs = import ./python_pkgs.nix pkgs;
  python_custom = python_custom_plain.withPackages (ps: with ps; (python_pkgs ps));
in
pkgs.mkShell {
  packages = [
    pkgs.clang_18
    pkgs.llvm_18
    pkgs.lld_18
    pkgs.cmake
    python_custom
  ];
  shellHook = ''
    export ASAN_OPTIONS='detect_leaks=0';
    export CC="${pkgs.ccache}/bin/ccache ${pkgs.clang_18}/bin/clang";
    export CXX="${pkgs.ccache}/bin/ccache ${pkgs.clang_18}/bin/clang++";
    export LDSHARED="${pkgs.clang_18}/bin/clang -shared";
  '';
}
