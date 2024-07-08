{ py_ver_str ? "3.11.9" }:
let
  pkgs = import <nixpkgs> { };
  python_custom_plain = import ./plain_python.nix py_ver_str;
  python_pkgs = import ./python_pkgs.nix pkgs;
  llvm_pkgs = (import ./llvm_pkgs.nix pkgs).pkg_list;
  python_custom = python_custom_plain.withPackages (ps: with ps; (python_pkgs ps));

in
pkgs.mkShell {
  packages = llvm_pkgs ++ [
    pkgs.cmake
    python_custom_plain # try to fix
    # python_custom # don't insert to path
  ];
  shellHook = ''
    export ASAN_OPTIONS='detect_leaks=0';
    export CC="${pkgs.clang_18}/bin/clang";
    export CXX="${pkgs.clang_18}/bin/clang++";
    export LDSHARED="${pkgs.clang_18}/bin/clang -shared";
    export PYTHON_PATH="${python_custom_plain}";
    export PYTHON_PKGS_PATH=${python_custom}/lib/python3.11/site-packages;
  '';
}
