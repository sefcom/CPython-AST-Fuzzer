pkgs: py_ver_str:
let
  py_ver = builtins.match "^([3])\\.([0-9]+)\\.([0-9]+)" py_ver_str;
  llvm_pkgs = (import ./llvm_pkgs.nix pkgs).pkg_list;
in
assert ((builtins.elemAt py_ver 1) <= "11");

let
  py_ver = builtins.match "^([3])\\.([0-9]+)\\.([0-9]+)" py_ver_str;
  # python_base = if builtins.elemAt py_ver 1 == "12" then pkgs.python312 else pkgs.python311;
  python_base = pkgs.python311;
in
(python_base.overrideAttrs (oldAttrs:
{
  build-system = llvm_pkgs;
  stdenv = pkgs.ccacheStdenv;
  src = ../cpython;
}))
