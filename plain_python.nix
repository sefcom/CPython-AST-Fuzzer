py_ver_str:
let
  py_ver = builtins.match "^([3])\\.([0-9]+)\\.([0-9]+)" py_ver_str;
in
assert ((builtins.elemAt py_ver 1) <= "11");

let
  pkgs = import <nixpkgs> { };
  hashs = {
    # "3.12.2" = "sha256-vigRLayBPSBTVFwUvxOhZAGiGHfxpp626l2ExKDz2HA=";
    # "3.12.4" = "sha256-9tQZpth0OrJnAIAbSQjSbZfouYbhT5XeMbMt4rDnlVQ=";
    "3.11.9" = "sha256-mx6JZSP8UQaREmyGRAbZNgo9Hphqy9pZzaV7Wr2kW4c=";
  };
  py_ver = builtins.match "^([3])\\.([0-9]+)\\.([0-9]+)" py_ver_str;
  # python_base = if builtins.elemAt py_ver 1 == "12" then pkgs.python312 else pkgs.python311;
  python_base = pkgs.python311;
in
python_base.override {
  stdenv = pkgs.clangStdenv;
  sourceVersion = {
    major = builtins.elemAt py_ver 0;
    minor = builtins.elemAt py_ver 1;
    patch = builtins.elemAt py_ver 2;
    suffix = "";
  };
  hash = hashs."${py_ver_str}";
}
