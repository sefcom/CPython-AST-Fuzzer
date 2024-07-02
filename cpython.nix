{ py_ver_str ? "3.11.9" }:
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
  python_base = if builtins.elemAt py_ver 1 == "12" then pkgs.python312 else pkgs.python311;
  python_custom_plain = python_base.override {
    stdenv = pkgs.clangStdenv;
    sourceVersion = {
      major = builtins.elemAt py_ver 0;
      minor = builtins.elemAt py_ver 1;
      patch = builtins.elemAt py_ver 2;
      suffix = "";
    };
    hash = hashs."${py_ver_str}";
  };
  atheris = ps: deps: ps.buildPythonPackage {
    # need to patch
    # src = pkgs.fetchFromGitHub {owner="google";repo="atheris";rev="2.3.0";hash="sha256-d5T+0YnHMS9nw8lyIS2TOQhwVJDc5dLp9tlpdoViPSs=";};
    src = ./atheris;
    pname = "atheris";
    version = "2.3.0";
    build-system = deps;
    format = "pyproject";
    preBuild = ''
      export CLANG_BIN=${pkgs.clang_17}/bin/clang;
      export LIBFUZZER_LIB=${pkgs.llvmPackages.compiler-rt-libc}/lib/linux/libclang_rt.fuzzer_no_main-x86_64.a;
    '';
    build-inputs = [ pkgs.clang_17 pkgs.llvm_17 pkgs.lld_17 pkgs.llvmPackages.compiler-rt-libc ];
  };
  pyInstaller = ps: deps: ps.buildPythonPackage {
    src = pkgs.fetchFromGitHub { owner = "pyinstaller"; repo = "pyinstaller"; rev = "v6.8.0"; hash = "sha256-OXbP2SbsQ/FzA4gIuj9Wyar0YEKYOPkG9QMoTFUzM9I="; };
    build-system = deps;
    pname = "pyInstaller";
    version = "6.8.0";
    format = "pyproject";
  };
  pyinstaller-hooks-contrib = ps: deps: ps.buildPythonPackage {
    src = pkgs.fetchFromGitHub { owner = "pyinstaller"; repo = "pyinstaller-hooks-contrib"; rev = "2024.7"; hash = "sha256-HnhqcJAGd0GWjt3ylaa3G9JOdRGz1PW9pvHjlQGc0LY="; };
    build-system = deps;
    pname = "pyinstaller-hooks-contrib";
    version = "2024.7";
  };
  python_custom = python_custom_plain.withPackages (ps: with ps; [
    (atheris ps [
      pybind11
      altgraph
      setuptools
      (pyInstaller ps [
        setuptools
        pip
        packaging
        altgraph
        importlib-metadata
        (pyinstaller-hooks-contrib ps [
          pip
          packaging
          setuptools
          importlib-metadata
        ])
      ])
    ])
  ]);
in
pkgs.mkShell {
  packages = [
    pkgs.clang_17
    pkgs.llvm_17
    pkgs.lld_17
    python_custom
  ];
  shellHook = ''
    # export ASAN_OPTIONS='detect_leaks=0';
    # export CC="${pkgs.ccache}/bin/ccache ${pkgs.clang_18}/bin/clang";
    # export CXX="${pkgs.ccache}/bin/ccache ${pkgs.clang_18}/bin/clang++";
  '';
}
