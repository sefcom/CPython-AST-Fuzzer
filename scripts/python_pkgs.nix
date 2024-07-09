pkgs: ps: with ps;
let
  llvm_pkgs = (import ./llvm_pkgs.nix pkgs).pkg_list;
  compiler_rt_libc = (import ./llvm_pkgs.nix pkgs).compiler_rt_libc;
  atheris = deps: ps.buildPythonPackage {
    # need to patch
    # src = pkgs.fetchFromGitHub {owner="google";repo="atheris";rev="2.3.0";hash="sha256-d5T+0YnHMS9nw8lyIS2TOQhwVJDc5dLp9tlpdoViPSs=";};
    src = ../atheris;
    pname = "atheris";
    version = "2.3.0";
    build-system = deps;
    format = "pyproject";
    preBuild = ''
      export LIBFUZZER_LIB=${compiler_rt_libc}/lib/linux/libclang_rt.fuzzer_no_main-x86_64.a;
    '';
    nativeBuildInputs = llvm_pkgs;
    stdenv = pkgs.ccacheStdenv;
  };
  pyInstaller = deps: ps.buildPythonPackage {
    src = pkgs.fetchFromGitHub { owner = "pyinstaller"; repo = "pyinstaller"; rev = "v6.8.0"; hash = "sha256-PZO1RJQV2krKQ5IOD3olEVMn8Q64nL3kfpNkPECyIv8="; };
    build-system = deps;
    nativeBuildInputs = llvm_pkgs;
    pname = "pyInstaller";
    version = "6.8.0";
    format = "pyproject";
    stdenv = pkgs.ccacheStdenv;
  };
  pyinstaller-hooks-contrib = deps: ps.buildPythonPackage {
    src = pkgs.fetchFromGitHub { owner = "pyinstaller"; repo = "pyinstaller-hooks-contrib"; rev = "2024.7"; hash = "sha256-HnhqcJAGd0GWjt3ylaa3G9JOdRGz1PW9pvHjlQGc0LY="; };
    build-system = deps;
    nativeBuildInputs = llvm_pkgs;
    pname = "pyinstaller-hooks-contrib";
    version = "2024.7";
    format = "pyproject";
    stdenv = pkgs.ccacheStdenv;
  };
in
[
  lief # for patching python shared obj symbols
  (atheris [
    pybind11
    altgraph
    setuptools
    (pyInstaller [
      setuptools
      pip
      packaging
      altgraph
      importlib-metadata
      (pyinstaller-hooks-contrib [
        pip
        packaging
        setuptools
        importlib-metadata
      ])
    ])
  ])
]
