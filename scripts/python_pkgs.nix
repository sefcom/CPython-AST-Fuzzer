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
    build-inputs = llvm_pkgs;
  };
  pyInstaller = deps: ps.buildPythonPackage {
    src = pkgs.fetchFromGitHub { owner = "pyinstaller"; repo = "pyinstaller"; rev = "v6.8.0"; hash = "sha256-OXbP2SbsQ/FzA4gIuj9Wyar0YEKYOPkG9QMoTFUzM9I="; };
    build-system = deps;
    pname = "pyInstaller";
    version = "6.8.0";
    format = "pyproject";
  };
  pyinstaller-hooks-contrib = deps: ps.buildPythonPackage {
    src = pkgs.fetchFromGitHub { owner = "pyinstaller"; repo = "pyinstaller-hooks-contrib"; rev = "2024.7"; hash = "sha256-HnhqcJAGd0GWjt3ylaa3G9JOdRGz1PW9pvHjlQGc0LY="; };
    build-system = deps;
    pname = "pyinstaller-hooks-contrib";
    version = "2024.7";
  };
in
[
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