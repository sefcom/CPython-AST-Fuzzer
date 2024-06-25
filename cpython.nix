let
  pkgs = import <nixpkgs> { };
in
pkgs.mkShell {
  packages = [
    pkgs.clang_18
    pkgs.llvm_18
    pkgs.ccache
  ];
  shellHook = ''
    export PATH=${pkgs.ccache}/bin:${pkgs.llvm_18}/bin:$PATH;
    export AR=llvm-ar;
    export RANLIB=llvm-ranlib;
    export AS=llvm-as;
    export ASAN_OPTIONS='detect_leaks=0';
    export AFL_USE_ASAN=1;
    export ax_cv_c_float_words_bigendian=no; # https://github.com/python/cpython/issues/89640
  '';
}
