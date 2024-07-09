{ py_ver_str ? "3.11.9" }:
let
  pkgs = import <nixpkgs> { 
    overlays = [
      (self: super: {
        ccacheWrapper = super.ccacheWrapper.override {
          extraConfig = ''
            export CCACHE_COMPRESS=1
            export CCACHE_DIR="/nix/var/cache/ccache"
            export CCACHE_UMASK=007
            if [ ! -d "$CCACHE_DIR" ]; then
              echo "====="
              echo "Directory '$CCACHE_DIR' does not exist"
              echo "Please create it with:"
              echo "  sudo mkdir -m0770 '$CCACHE_DIR'"
              echo "  sudo chown root:nixbld '$CCACHE_DIR'"
              echo "====="
              exit 1
            fi
            if [ ! -w "$CCACHE_DIR" ]; then
              echo "====="
              echo "Directory '$CCACHE_DIR' is not accessible for user $(whoami)"
              echo "Please verify its access permissions"
              echo "====="
              exit 1
            fi
          '';
        };
      })
    ];
  };
  python_custom_plain = import ./plain_python.nix pkgs py_ver_str;
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
