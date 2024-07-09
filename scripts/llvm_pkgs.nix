pkgs:
{
  pkg_list = [
    pkgs.clang_18
    pkgs.llvm_18
    pkgs.lld_18
    pkgs.llvmPackages_18.compiler-rt-libc
    pkgs.ccache
  ];
  compiler_rt_libc = pkgs.llvmPackages_18.compiler-rt-libc;
  clang = pkgs.clang_18;
}
