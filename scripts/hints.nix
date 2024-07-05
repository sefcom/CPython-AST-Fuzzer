# Modified from https://github.com/Antares0982/nix-pyenv
{py_ver_str ? "3.11.9"}:
let
  pkgs = import <nixpkgs> { };
  python_custom_plain = import ./plain_python.nix py_ver_str;
  python_pkgs = import ./python_pkgs.nix pkgs;
  nix_pyenv_directory = "../.nix-pyenv";
  llvm_pkgs = (import ./llvm_pkgs.nix pkgs).pkg_list;
  clang = (import ./llvm_pkgs.nix pkgs).clang;
  pyenv = python_custom_plain.withPackages python_pkgs;
in
pkgs.mkShell {
  packages = llvm_pkgs ++ [
    pyenv
  ];
shellHook = ''
    cd ${builtins.toString ./.}

    # ensure the nix-pyenv directory exists
    if [[ ! -d ${nix_pyenv_directory} ]]; then mkdir ${nix_pyenv_directory}; fi
    if [[ ! -d ${nix_pyenv_directory}/lib ]]; then mkdir ${nix_pyenv_directory}/lib; fi
    if [[ ! -d ${nix_pyenv_directory}/bin ]]; then mkdir ${nix_pyenv_directory}/bin; fi

    ensure_symlink() {
        local link_path="$1"
        local target_path="$2"
        if [[ -L "$link_path" ]] && [[ "$(readlink "$link_path")" = "$target_path" ]]; then
            return 0
        fi
        rm -f "$link_path" > /dev/null 2>&1
        ln -s "$target_path" "$link_path"
    }

    # creating python library symlinks
    for file in ${pyenv}/${python_custom_plain.sitePackages}/*; do
        basefile=$(basename $file)
        if [ -d "$file" ]; then
            if [[ "$basefile" != *dist-info && "$basefile" != __pycache__ ]]; then
                ensure_symlink ${nix_pyenv_directory}/lib/$basefile $file
            fi
        else
            # the typing_extensions.py will make the vscode type checker not working!
            if [[ $basefile == *.so ]] || ([[ $basefile == *.py ]] && [[ $basefile != typing_extensions.py ]]); then
                ensure_symlink ${nix_pyenv_directory}/lib/$basefile $file
            fi
        fi
    done
    for file in ${nix_pyenv_directory}/lib/*; do
        if [[ -L "$file" ]] && [[ "$(dirname $(readlink "$file"))" != "${pyenv}/${python_custom_plain.sitePackages}" ]]; then
            rm -f "$file"
        fi
    done

    # ensure the typing_extensions.py is not in the lib directory
    rm ${nix_pyenv_directory}/lib/typing_extensions.py > /dev/null 2>&1

    # add python executable to the bin directory
    ensure_symlink ${nix_pyenv_directory}/bin/python ${pyenv}/bin/python
    export PATH=${nix_pyenv_directory}/bin:$PATH
    export CPYTHON_INCLUDE=${python_custom_plain}/include/python3.11;
    export CLANG_BIN=${clang}/bin/clang
  '';
}