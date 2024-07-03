# Modified from https://github.com/Antares0982/nix-pyenv
{py_ver_str ? "3.11.9"}:
let
  pkgs = import <nixpkgs> { };
  python_custom_plain = import ./plain_python.nix py_ver_str;
  python_pkgs = import ./python_pkgs.nix pkgs;
  nix_pyenv_directory = ".nix-pyenv";
  pyenv = python_custom_plain.withPackages python_pkgs;
in
pkgs.mkShell {
  packages = [
    pyenv
  ];
  shellHook = ''
    if [[ ! -d ${nix_pyenv_directory} ]]; then mkdir ${nix_pyenv_directory}; fi
    ensure_symlink() {
        local link_path="$1"
        local target_path="$2"
        if [[ -L "$link_path" ]] && [[ "$(readlink "$link_path")" = "$target_path" ]]; then
            return 0
        fi
        rm -f "$link_path" > /dev/null 2>&1
        ln -s "$target_path" "$link_path"
    }

    for file in ${pyenv}/${python_custom_plain.sitePackages}/*; do
        ensure_symlink ${nix_pyenv_directory}/$(basename $file) $file
    done
    for file in ${nix_pyenv_directory}/*; do
        if [[ -L "$file" ]] && [[ "$(dirname $(readlink "$file"))" != "${pyenv}/${python_custom_plain.sitePackages}" ]]; then
            rm -f "$file"
        fi
    done
    ensure_symlink ${nix_pyenv_directory}/python ${pyenv}/bin/python
  '';
}