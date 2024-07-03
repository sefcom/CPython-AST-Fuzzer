import os, sys

TEMPLATE="""
{
    "configurations": [
        {
            "name": "Linux",
            "includePath": [
                "${workspaceFolder}/**",
                "CPYTHON_INCLUDE",
                "CPYTHON_INCLUDE/internal",
            ],
            "defines": [],
            "compilerPath": "CLANG_BIN",
            "cStandard": "c17",
            "cppStandard": "c++17",
            "intelliSenseMode": "linux-clang-x64"
        }
    ],
    "version": 4
}
""".strip()

# from https://github.com/Antares0982/nix-pyenv
SETTINGS_TEMPLATE="""
{
    "python.analysis.stubPath": ".nix-pyenv",
    "terminal.integrated.profiles.linux": {
        "nix-shell": {
            "path": "/run/current-system/sw/bin/nix-shell",
            "icon": "terminal-bash"
        }
    },
    "terminal.integrated.defaultProfile.linux": "nix-shell",
}
""".strip()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} VSCODE_CCONFIG_FOLDER")
        sys.exit(1)
    clang_bin = os.environ.get("CLANG_BIN", "")
    cpython_include = os.environ.get("CPYTHON_INCLUDE", "")
    assert clang_bin != "", "CLANG_BIN not set"
    assert cpython_include != "", "CPYTHON_INCLUDE not set"
    vscode_cconfig_folder = sys.argv[1].removesuffix("/")
    os.makedirs(vscode_cconfig_folder, exist_ok=True)
    with open(vscode_cconfig_folder + "/c_cpp_properties.json", "w", encoding="utf8") as f:
        f.write(TEMPLATE.replace("CLANG_BIN", clang_bin).replace("CPYTHON_INCLUDE", cpython_include))
    with open(vscode_cconfig_folder + "/settings.json", "w", encoding="utf8") as f:
        f.write(SETTINGS_TEMPLATE)
