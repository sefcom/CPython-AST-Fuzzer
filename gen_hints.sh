#!/bin/bash
set -e

###
# setup environment and type hints for vscode
###

WORK_DIR=$(readlink -f .)
SCRIPT_DIR=$(readlink -f ./scripts)
CPYTHON_BIN_PATH=$(readlink -f ./cpython_bin/include/python3.*)

echo '''
{
    "configurations": [
        {
            "name": "Linux",
            "includePath": [
                "${workspaceFolder}/**",
                "'$CPYTHON_BIN_PATH'/",
                "'$CPYTHON_BIN_PATH'/internal"
            ],
            "defines": [],
            "compilerPath": "'$(nix-shell --pure --command "echo \$CLANG_BIN" $SCRIPT_DIR/cpython.nix)'",
            "cStandard": "c17",
            "cppStandard": "c++17",
            "intelliSenseMode": "linux-clang-x64"
        }
    ],
    "version": 4
}
''' > $WORK_DIR/.vscode/c_cpp_properties.json

echo '''
{
    "cmake.sourceDirectory": "${workspaceFolder}/src",
    "cmake.buildDirectory": "${workspaceFolder}/build",
    "C_Cpp.default.compilerPath": "'$(nix-shell --pure --command "echo \$CLANG_BIN" $SCRIPT_DIR/cpython.nix)'"
}
''' > $WORK_DIR/.vscode/settings.json
