#!/bin/bash
set -e

PYTHON_PKGS_PATH=$(nix-shell --pure --command "echo \$PYTHON_PKGS_PATH" ./scripts/cpython.nix)
PYTHON_PATH=$(nix-shell --pure --command "echo \$PYTHON_PATH" ./scripts/cpython.nix)
echo PYTHON_PKGS_PATH=$PYTHON_PKGS_PATH
echo PYTHON_PATH=$PYTHON_PATH

ACTION=--add-needed

if [[ ! -z "$1" && $1 == "remove" ]]; then
    ACTION=--remove-needed
    echo "Remove mode"
fi

# build ouputs
patchelf $ACTION $PYTHON_PKGS_PATH/asan_with_fuzzer.so ./build/pyFuzzerHelper.so
patchelf $ACTION $PYTHON_PKGS_PATH/asan_with_fuzzer.so ./build/pyFuzzerTarget.so

# bc PYTHON_PKGS_PATH and PYTHON_PATH under /nix/store is read-only, otherwise sudo is not needed
# ensure ASAN symbols in custom_mutator
sudo patchelf $ACTION $PYTHON_PKGS_PATH/asan_with_fuzzer.so $PYTHON_PKGS_PATH/atheris/custom_mutator.cpython-*.so
# ensure LLVM symbols exported
sudo patchelf $ACTION $PYTHON_PKGS_PATH/atheris/custom_mutator.cpython-*.so $PYTHON_PATH/bin/python