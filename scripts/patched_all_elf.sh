#!/bin/bash
set -e

PYTHON_PKGS_PATH=$(nix-shell --pure --command "echo \$PYTHON_PKGS_PATH" ./scripts/cpython.nix)
echo $PYTHON_PKGS_PATH

ACTION=--add-needed

if [[ ! -z "$1" && $1 == "remove" ]]; then
    ACTION=--remove-needed
    echo "Remove mode"
fi

patchelf $ACTION $PYTHON_PKGS_PATH/asan_with_fuzzer.so ./build/pyFuzzerHelper.so
patchelf $ACTION $PYTHON_PKGS_PATH/asan_with_fuzzer.so ./build/pyFuzzerTarget.so

# bc PYTHON_PKGS_PATH under /nix/store is read-only
sudo patchelf $ACTION $PYTHON_PKGS_PATH/asan_with_fuzzer.so $PYTHON_PKGS_PATH/atheris/custom_mutator.cpython-*.so
sudo patchelf $ACTION $PYTHON_PKGS_PATH/atheris/custom_mutator.cpython-*.so $PYTHON_PKGS_PATH/atheris/native.cpython-*.so
