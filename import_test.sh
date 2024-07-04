#!/bin/bash
set -e

SCRIPT_DIR=$(readlink -f ./scripts)
BUILD_PATH=$(readlink -f ./build)
CPYTHON_VERSION=3.11.9

pushd $BUILD_PATH
nix-shell --pure --command "LD_PRELOAD=\"\$(python -c \"import atheris; print(atheris.path())\")/asan_with_fuzzer.so\" python -c \"import pyFuzzerHelper\"" $SCRIPT_DIR/cpython.nix --argstr py_ver_str $CPYTHON_VERSION
popd