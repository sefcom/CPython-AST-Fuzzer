#!/bin/bash
set -e

pushd() {
    command pushd "$@" >/dev/null
}

popd() {
    command popd "$@" >/dev/null
}

SCRIPT_DIR=$(readlink -f ./scripts)
BUILD_PATH=$(readlink -f ./build)
SRC_PATH=$(readlink -f ./src)
CPYTHON_VERSION=3.11.9

pushd $BUILD_PATH
nix-shell --pure --command "LD_PRELOAD=\"\$(python $SCRIPT_DIR/get_asan.py)/asan_with_fuzzer.so\" python $SRC_PATH/main.py" $SCRIPT_DIR/cpython.nix --argstr py_ver_str $CPYTHON_VERSION
popd
