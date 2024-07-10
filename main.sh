#!/bin/bash
set -e

###
# run pyFuzzer by running the src/main.py
###

pushd() {
    command pushd "$@" >/dev/null
}

popd() {
    command popd "$@" >/dev/null
}

BUILD_PATH=$(readlink -f ./build)
LOG_PATH=$(readlink -f .)/log$(date +"%H%M%S")

mkdir -p $LOG_PATH

pushd $LOG_PATH
$BUILD_PATH/pyFuzzerHelper &> $LOG_PATH/log.txt
popd
