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

while [ "$1" != "" ]; do
    case $1 in
        -c | --clean )  echo "cleaning up logs"
                        rm -rf $(readlink -f .)/log*
                        ;;
    esac
    shift
done

LOG_PATH=$(readlink -f .)/log$(date +"%m%d%H%M%S")

mkdir -p $LOG_PATH

pushd $LOG_PATH
$BUILD_PATH/pyFuzzerHelper &> $LOG_PATH/log.txt
popd
