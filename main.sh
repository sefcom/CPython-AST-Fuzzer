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
DEBUG_MODE=0
LIBFUZZER_ARGS="-runs=5000"

while [ "$1" != "" ]; do
    case $1 in
        -c | --clean )  echo "cleaning up logs"
                        rm -rf $(readlink -f .)/log*
                        ;;
        -d | --debug ) DEBUG_MODE=1
        ;;
    esac
    shift
done

LOG_PATH=$(readlink -f .)/log$(date +"%m%d%H%M%S")

mkdir -p $LOG_PATH

pushd $LOG_PATH
if [ $DEBUG_MODE -eq 1 ]; then
    ASAN_OPTIONS='detect_leaks=0' $BUILD_PATH/pyFuzzerHelper $LIBFUZZER_ARGS
else
    ASAN_OPTIONS='detect_leaks=0' $BUILD_PATH/pyFuzzerHelper $LIBFUZZER_ARGS &> $LOG_PATH/log.txt
fi
popd
