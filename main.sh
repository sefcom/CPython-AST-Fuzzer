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
COV_MODE=0
LIBFUZZER_ARGS="-runs=2000"
BIN=pyFuzzerHelper

while [ "$1" != "" ]; do
    case $1 in
    -c | --clean)
        echo "cleaning up logs"
        rm -rf $(readlink -f .)/log*
        ;;
    -d | --debug)
        DEBUG_MODE=1
        ;;
    --cov)
        echo "cov mode"
        COV_MODE=1
        BIN=pyFuzzerHelper_cov
        ;;
    -r | --runs)
        shift
        LIBFUZZER_ARGS="-runs=$1"
        ;;
    esac
    shift
done

# gave 8Gb memory, 20s timeout
LIBFUZZER_ARGS="$LIBFUZZER_ARGS -rss_limit_mb=8192 -timeout=20"

LOG_PATH=$(readlink -f .)/log$(date +"%m%d%H%M%S")

mkdir -p $LOG_PATH

pushd $LOG_PATH
# sadly corpus doesn't work bc we are passing pointer as data
# and obviously an AST cannot pass between different cpython instance
# unless using compile_string and ast.unparse
if [ $DEBUG_MODE -eq 1 ]; then
    ASAN_OPTIONS='detect_leaks=0' $BUILD_PATH/$BIN $LIBFUZZER_ARGS
else
    ASAN_OPTIONS='detect_leaks=0' $BUILD_PATH/$BIN $LIBFUZZER_ARGS &>$LOG_PATH/log.txt
fi
if [ $COV_MODE -eq 1 ]; then
    echo "analysis cov"
    cd $LOG_PATH
    llvm-profdata merge -sparse default.profraw -o default.profdata
    # ignore src/ folder
    llvm-cov show $BUILD_PATH/$BIN -instr-profile=default.profdata -o reports --ignore-filename-regex='src/*'
    cat reports/index.txt
fi
popd
