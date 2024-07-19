#!/bin/bash
set -e

if [[ "$EUID" = 0 ]]; then
    echo "don't run as root"
    exit
fi

###
# run pyFuzzer by running the src/main.py
###

pushd() {
    command pushd "$@" >/dev/null
}

popd() {
    command popd "$@" >/dev/null
}

WORK_DIR=$(readlink -f .)
BUILD_PATH=$(readlink -f ./build)
CPYTHON_LIB=$(readlink -f ./cpython_bin/lib/libpython3.*.so.*.*)
DEBUG_MODE=0
COV_MODE=0
USE_LAST=0
CLEAN_UP_LOGS=0
LIBFUZZER_ARGS="-runs=2000"
BIN=pyFuzzerHelper

while [ "$1" != "" ]; do
    case $1 in
    -c | --clean)
        echo "cleaning up logs"
        CLEAN_UP_LOGS=1
        ;;
    -d | --debug)
        DEBUG_MODE=1
        ;;
    --cov)
        echo "cov mode"
        COV_MODE=1
        ;;
    -r | --runs)
        shift
        LIBFUZZER_ARGS="-runs=$1"
        ;;
    -l | --use-last)
        USE_LAST=1
        ;;
    *)
        echo "Invalid argument $1"
        exit
        ;;
    esac
    shift
done

# gave 8Gb memory, 20s timeout, 100000 runs will take ~4Gb
LIBFUZZER_ARGS="$LIBFUZZER_ARGS -rss_limit_mb=8192 -timeout=20"

if [ $USE_LAST -eq 1 ]; then
    LAST_CASE_FOLDER=$(find $WORK_DIR -type d -name "log*" | sort | tail -n 1)
    LAST_CASE_FILE=$(find $LAST_CASE_FOLDER -type f -name "corpus-*.py" | sort | tail -n 1)
    echo "last case found: $LAST_CASE_FILE"
    if [ -z $LAST_CASE_FILE ]; then
        echo "No last case found"
    else
        LAST_CASE=$(readlink -f $LAST_CASE_FILE)
        cp $LAST_CASE $WORK_DIR/last_case_corpus.py
        LIBFUZZER_ARGS="$LIBFUZZER_ARGS -last-case=$WORK_DIR/last_case_corpus.py"
    fi
fi

if [ $CLEAN_UP_LOGS -eq 1 ]; then
    rm -rf $(readlink -f .)/log*
fi

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
    llvm-cov show $CPYTHON_LIB -instr-profile=default.profdata -o reports
    cat reports/index.txt
fi
popd
