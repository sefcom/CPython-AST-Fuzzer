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
    # generate coverage report by llvm-cov after running
    --cov)
        echo "cov mode"
        COV_MODE=1
        ;;
    -r | --runs)
        shift
        LIBFUZZER_ARGS="-runs=$1"
        ;;
    # reuse most recently saved corpus for the dummy-ast (mutation base)
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

OLD_LOGS=$(find $WORK_DIR -type d -name "log*")

LOG_PATH=$WORK_DIR/log$(date +"%m%d%H%M%S")
mkdir -p $LOG_PATH

if [ $USE_LAST -eq 1 ]; then
    LAST_CASE_FOLDER=$(echo $OLD_LOGS | sort | tail -n 1)
    LAST_CASE_FILE=$(find $LAST_CASE_FOLDER -type f -name "corpus-*.py" | sort | tail -n 1)
    echo "last case found: $LAST_CASE_FILE"
    if [ -z $LAST_CASE_FILE ]; then
        echo "No last case found"
    else
        cp $LAST_CASE_FILE $LOG_PATH/base_ast.py
        # copy old profraw(s)
        find $LAST_CASE_FOLDER -type f -name "log*.profraw" -exec cp {} $LOG_PATH \;
        if [ -f $LAST_CASE_FOLDER/default.profraw ]; then
            # tmp for remove / as suffix and ${tmp##*/} get last group of / as delimiter
            tmp=${LAST_CASE_FOLDER#/}
            # rename current profraw to log + date (the log folder name)
            cp $LAST_CASE_FOLDER/default.profraw $LOG_PATH/${tmp##*/}.profraw
        fi
        # it will be handled by custom LLVMFuzzerInitialize
        LIBFUZZER_ARGS="$LIBFUZZER_ARGS -last-case=$LOG_PATH/base_ast.py"
    fi
fi

if [ $CLEAN_UP_LOGS -eq 1 ]; then
    rm -rf $OLD_LOGS
fi

pushd $LOG_PATH

if [ $DEBUG_MODE -eq 1 ]; then
    ASAN_OPTIONS='detect_leaks=0' $BUILD_PATH/$BIN $LIBFUZZER_ARGS
else
    # redirect stdout and stderr
    ASAN_OPTIONS='detect_leaks=0' $BUILD_PATH/$BIN $LIBFUZZER_ARGS &>$LOG_PATH/log.txt
fi
if [ $COV_MODE -eq 1 ]; then
    echo "analysis cov"
    cd $LOG_PATH
    # merge all profraw files
    llvm-profdata merge -sparse $(find $LOG_PATH -type f -name "*.profraw") -o default.profdata
    llvm-cov show $CPYTHON_LIB -instr-profile=default.profdata -o reports
    cat reports/index.txt
fi
popd
