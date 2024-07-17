#!/bin/bash

WORK_DIR=$(readlink -f .)
cd $WORK_DIR

CPYTHON_VERSION=3.13
CPYTHON_BIN_PATH=$(readlink -f ./cpython_bin)

# for every ./log* folders
for log in $(find $WORK_DIR -maxdepth 1 -type d -name "log*"); do
    echo "Checking $log"
    for file in $(find $log -maxdepth 1 -type f -name "crash-*"); do
        echo "Checking $file"
        ASAN_OPTIONS='detect_leaks=0' LD_LIBRARY_PATH="$CPYTHON_BIN_PATH/lib" $CPYTHON_BIN_PATH/bin/python$CPYTHON_VERSION $file
    done
done
