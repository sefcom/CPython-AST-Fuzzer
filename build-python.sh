#!/bin/bash
set -e

WORK_DIR=$(readlink -f .)
cd $WORK_DIR

CPYTHON_VERSION=3.12
CPYTHON_PATH=$(readlink -f ./cpython)
CPYTHON_BIN=$(readlink -f ./cpython-bin)
AFLPP_VER=stable
AFLPP_PATH=$(readlink -f ./AFLplusplus)
ENTRY_PATH=$(readlink -f ./fuzzer-entry)
USING_CORE=7

SKIP_AFL=0
SKIP_CPYTHON=0

# COLORs
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# parse args skip-afl and skip-cpython
while [ "$1" != "" ]; do
    case $1 in
        -a | --skip-afl )       SKIP_AFL=1
                                ;;
        -c | --skip-cpython )   SKIP_CPYTHON=1
                                ;;
        -j | --jobs )           shift
                                USING_CORE=$1
                                ;;
        --clean )               rm -rf $CPYTHON_PATH $AFLPP_PATH $CPYTHON_BIN
                                exit
                                ;;
        * )                     echo "Invalid argument $1"
                                ;;
    esac
    shift
done

if [ -d "cpython" ]; then
    echo "[WARN] using cached cpython"
else
    echo "[INFO] cloning cpython $CPYTHON_VERSION"
    git clone --quiet --depth=1 --branch=$CPYTHON_VERSION https://github.com/python/cpython.git $CPYTHON_PATH
fi

if [ -d "AFLplusplus" ]; then
    echo "[WARN] using cached AFLplusplus"
else
    echo "[INFO] cloning AFLplusplus $AFLPP_VER"
    git clone --quiet --depth=1 --branch=$AFLPP_VER https://github.com/AFLplusplus/AFLplusplus.git $AFLPP_PATH
fi

echo "Instructment python with:"
echo " VER: $GREEN $CPYTHON_VERSION $NC in $CPYTHON_PATH"
echo " AFL++: $GREEN $AFLPP_VER $NC in $AFLPP_PATH"

if [ $SKIP_AFL -eq 1 ]; then
    echo "[INFO] skip building AFLplusplus"
else
    echo "[INFO] cleaning AFLplusplus"
    cd $AFLPP_PATH
    nix-shell --pure --command "make -s clean" $WORK_DIR/aflpp.nix
    echo "$GREEN [INFO] building AFLplusplus $NC"
    # make -s -C $AFLPP_PATH distrib
    nix-shell --pure --command "make -s source-only -j$USING_CORE" $WORK_DIR/aflpp.nix
    cd $WORK_DIR
fi

if [ $SKIP_CPYTHON -eq 1 ]; then
    echo "[INFO] skip building CPython"
else
    rm -rf $CPYTHON_BIN
    cd $CPYTHON_PATH
    if [ -f "Makefile" ]; then
        echo "[INFO] cleaning CPython"
        make clean
    fi
    echo "$GREEN [INFO] building CPython $NC"
    nix-shell --pure --command "./configure CC='$AFLPP_PATH/afl-clang-lto' CXX='$AFLPP_PATH/afl-clang-lto++' --prefix=$CPYTHON_BIN --disable-shared" $WORK_DIR/cpython.nix
    echo "$GREEN [INFO] installing CPython $NC"
    nix-shell --pure --command "make -s altinstall -j$USING_CORE" $WORK_DIR/cpython.nix
    cd $WORK_DIR
fi
