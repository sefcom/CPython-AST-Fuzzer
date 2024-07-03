#!/bin/bash
set -e

WORK_DIR=$(readlink -f .)
cd $WORK_DIR

CPYTHON_VERSION=3.11.9
ATHERIS_VERSION=master
ATHERIS_PATH=$(readlink -f ./atheris)
BUILD_PATH=$(readlink -f ./build)
SRC_PATH=$(readlink -f ./src)
USING_CORE=7

SKIP_ATHERIS=0

# COLORs
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# parse args skip-afl and skip-cpython
while [ "$1" != "" ]; do
    case $1 in
        -a | --skip-atheris )   SKIP_ATHERIS=1
                                ;;
        -j | --jobs )           shift
                                USING_CORE=$1
                                ;;
        --clean )               rm -rf $CPYTHON_PATH $CPYTHON_BIN
                                exit
                                ;;
        * )                     echo "Invalid argument $1"
                                exit
                                ;;
    esac
    shift
done

if [ -d $ATHERIS_PATH ]; then
    echo -e "[WARN] using cached atheris"
else
    echo -e "[INFO] cloning atheris into $ATHERIS_PATH"
    git clone --quiet --depth=1 --branch=$ATHERIS_VERSION https://github.com/google/atheris.git $ATHERIS_PATH
fi

if [ $SKIP_ATHERIS -eq 1 ]; then
    echo -e "[INFO] skip building atheris"
else
    cd $ATHERIS_PATH

    # PATCHING
    echo -e "${GREEN}[INFO] patching Atheris$NC"
    cd $ATHERIS_PATH
    git reset --hard HEAD
    git apply $WORK_DIR/atheris-nix-bash.patch

    echo -e "${GREEN}[INFO] building Atheris$NC"
    nix-shell --pure --command "echo -e '${GREEN}[INFO] finished building Atheris$NC'" $WORK_DIR/cpython.nix --argstr py_ver_str $CPYTHON_VERSION
    cd $WORK_DIR
fi

echo -e "${GREEN}[INFO] building pyFuzzer$NC"
mkdir -p $BUILD_PATH
cd $BUILD_PATH
nix-shell --pure --command "cmake $SRC_PATH" $WORK_DIR/cpython.nix --argstr py_ver_str $CPYTHON_VERSION
nix-shell --pure --command "make -j$USING_CORE" $WORK_DIR/cpython.nix --argstr py_ver_str $CPYTHON_VERSION
