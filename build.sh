#!/bin/bash
set -e

###
# build the pyFuzzer
###

WORK_DIR=$(readlink -f .)
SCRIPT_DIR=$(readlink -f ./scripts)
cd $WORK_DIR

CPYTHON_VERSION=3.13.0b3
ATHERIS_VERSION=2.3.0
ATHERIS_PATH=$(readlink -f ./atheris)
CPYTHON_PATH=$(readlink -f ./cpython)
CPYTHON_BUILD_PATH=$(readlink -f ./cpython_build)
CPYTHON_BIN_PATH=$(readlink -f ./cpython_bin)
BUILD_PATH=$(readlink -f build)
SRC_PATH=$(readlink -f ./src)
USING_CORE=7

FORCE_MODE=0

# COLORs
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# parse args skip-afl and skip-cpython
while [ "$1" != "" ]; do
    case $1 in
        -f | --force )   FORCE_MODE=1
                                ;;
        -j | --jobs )           shift
                                USING_CORE=$1
                                ;;
        --clean )               rm -rf $ATHERIS_PATH $BUILD_PATH $CPYTHON_PATH $CPYTHON_BUILD_PATH $CPYTHON_BIN_PATH
                                exit
                                ;;
        * )                     echo "Invalid argument $1"
                                exit
                                ;;
    esac
    shift
done

# if [ -d $ATHERIS_PATH ]; then
#     echo -e "[WARN] using cached atheris"
# else
#     echo -e "[INFO] cloning atheris into $ATHERIS_PATH"
#     git clone --quiet --depth=1 --branch=$ATHERIS_VERSION https://github.com/google/atheris.git $ATHERIS_PATH
#     FORCE_MODE=1
#     cd $WORK_DIR
# fi

if [ -d $CPYTHON_PATH ]; then
    echo -e "[WARN] using cached cpython"
else
    echo -e "[INFO] cloning cpython into $CPYTHON_PATH"
    git clone --quiet --depth=1 --branch=v$CPYTHON_VERSION https://github.com/python/cpython.git $CPYTHON_PATH
    FORCE_MODE=1
    cd $WORK_DIR
fi

if [ $FORCE_MODE -eq 0 ]; then
    echo -e "${GREEN}[INFO] skipping force building Atheris and CPython$NC"
else
    echo -e "${GREEN}[INFO] building Atheris and CPython$NC"
    # cd $ATHERIS_PATH
    # echo -e "${GREEN}[INFO] patching Atheris$NC"
    # cd $ATHERIS_PATH
    # git reset --hard HEAD
    # git apply $WORK_DIR/atheris-nix-bash.patch

    echo -e "${GREEN}[INFO] patching CPython$NC"
    cd $CPYTHON_PATH
    git reset --hard HEAD
    nix-shell --pure --command "patch -p1 < \$PYTHON_NOLDPATCH" $SCRIPT_DIR/cpython.nix
    python $SCRIPT_DIR/patch_python.py

    cd $WORK_DIR
    if [ -d $CPYTHON_BUILD_PATH ]; then
        rm -rf $CPYTHON_BUILD_PATH
    fi

    if [ -d $CPYTHON_BIN_PATH ]; then
        rm -rf $CPYTHON_BIN_PATH
    fi

    echo -e "${GREEN}[INFO] building CPython$NC"
    mkdir -p $CPYTHON_BUILD_PATH
    mkdir -p $CPYTHON_BIN_PATH
    cd $CPYTHON_BUILD_PATH
    # cannot use --enable-optimizations
    nix-shell --pure --command "$CPYTHON_PATH/configure ac_cv_func_lchmod=no --enable-shared --prefix=\"$CPYTHON_BIN_PATH\" --with-openssl=\"\$OPENSSL_DEV\" --with-system-expat --with-ensurepip" $SCRIPT_DIR/cpython.nix
    nix-shell --pure --command "make altinstall -j$USING_CORE" $SCRIPT_DIR/cpython.nix
fi

echo -e "${GREEN}[INFO] building pyFuzzer$NC"

# -- codegen --
python $SCRIPT_DIR/codgen/deepcopy_ast.py $(readlink -f $CPYTHON_BIN_PATH/include/python3.*/internal/pycore_ast.h) $SRC_PATH/codgen/deepcopy_gen
python $SCRIPT_DIR/codgen/override_func.py $SRC_PATH/codgen/override_func_gen
if [ -d $BUILD_PATH ]; then
    rm -rf $BUILD_PATH
fi
mkdir -p $BUILD_PATH
cd $BUILD_PATH
nix-shell --pure --command "PYTHON_PATH=$CPYTHON_BIN_PATH cmake $SRC_PATH -DCMAKE_BUILD_TYPE=Debug" $SCRIPT_DIR/cpython.nix
nix-shell --pure --command "make -j$USING_CORE" $SCRIPT_DIR/cpython.nix

cd $WORK_DIR
# echo -e "${GREEN}[INFO] patching output ELF files for Atheris$NC"
# # check https://github.com/google/atheris/issues/54
# $SCRIPT_DIR/patched_all_elf.sh


echo -e "${GREEN}[INFO] finished building pyFuzzer$NC"
