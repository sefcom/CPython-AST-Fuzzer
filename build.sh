#!/bin/bash
set -e

WORK_DIR=$(readlink -f .)
cd $WORK_DIR

CPYTHON_VERSION=v3.12.4
CPYTHON_PATH=$(readlink -f ./cpython)
CPYTHON_BIN=$(readlink -f ./cpython-bin)
AFLPP_VER=dev
AFLPP_PATH=$(readlink -f ./AFLplusplus)
USING_CORE=7
MODE=fast # fast, lto

SKIP_AFL=0
SKIP_CPYTHON=0
SKIP_CPYTHON_CONFIGURE=0

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
        -cc | --skip-cpython-configure )  SKIP_CPYTHON_CONFIGURE=1
                                ;;
        -j | --jobs )           shift
                                USING_CORE=$1
                                ;;
        --clean )               rm -rf $CPYTHON_PATH $AFLPP_PATH
                                exit
                                ;;
        * )                     echo "Invalid argument $1"
                                exit
                                ;;
    esac
    shift
done

if [ -d "cpython" ]; then
    echo -e "[WARN] using cached cpython"
else
    echo -e "[INFO] cloning cpython $CPYTHON_VERSION"
    git clone --quiet --depth=1 --branch=$CPYTHON_VERSION https://github.com/python/cpython.git $CPYTHON_PATH
fi

if [ -d "AFLplusplus" ]; then
    echo -e "[WARN] using cached AFLplusplus"
else
    echo -e "[INFO] cloning AFLplusplus $AFLPP_VER"
    git clone --quiet --depth=1 --branch=$AFLPP_VER https://github.com/AFLplusplus/AFLplusplus.git $AFLPP_PATH
fi

echo -e "Instructment python with:"
echo -e " VER: $GREEN $CPYTHON_VERSION $NC in $CPYTHON_PATH"
echo -e " AFL++: $GREEN $AFLPP_VER $NC in $AFLPP_PATH"

if [ $SKIP_AFL -eq 1 ]; then
    echo -e "[INFO] skip building AFLplusplus"
else
    echo -e "[INFO] cleaning AFLplusplus"
    cd $AFLPP_PATH
    nix-shell --pure --command "make -s clean" $WORK_DIR/aflpp.nix
    echo -e "$GREEN [INFO] building AFLplusplus $NC"
    # make -s -C $AFLPP_PATH distrib
    nix-shell --pure --command "CC='ccache clang' CXX='ccache clang++' make -s source-only -j$USING_CORE" $WORK_DIR/aflpp.nix
    cd $WORK_DIR
fi

if [ $SKIP_CPYTHON -eq 1 ]; then
    echo -e "[INFO] skip building CPython"
else
    cd $CPYTHON_PATH
    if [ $SKIP_CPYTHON_CONFIGURE -eq 0 ]; then
        if [ -f "Makefile" ]; then
            echo "$GREEN[INFO] cleaning CPython$NC"
            make clean
        fi
        
        echo -e "${GREEN}[INFO] configuring CPython$NC"
        # nix-shell --pure --command "autoreconf -fi" $WORK_DIR/cpython.nix
        nix-shell --pure --command "./configure CC='ccache $AFLPP_PATH/afl-clang-$MODE' CXX='ccache $AFLPP_PATH/afl-clang-$MODE++' --prefix=$CPYTHON_BIN --disable-shared" $WORK_DIR/cpython.nix
    fi

    echo -e "${GREEN}[INFO] patching CPython$NC"
    cp $WORK_DIR/src/entry.c $CPYTHON_PATH/Programs/python.c
    if [ "$(tail $CPYTHON_PATH/Python/pythonrun.c -n 1)" = "#endif" ]; then
        echo "PyObject *(*run_mod_fuzzer)(mod_ty, PyObject *, PyObject *, PyObject *,PyCompilerFlags *, PyArena *) = run_mod;" >> $CPYTHON_PATH/Python/pythonrun.c
    fi
    $WORK_DIR/get-allow-list.sh $CPYTHON_PATH
    echo -n "$CPYTHON_PATH/Programs/python.c" >> $WORK_DIR/afl-allow-list.txt
    
    echo -e "${GREEN}[INFO] building CPython$NC"
    rm -rf $CPYTHON_BIN
    # since the persistent mode will interrup normal main function, hence we need to suspend the tests of cpython
    sed -i 's/^TESTPYTHON=.*/TESTPYTHON=echo/' $CPYTHON_PATH/Makefile
    nix-shell --pure --command "AFL_LLVM_ALLOWLIST='$WORK_DIR/afl-allow-list.txt' make -s -j$USING_CORE build_all" $WORK_DIR/cpython.nix
    cd $WORK_DIR
fi

# python-config --version == $CPYTHON_VERSION
nix-shell --pure --command "clang $WORK_DIR/src/mutators/*.c -I$AFLPP_PATH/include -I$CPYTHON_PATH -I$CPYTHON_PATH/Include -I$CPYTHON_PATH/Include/internal -o $WORK_DIR/fuzzer.so --shared -O3 -march=native" $WORK_DIR/aflpp.nix
nix-shell --pure --command "clang $WORK_DIR/src/dumpAST.c -I$CPYTHON_PATH -I$CPYTHON_PATH/Include -I$CPYTHON_PATH/Include/internal -o $WORK_DIR/dumpAST" $WORK_DIR/aflpp.nix