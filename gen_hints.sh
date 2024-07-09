#!/bin/bash
set -e

###
# setup environment and type hints for vscode
###

WORK_DIR=$(readlink -f .)
SCRIPT_DIR=$(readlink -f ./scripts)
CPYTHON_VERSION=3.11.9

nix-shell --pure --command "python $WORK_DIR/scripts/gen_hints.py $WORK_DIR/.vscode" $SCRIPT_DIR/hints.nix --argstr py_ver_str $CPYTHON_VERSION
