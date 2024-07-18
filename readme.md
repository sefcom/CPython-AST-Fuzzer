# pyFuzzer
A toy project for Python interpreter fuzzing using AST-base mutators, based on LibFuzzer.  
*Started in SEFCOM.*

## Requirements
- nix-shell
- git for pulling source code
- python for code generation

## How to build
```bash
./build.sh
```

arguments:
- `-p` / `--cpython` forces to re-clone, re-patch and rebuild CPython
- `-f` / `--force` forces to re-generate all codgen codes, re-configure cmake and build
- `--clear` remove all cache directories
- `-j <core>` / `--jobs <core>` equivalent to `make -j<core>`

## How to run
```bash
./main.sh
```

arguments:
- `-c` / `--clean` removing all log directories
- `-d` / `--debug` using stdout instead of redirecting into log file
- `--cov` generate coverage report using `llvm-cov`
- `-r <turns>` / `--runs <turns>` equivalent to libFuzzer `-runs=<turns>`

## Executing every known crash
```bash
./check.sh
```

## Type hints for VScode
```bash
./gen_hints.sh
```

## Designing
[pipline.md](./pipline.md)  
For mutators list, check [mutators.h](./src/fuzzerHelper/mutators/mutators.h).  
My goal is to recover and find more similar bugs like the motivation samples in [pipline.md](./pipline.md).

## TODO
- [ ] Using Atheris to extend target modules from only builtin to others (Atheris only support Python <= 3.11 so far)
- [ ] Free useless ASTs in appropriate time
- [ ] Add more guide to mutator picking instead of pure randomness
- [ ] More mutator, more performance
- [ ] Automatically document parse
- [ ] is there any way to enable Corpus?
- [ ] More depth(it's only 2 rn)
- [ ] Multi-inherit class support(risk at conflicted class)
