AFL_CUSTOM_MUTATOR_ONLY=1 AFL_DEBUG=1 AFL_CUSTOM_MUTATOR_LIBRARY=./fuzzer.so ./AFLplusplus/afl-fuzz -i seeds_dir -o output_dir ./cpython/python
