echo "" > ./afl-allow-list.txt
find $(pwd)/cpython/Modules -name "*.c" >> ./afl-allow-list.txt
find $(pwd)/cpython/Objects -name "*.c" >> ./afl-allow-list.txt