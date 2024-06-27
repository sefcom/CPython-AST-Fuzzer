find $1/Modules -name "*.c" > ./afl-allow-list.txt
find $1/Objects -name "*.c" >> ./afl-allow-list.txt