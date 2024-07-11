#include "mutators.h"

void entry_mutate(ast_data_t **data, size_t max_size, size_t seed){
    srand(seed);
    // switch(rand() % 2){
    //     // add class def and call init
    //     // add override function to class

    // }
    add_clz_and_init(*data);
}