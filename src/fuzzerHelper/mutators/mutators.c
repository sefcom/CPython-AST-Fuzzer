#include "mutators.h"
#include "deepcopy.h"

void entry_mutate(ast_data_t **data, size_t max_size, size_t seed){
    srand(seed);
    PyArena *arena = _PyArena_New();
    ast_data_t *new_data = (ast_data_t *)_PyArena_Malloc(arena, sizeof(ast_data_t));
    new_data->arena = arena;
    new_data->mod = mod_copy((*data)->mod, arena);
    // switch(rand() % 2){
    //     // add class def and call init
    //     // add override function to class

    // }
    add_clz_and_init(new_data);

    *data = new_data;
}