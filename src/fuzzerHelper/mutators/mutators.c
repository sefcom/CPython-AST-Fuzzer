#include "mutators.h"
#include "deepcopy.h"

void entry_mutate(ast_data_t **data, size_t max_size, size_t seed){
    srand(seed);
    ast_data_t *new_data;
    int state = -1;
    while(1){
        PyArena *arena;
        if(state == -1){
            arena = _PyArena_New();
            new_data = (ast_data_t *)_PyArena_Malloc(arena, sizeof(ast_data_t));
            new_data->arena = arena;
            new_data->mod = mod_copy((*data)->mod, arena);
        }
        state = -2;
        switch(rand() % 2){
            // add class def and call init
            case 0:
                state = add_clz_and_init(new_data);
                break;
            // inherit a plain class from random base class
            case 1:
                int plain_clz_cnt;
                int clz_cnt = get_clz_count(new_data->mod->v.Module.body, &plain_clz_cnt);
                if(clz_cnt == 0){
                    state = -2; // just re-roll
                    break;
                }
                // TODO
                state = make_clz_inherit(new_data, gen_name(0, NULL), "object");
                break;
        }
        if(state == -1){
            // redo the loop
            _PyArena_Free(arena);
            continue;
        }else if(state == 0){
            break;
        }
    }
    *data = new_data;
}