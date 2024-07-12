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
                printf("mutator: add_clz_and_init\n");
                state = add_clz_and_init(new_data);
                break;
            // inherit a plain class from random base class
            case 1:
                printf("mutator: make_clz_inherit\n");
                int plain_clz_cnt = 0;
                int clz_cnt = get_clz_count(new_data->mod->v.Module.body, &plain_clz_cnt);
                if(plain_clz_cnt == 0){
                    state = -2; // no plain classes defined yet, just re-roll
                    break;
                }
                int picked_clz_id = rand() % plain_clz_cnt;
                printf("picked_clz: %d/%d\n", picked_clz_id, plain_clz_cnt);
                stmt_ty picked_clz = get_clz(new_data->mod->v.Module.body, picked_clz_id, 1);
                assert(picked_clz != NULL);
                int picked_clz_base = rand() % builtin_type_cnt;
                state = make_clz_inherit(new_data, picked_clz, builtin_clz_obj[picked_clz_base]);
                break;
        }
        if(state == -1){
            // redo the loop
            printf("bad state, redo\n");
            _PyArena_Free(arena);
            continue;
        }else if(state == 0){
            break;
        }
    }
    *data = new_data;
}