#include "mutators.h"
#include "deepcopy.h"

ast_data_t *copy_asd_data_t(ast_data_t *src){
    PyArena *arena = _PyArena_New();
    ast_data_t *dst = (ast_data_t *)_PyArena_Malloc(arena, sizeof(ast_data_t));
    dst->arena = arena;
    if(dst->arena == NULL){
        fprintf(stderr, "arena is NULL\n");
    }
    dst->mod = mod_copy(src->mod, dst->arena);
    dst->gen_name_cnt = src->gen_name_cnt;
    dst->func_cnt = src->func_cnt;
    dst->plain_clz_cnt = src->plain_clz_cnt;
    dst->inherited_clz_cnt = src->inherited_clz_cnt;
    return dst;
}

void entry_mutate(ast_data_t **data, size_t max_size, size_t seed){
    srand(seed);
    ast_data_t *new_data;
    int state = -1;
    while(1){
        if(state == -1){
            new_data = copy_asd_data_t(*data);
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
                if(new_data->plain_clz_cnt == 0){
                    state = -2; // no plain classes defined yet, just re-roll
                    break;
                }
                int picked_clz_id = rand() % new_data->plain_clz_cnt;
                printf("picked_clz: %d/%d\n", picked_clz_id, new_data->plain_clz_cnt);
                stmt_ty picked_clz = get_clz(new_data->mod->v.Module.body, picked_clz_id, 1);
                assert(picked_clz != NULL);
                int picked_clz_base = rand() % builtin_type_cnt;
                state = make_clz_inherit(new_data, picked_clz, builtin_clz_obj[picked_clz_base]);
                break;
        }
        if(state == -1){
            // redo the loop
            printf("bad state, redo\n");
            _PyArena_Free(new_data->arena);
            continue;
        }else if(state == 0){
            break;
        }
    }
    *data = new_data;
}