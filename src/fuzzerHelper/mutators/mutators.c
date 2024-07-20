#include "mutators.h"

ast_data_t *copy_asd_data_t(ast_data_t *src)
{
    PyArena *arena = _PyArena_New();
    if (arena == NULL)
    {
        PANIC("arena is NULL\n");
    }
    ast_data_t *dst = (ast_data_t *)_PyArena_Malloc(arena, sizeof(ast_data_t));
    memcpy(dst, src, sizeof(ast_data_t));
    dst->arena = arena;
    dst->mod = mod_copy(src->mod, dst->arena);
    return dst;
}

// TODO only do the 2 layers depth rn
int entry_mutate(ast_data_t **data, size_t max_size, size_t seed)
{
    srand(seed);
    ast_data_t *new_data;
    int state = STATE_COPY_REROLL;
    while (state != STATE_OK)
    {
        if (state == STATE_COPY_REROLL)
        {
            new_data = copy_asd_data_t(*data);
            state = STATE_REROLL;
        }
        switch (rand() % 8)
        {
        // add class def and call init
        case 0:
        {
            INFO("mutator: add_clz_and_init\n");
            state = add_clz_and_init(new_data);
            break;
        }
        // inherit a plain class from random base class
        case 1:
        {
            INFO("mutator: make_clz_inherit\n");
            if (new_data->plain_clz_cnt == 0)
            {
                state = STATE_REROLL; // no plain classes defined yet, just re-roll
                break;
            }
            int picked_clz_id = rand() % new_data->plain_clz_cnt;
            INFO("picked_clz: %d/%d\n", picked_clz_id, new_data->plain_clz_cnt);
            stmt_ty picked_clz = get_clz(new_data->mod->v.Module.body, picked_clz_id, 1);
            assert(picked_clz != NULL);
            int picked_clz_base = rand() % builtin_type_cnt;
            state = make_clz_inherit(new_data, picked_clz, builtin_clz_obj[picked_clz_base]);
            break;
        }
        // add random override function
        case 2:
        {
            INFO("mutator: add_rand_override\n");
            int clz_cnt = new_data->plain_clz_cnt + new_data->inherited_clz_cnt;
            if (clz_cnt == 0)
            {
                state = STATE_REROLL; // no classes defined yet, just re-roll
                break;
            }
            int picked_clz_id = rand() % clz_cnt;
            INFO("picked_clz: %d/%d\n", picked_clz_id, clz_cnt);
            stmt_ty picked_clz = get_clz(new_data->mod->v.Module.body, picked_clz_id, 0);
            assert(picked_clz != NULL);
            int clz_base_id = 0; // default inherit from object
            if (picked_clz->v.ClassDef.bases != NULL && picked_clz->v.ClassDef.bases->size > 0)
            {
                for (int i = 0; i < builtin_type_cnt; i++)
                {
                    assert(builtin_clz_obj[i] != NULL);
                    if (PyUnicode_Compare(picked_clz->v.ClassDef.bases->typed_elements[0]->v.Name.id, builtin_clz_obj[i]) == 0)
                    {
                        clz_base_id = i;
                        break;
                    }
                }
            }
            overridable_func picked_func = rand_override_func(clz_base_id);
            state = add_rand_override(new_data, picked_clz, picked_func);
            if(state == 0 && new_data->locals_cnt > picked_func.args_size - (picked_func.arg_type & HAS_SELF)){
                // try to call the override func
                state = feed_func_locals(new_data, get_func(new_data, new_data->func_cnt - 1), picked_clz);
                if(state == STATE_REROLL){
                    state = STATE_OK;
                }
            }
            break;
        }
        // init a builtin type instance
        case 3:
        {
            int picked_type = rand() % builtin_type_cnt;
            int global = rand() % 2;
            if (global)
            {
                INFO("mutator: init_builtin_instance in global\n");
                state = init_builtin_instance(new_data, builtin_clz_obj[picked_type], &(new_data->mod->v.Module.body));
            }
            else
            {
                INFO("mutator: init_builtin_instance in func\n");
                if (new_data->func_cnt == 0)
                {
                    state = STATE_REROLL; // no functions defined yet, just re-roll
                    break;
                }
                int picked_func_id = rand() % new_data->func_cnt;
                stmt_ty picked_func = get_func(new_data, picked_func_id);
                state = init_builtin_instance(new_data, builtin_clz_obj[picked_type], &(picked_func->v.FunctionDef.body));
            }
            break;
        }
        // blend locals
        case 4:
        {
            // this mutator may introduce runtime exception, so just reduce the chance
            if (rand() % 2)
            {
                state = STATE_REROLL;
                break;
            }
            INFO("mutator: blend_locals\n");
            if (new_data->locals_cnt < 2)
            {
                state = STATE_REROLL; // no locals defined yet, just re-roll
                break;
            }
            state = blend_locals_global(new_data);
            break;
        }
        // modify argument based on types
        case 5:
        {
            INFO("mutator: modify_arguments\n");
            if (new_data->func_cnt == 0)
            {
                state = STATE_REROLL; // no functions defined yet, just re-roll
                break;
            }
            int picked_func_id = rand() % new_data->func_cnt;
            stmt_ty picked_func = get_func(new_data, picked_func_id);
            if (picked_func->v.FunctionDef.args->args->size == 0)
            {
                state = STATE_REROLL;
                break;
            }
            int picked_type = rand() % builtin_type_cnt;

            switch (picked_type)
            {
            case CLZ_DICT:
            {
                INFO("CLZ_DICT w/ picked_func: %d/%d\n", picked_func_id, new_data->func_cnt);
                state = mutate_dict_entry(new_data, picked_func);
                break;
            }
            case CLZ_LIST:
            {
                INFO("CLZ_LIST w/ picked_func: %d/%d\n", picked_func_id, new_data->func_cnt);
                state = mutate_list_entry(new_data, picked_func);
                break;
            }
            default:
            {
                state = STATE_REROLL;
                break;
            }
            }
            break;
        }
        // feed random function with random locals
        case 6:
        {
            INFO("mutator: feed_func_locals\n");
            if (new_data->func_cnt == 0 || new_data->locals_cnt == 0)
            {
                state = STATE_REROLL; // no functions or locals defined yet, just re-roll
                break;
            }
            int picked_func_id = rand() % new_data->func_cnt;
            stmt_ty base_clz = NULL;
            stmt_ty func = get_func_w_base_clz(new_data, picked_func_id, &base_clz);
            state = feed_func_locals(new_data, func, base_clz);
            break;
        }
        // add random lifetime annotation
        case 7:
        {
            INFO("mutator: add_lifetime_annotation\n");
            if(new_data->func_cnt == 0){
                state = STATE_REROLL;
                break;
            }
            int picked_func_id = rand() % new_data->func_cnt;
            stmt_ty func = get_func(new_data, picked_func_id);
            state = func_variable_lifetime(new_data, func);
            break;
        }
        }

        if (unlikely(PyErr_Occurred() || new_data->mod == NULL) || !_PyAST_Validate(new_data->mod))
        {
            ERROR("invalid ast\n");
            ERROR("more info: mod=%p, func_cnt=%d, plain_clz_cnt=%d, inherited_clz_cnt=%d\n",
                  new_data->mod, new_data->func_cnt, new_data->plain_clz_cnt, new_data->inherited_clz_cnt);
            state = STATE_COPY_REROLL; // dirty data
        }

        if (unlikely(PyErr_Occurred()))
        {
            PyErr_Print();
            PyErr_Clear();
        }

        if (state != STATE_OK)
        {
            // redo the loop
            INFO("bad state %d, redo\n", state);
            if (state == STATE_COPY_REROLL)
            {
                // clean dirty data
                _PyArena_Free(new_data->arena);
            }
            continue;
        }
    }
    *data = new_data;
    return sizeof(ast_data_t *);
}