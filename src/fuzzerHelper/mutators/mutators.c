#include "mutators.h"
#include "deepcopy.h"

ast_data_t *copy_asd_data_t(ast_data_t *src)
{
    PyArena *arena = _PyArena_New();
    ast_data_t *dst = (ast_data_t *)_PyArena_Malloc(arena, sizeof(ast_data_t));
    dst->arena = arena;
    if (dst->arena == NULL)
    {
        PANIC("arena is NULL\n");
    }
    dst->mod = mod_copy(src->mod, dst->arena);
    dst->gen_name_cnt = src->gen_name_cnt;
    dst->func_cnt = src->func_cnt;
    dst->plain_clz_cnt = src->plain_clz_cnt;
    dst->inherited_clz_cnt = src->inherited_clz_cnt;
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
        switch (rand() % 3)
        {
        // add class def and call init
        case 0:
        {
            INFO("mutator: add_clz_and_init\n");
            state = add_clz_and_init(new_data);
        }
        break;
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
        }
        break;
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
            state = add_rand_override(new_data, picked_clz, rand_override_func(clz_base_id));
        }
        break;
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