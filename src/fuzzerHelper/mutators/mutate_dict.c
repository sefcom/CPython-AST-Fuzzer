#include "mutators.h"
#include "mutate_type.h"

MUTATE_TYPE(dict)
{
    MUTATE_TYPE_LOOP
    {
        asdl_arg_seq *args = picked_func->v.FunctionDef.args->args;
        PICK_ARG
        int picked_mod = rand() % 4;
        switch (picked_mod)
        {
        case 0: // override random arg w/ random locals
        {
            INFO("override random item w/ random locals\n");
            PyObject *val;
            if (rand() % 2)
            {
                // random arg mode
                if (args->size == 1)
                {
                    state = STATE_REROLL;
                    break;
                }
                int picked_arg_id2 = rand() % (args->size - 1);
                if (picked_arg_id2 >= picked_arg_id)
                {
                    picked_arg_id2++;
                }
                val = args->typed_elements[picked_arg_id2]->arg;
            }
            else
            {
                if (data->locals_cnt == 0)
                {
                    state = STATE_REROLL; // no locals defined yet, just re-roll
                    break;
                }
                int picked_local_id = rand() % data->locals_cnt;
                val = get_locals(data, picked_local_id);
            }
            add_stmt = iterable_non_empty_and_type_cond(data, picked_arg, builtin_clz_obj[CLZ_DICT], dict_assign(data, picked_arg, CONST(val), LONG(rand())));
            state = STATE_OK;
            break;
        }
        case 1: // override w/ self
        {
            INFO("override w/ self\n");
            if (args->size <= 1 || PyUnicode_CompareWithASCIIString(args->typed_elements[0]->arg, "self") != 0)
            {
                state = STATE_REROLL;
                break;
            }
            if (picked_arg_id == 0)
            {
                PICK_ARG_OFS(-1, 1)
            }
            add_stmt = iterable_non_empty_and_type_cond(data, picked_arg, builtin_clz_obj[CLZ_DICT], dict_assign(data, picked_arg, CONST(SELF_OBJ), LONG(rand())));
            state = STATE_OK;
            break;
        }
        case 2: // del random args
        {
            INFO("del random item\n");
            add_stmt = iterable_non_empty_and_type_cond(data, picked_arg, builtin_clz_obj[CLZ_DICT], dict_del(data, picked_arg, LONG(rand())));
            state = STATE_OK;
            break;
        }
        case 3: // clear
        {
            INFO("clear\n");
            add_stmt = iterable_non_empty_and_type_cond(
                data,
                picked_arg,
                builtin_clz_obj[CLZ_DICT],
                stmt(_PyAST_Call(
                         _PyAST_Attribute(
                             NAME_L(picked_arg),
                             CLEAR_OBJ,
                             Load,
                             LINE,
                             data->arena),
                         NULL,
                         NULL,
                         LINE,
                         data->arena),
                     data->arena));
            state = STATE_OK;
            break;
        }
        }
    }
    MERGE_STMT
    return STATE_OK;
}