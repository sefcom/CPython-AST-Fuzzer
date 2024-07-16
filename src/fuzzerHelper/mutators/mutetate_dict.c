#include "mutators.h"
#include "deepcopy.h"

#define CONST(name) _PyAST_Constant(name, NULL, LINE, data->arena)
#define LONG(name) PyLong_FromLong_Arena(name, data->arena)

int mutate_dict_entry(ast_data_t *data, stmt_ty picked_func)
{
    int state = STATE_REROLL;
    stmt_ty add_stmt = NULL;
    while (state)
    {
        int picked_mod = rand() % 3;
        switch (picked_mod)
        {
        case 0: // assign random arg w/ random locals
        {
            INFO("assign random item w/ random locals\n");
            if (data->locals_cnt == 0)
            {
                state = STATE_REROLL; // no locals defined yet, just re-roll
                break;
            }
            int picked_local_id = rand() % data->locals_cnt;
            PyObject *picked_local = get_locals(data, picked_local_id);
            asdl_arg_seq *args = picked_func->v.FunctionDef.args->args;
            int picked_arg_id = rand() % args->size;
            PyObject *picked_arg = args->typed_elements[picked_arg_id]->arg;
            add_stmt = dict_non_empty_and_type_cond(data, picked_arg, dict_assign(data, picked_arg, CONST(picked_local), LONG(rand())));
            state = STATE_OK;
            break;
        }
        case 1: // assign w/ self
        {
            INFO("assign w/ self\n");
            asdl_arg_seq *args = picked_func->v.FunctionDef.args->args;
            if (args->size == 1 || PyUnicode_CompareWithASCIIString(args->typed_elements[0]->arg, "self") != 0)
            {
                state = STATE_REROLL;
                break;
            }
            int picked_arg_id = rand() % (args->size - 1) + 1;
            PyObject *picked_arg = args->typed_elements[picked_arg_id]->arg;
            add_stmt = dict_non_empty_and_type_cond(data, picked_arg, dict_assign(data, picked_arg, CONST(SELF_OBJ), LONG(rand())));
            state = STATE_OK;
            break;
        }
        case 2: // del random args
        {
            INFO("del random item\n");
            asdl_arg_seq *args = picked_func->v.FunctionDef.args->args;
            int picked_arg_id = rand() % args->size;
            PyObject *picked_arg = args->typed_elements[picked_arg_id]->arg;
            add_stmt = dict_non_empty_and_type_cond(data, picked_arg, dict_del(data, picked_arg, LONG(rand())));
            state = STATE_OK;
            break;
        }
        }
    }
    picked_func->v.FunctionDef.body = asdl_stmt_seq_copy_add(picked_func->v.FunctionDef.body, data->arena, 1);
    picked_func->v.FunctionDef.body->typed_elements[picked_func->v.FunctionDef.body->size - 1] = add_stmt;
    return STATE_OK;
}