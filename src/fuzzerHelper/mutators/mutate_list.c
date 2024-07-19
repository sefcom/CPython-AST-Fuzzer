#include "mutators.h"
#include "deepcopy.h"
#include "override_func.h"

int mutate_list_entry(ast_data_t *data, stmt_ty picked_func)
{
    int state = STATE_REROLL;
    stmt_ty add_stmt = NULL;
    while (state != STATE_OK)
    {
        asdl_arg_seq *args = picked_func->v.FunctionDef.args->args;
        int picked_arg_id = rand() % args->size;
        PyObject *picked_arg = args->typed_elements[picked_arg_id]->arg;
        PyObject *val;
        int picked_mod = rand() % 4;
        switch (picked_mod)
        {
        // append
        case 0:
        {
            INFO("append\n");
            PyObject *val;
            if (rand() % 2)
            {
                // random arg mode
                if (picked_func->v.FunctionDef.args->args->size == 1)
                {
                    state = STATE_REROLL;
                    break;
                }
                int picked_arg_id2 = rand() % (picked_func->v.FunctionDef.args->args->size - 1);
                if (picked_arg_id2 >= picked_arg_id)
                {
                    picked_arg_id2++;
                }
                val = picked_func->v.FunctionDef.args->args->typed_elements[picked_arg_id2]->arg;
            }
            else
            {
                if (data->locals_cnt == 0)
                {
                    state = STATE_REROLL;
                    break;
                }
                int picked_local_id = rand() % data->locals_cnt;
                val = get_locals(data, picked_local_id);
            }
            asdl_expr_seq *body = _Py_asdl_expr_seq_new(1, data->arena);
            body->typed_elements[0] = NAME_L(val);
            add_stmt = iterable_non_empty_and_type_cond(
                data,
                picked_arg,
                builtin_clz_obj[CLZ_LIST],
                stmt(_PyAST_Call(
                         _PyAST_Attribute(
                             NAME_L(picked_arg),
                             APPEND_OBJ,
                             Load,
                             LINE,
                             data->arena),
                         body,
                         NULL,
                         LINE,
                         data->arena),
                     data->arena));
            state = STATE_OK;
            break;
        }
        // pop
        case 1:
        {
            INFO("pop\n");
            add_stmt = iterable_non_empty_and_type_cond(
                data,
                picked_arg,
                builtin_clz_obj[CLZ_LIST],
                stmt(_PyAST_Call(
                         _PyAST_Attribute(
                             NAME_L(picked_arg),
                             POP_OBJ,
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
        // clear
        case 2:
        {
            INFO("clear\n");
            add_stmt = iterable_non_empty_and_type_cond(
                data,
                picked_arg,
                builtin_clz_obj[CLZ_LIST],
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
        // del random item
        case 3:
        {
            INFO("del random item\n");
            asdl_expr_seq *targets = _Py_asdl_expr_seq_new(1, data->arena);
            targets->typed_elements[0] = iterable_get_element_del(data, NAME_L(picked_arg), LONG(rand()));
            add_stmt = iterable_non_empty_and_type_cond(
                data,
                picked_arg,
                builtin_clz_obj[CLZ_LIST],
                _PyAST_Delete(
                    targets,
                    LINE,
                    data->arena));
            state = STATE_OK;
            break;
        }
        }
    }
    picked_func->v.FunctionDef.body = asdl_stmt_seq_copy_add(picked_func->v.FunctionDef.body, data->arena, 1);
    picked_func->v.FunctionDef.body->typed_elements[picked_func->v.FunctionDef.body->size - 1] = add_stmt;
    return STATE_OK;
}