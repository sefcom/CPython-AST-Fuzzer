#include "ast.h"

stmt_ty func_w_name(ast_data_t *data, PyObject *name, arguments_ty args)
{
    stmt_ty stmt = _PyAST_FunctionDef(
        name,
        args,
        _Py_asdl_stmt_seq_new(1, data->arena), // body is required,
        NULL,
        NULL,
        NULL,
#if PYTHON_VER == 313
        NULL,
#endif
        LINE,
        data->arena);
    stmt->v.FunctionDef.body->typed_elements[0] = _PyAST_Pass(LINE, data->arena); // placeholder
    data->func_cnt++;
    return stmt;
}

stmt_ty get_func_internal(int *index, asdl_stmt_seq *stmt_seq, stmt_ty *base)
{
    for (int i = 0; i < stmt_seq->size; i++)
    {
        stmt_ty ele = stmt_seq->typed_elements[i];
        stmt_ty re;
        switch (ele->kind)
        {
        case FunctionDef_kind:
            if (*index == 0)
            {
                return ele;
            }
            (*index)--;
            break;
            RECURSIVE_CASE(ClassDef, get_func_internal, COMMA base, if (base != NULL && *base == NULL) { *base = ele; })
            RECURSIVE_CASE(If, get_func_internal, COMMA base, )
            RECURSIVE_CASE(While, get_func_internal, COMMA base, )
            RECURSIVE_CASE(For, get_func_internal, COMMA base, )
            RECURSIVE_CASE(With, get_func_internal, COMMA base, )
        default:
            break;
        }
    }
    return NULL;
}

stmt_ty get_func(ast_data_t *data, int index)
{
    int idx = index;
    stmt_ty re = get_func_internal(&idx, data->mod->v.Module.body, NULL);
    if (re == NULL)
    {
        PANIC("get_func: index out of range %d/%d\n", idx, index);
    }
    return re;
}

stmt_ty get_func_w_base_clz(ast_data_t *data, int index, stmt_ty *base)
{
    assert(base != NULL);
    *base = NULL;
    int idx = index;
    stmt_ty re = get_func_internal(&idx, data->mod->v.Module.body, base);
    if (re == NULL)
    {
        PANIC("get_func_w_base_clz: index out of range %d/%d\n", idx, index);
    }
    return re;
}