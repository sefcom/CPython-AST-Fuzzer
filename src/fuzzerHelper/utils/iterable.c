#include "ast.h"

stmt_ty iterable_non_empty_and_type_cond(ast_data_t *data, PyObject *in_var, PyObject *type, stmt_ty body)
{
    expr_ty len = _PyAST_Attribute(
        _PyAST_Attribute(
            NAME_L(in_var),
            KEYS_OBJ,
            Load,
            LINE,
            data->arena),
        LEN_OBJ,
        Load,
        LINE,
        data->arena);
    expr_ty non_empty = _PyAST_Call(
        len,
        NULL,
        NULL,
        LINE,
        data->arena);
    expr_ty isinstance = _PyAST_Call(
        NAME_L(ISINSTANTANCE_OBJ),
        _Py_asdl_expr_seq_new(2, data->arena),
        NULL,
        LINE,
        data->arena);
    isinstance->v.Call.args->typed_elements[0] = NAME_L(in_var);
    isinstance->v.Call.args->typed_elements[1] = NAME_L(type);
    expr_ty cond = _PyAST_BoolOp(
        And,
        _Py_asdl_expr_seq_new(2, data->arena),
        LINE,
        data->arena);
    cond->v.BoolOp.values->typed_elements[0] = isinstance;
    cond->v.BoolOp.values->typed_elements[1] = non_empty;
    return do_w_cond(data, cond, body);
}

expr_ty _iterable_get_element(ast_data_t *data, expr_ty in_var, PyObject *index, expr_context_ty ctx)
{
    // in_var.keys()[index % in_var.keys().__len__()]
    // in_var[index % in_var.__len__()]
    expr_ty len_of_key = _PyAST_Call(
        _PyAST_Attribute(
            in_var,
            LEN_OBJ,
            Load,
            LINE,
            data->arena),
        NULL,
        NULL,
        LINE,
        data->arena);
    return _PyAST_Subscript(
        in_var,
        _PyAST_BinOp(
            _PyAST_Constant(index, NULL, LINE, data->arena),
            Mod,
            len_of_key,
            LINE,
            data->arena),
        ctx,
        LINE,
        data->arena);
}

expr_ty iterable_get_element_load(ast_data_t *data, expr_ty in_var, PyObject *index)
{
    return _iterable_get_element(data, in_var, index, Load);
}

expr_ty iterable_get_element_del(ast_data_t *data, expr_ty in_var, PyObject *index)
{
    return _iterable_get_element(data, in_var, index, Del);
}
