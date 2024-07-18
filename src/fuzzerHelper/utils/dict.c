#include "ast.h"
#include "override_func.h"

stmt_ty dict_assign(ast_data_t *data, PyObject *in_var, expr_ty value, PyObject *index)
{
    // in_var[index % in_var.keys().__len__()] = value
    stmt_ty stmt = _PyAST_Assign(
        _Py_asdl_expr_seq_new(1, data->arena),
        value,
        NULL,
        LINE,
        data->arena);
    expr_ty keys = _PyAST_Call(
        _PyAST_Attribute(
            NAME_L(in_var),
            KEYS_OBJ,
            Load,
            LINE,
            data->arena),
        NULL,
        NULL,
        LINE,
        data->arena);
    stmt->v.Assign.targets->typed_elements[0] = _PyAST_Subscript(
        NAME_L(in_var),
        iterable_get_element(data, keys, index),
        Store,
        LINE,
        data->arena);
    return stmt;
}

stmt_ty dict_del(ast_data_t *data, PyObject *in_var, PyObject *index)
{
    // del in_var[index % in_var.keys().__len__()]
    stmt_ty stmt = _PyAST_Delete(
        _Py_asdl_expr_seq_new(1, data->arena),
        LINE,
        data->arena);
    expr_ty keys = _PyAST_Call(
        _PyAST_Attribute(
            NAME_L(in_var),
            KEYS_OBJ,
            Load,
            LINE,
            data->arena),
        NULL,
        NULL,
        LINE,
        data->arena);
    stmt->v.Delete.targets->typed_elements[0] = _PyAST_Subscript(
        NAME_L(in_var),
        iterable_get_element(data, keys, index),
        Del,
        LINE,
        data->arena);
    return stmt;
}
