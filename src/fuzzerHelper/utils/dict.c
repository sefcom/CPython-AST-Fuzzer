#include "ast.h"
#include "override_func.h"

stmt_ty dict_do_w_cond(ast_data_t *data, expr_ty cond, stmt_ty body)
{
    stmt_ty stmt = _PyAST_If(
        cond,
        _Py_asdl_stmt_seq_new(1, data->arena),
        NULL,
        LINE,
        data->arena);
    stmt->v.If.body->typed_elements[0] = body;
    return stmt;
}

expr_ty dict_get_element(ast_data_t *data, PyObject *in_var, PyObject *index)
{
    // in_var[index % in_var.keys().__len__()]
    expr_ty keys = _PyAST_Call(
        _PyAST_Attribute(
            _PyAST_Name(in_var, Load, LINE, data->arena),
            KEYS_OBJ,
            Load,
            LINE,
            data->arena),
        NULL,
        NULL,
        LINE,
        data->arena);
    expr_ty len_of_key = _PyAST_Call(
        _PyAST_Attribute(
            _PyAST_Name(in_var, Load, LINE, data->arena),
            LEN_OBJ,
            Load,
            LINE,
            data->arena),
        NULL,
        NULL,
        LINE,
        data->arena);
    return _PyAST_Subscript(
        keys,
        _PyAST_BinOp(
            _PyAST_Constant(index, NULL, LINE, data->arena),
            Mod,
            len_of_key,
            LINE,
            data->arena),
        Load,
        LINE,
        data->arena);
}

// --- end of helpers ---

stmt_ty dict_non_empty_and_type_cond(ast_data_t *data, PyObject *in_var, stmt_ty body)
{
    expr_ty len = _PyAST_Attribute(
        _PyAST_Attribute(
            _PyAST_Name(in_var, Load, LINE, data->arena),
            KEYS_OBJ,
            Load,
            LINE,
            data->arena),
        LEN_OBJ,
        Load,
        LINE,
        data->arena);
    expr_ty non_empty = _PyAST_UnaryOp(
        UAdd,
        _PyAST_Call(
            len,
            NULL,
            NULL,
            LINE,
            data->arena),
        LINE,
        data->arena);
    expr_ty isinstance = _PyAST_Call(
        _PyAST_Name(ISINSTANTANCE_OBJ, Load, LINE, data->arena),
        _Py_asdl_expr_seq_new(2, data->arena),
        NULL,
        LINE,
        data->arena);
    isinstance->v.Call.args->typed_elements[0] = _PyAST_Name(in_var, Load, LINE, data->arena);
    isinstance->v.Call.args->typed_elements[1] = _PyAST_Name(builtin_clz_obj[CLZ_DICT], Load, LINE, data->arena);
    expr_ty cond = _PyAST_BoolOp(
        And,
        _Py_asdl_expr_seq_new(2, data->arena),
        LINE,
        data->arena);
    cond->v.BoolOp.values->typed_elements[0] = isinstance;
    cond->v.BoolOp.values->typed_elements[1] = non_empty;
    return dict_do_w_cond(data, cond, body);
}

stmt_ty dict_assign(ast_data_t *data, PyObject *in_var, expr_ty value, PyObject *index)
{
    // in_var[index % in_var.keys().__len__()] = value
    stmt_ty stmt = _PyAST_Assign(
        _Py_asdl_expr_seq_new(1, data->arena),
        value,
        NULL,
        LINE,
        data->arena);
    stmt->v.Assign.targets->typed_elements[0] = _PyAST_Subscript(
        _PyAST_Name(in_var, Load, LINE, data->arena),
        dict_get_element(data, in_var, index),
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
    stmt->v.Delete.targets->typed_elements[0] = _PyAST_Subscript(
        _PyAST_Name(in_var, Load, LINE, data->arena),
        dict_get_element(data, in_var, index),
        Del,
        LINE,
        data->arena);
    return stmt;
}
