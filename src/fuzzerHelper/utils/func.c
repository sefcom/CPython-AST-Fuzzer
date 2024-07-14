#include "ast.h"

int plain_func(ast_data_t *data, stmt_ty *stmt, arguments_ty args){
    int id = (data->gen_name_cnt)++;
    *stmt = _PyAST_FunctionDef(
        gen_name_id(id),
        args,
        _Py_asdl_stmt_seq_new(1, data->arena),
        NULL,
        NULL,
        NULL,
        #if PYTHON_VER == 313
        NULL,
        #endif
        LINE,
        data->arena
    );
    (*stmt)->v.FunctionDef.body->typed_elements[0] = _PyAST_Pass(LINE, data->arena); // placeholder
    data->func_cnt++;
    return id;
}
void func_w_name(ast_data_t *data, PyObject *name, stmt_ty *stmt, arguments_ty args){
    *stmt = _PyAST_FunctionDef(
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
        data->arena
    );
    (*stmt)->v.FunctionDef.body->typed_elements[0] = _PyAST_Pass(LINE, data->arena); // placeholder
    data->func_cnt++;
}