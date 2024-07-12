#include "ast.h"

int plain_func(ast_data_t *data, stmt_ty *stmt, arguments_ty args){
    int id = (data->gen_name_cnt)++;
    *stmt = _PyAST_FunctionDef(
        gen_name_id(id),
        args,
        NULL,
        NULL,
        NULL,
        NULL,
        #if PYTHON_VER == 313
        NULL,
        #endif
        LINE,
        data->arena
    );
    data->func_cnt++;
    return id;
}
void func_w_name(ast_data_t *data, PyObject *name, stmt_ty *stmt, arguments_ty args){
    *stmt = _PyAST_FunctionDef(
        name,
        args,
        NULL,
        NULL,
        NULL,
        NULL,
        #if PYTHON_VER == 313
        NULL,
        #endif
        LINE,
        data->arena
    );
    data->func_cnt++;
}