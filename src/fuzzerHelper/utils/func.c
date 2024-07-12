#include "ast.h"

int plain_func(PyArena *arena, stmt_ty *stmt, arguments_ty args){
    int id;
    *stmt = _PyAST_FunctionDef(
        gen_name(0, &id),
        args,
        NULL,
        NULL,
        NULL,
        NULL,
        #if PYTHON_VER == 313
        NULL,
        #endif
        LINE,
        arena
    );
    return id;
}
void func_w_name(PyArena *arena, PyObject *name, stmt_ty *stmt, arguments_ty args){
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
        arena
    );
}