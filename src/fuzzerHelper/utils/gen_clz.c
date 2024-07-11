#include "ast.h"

// TODO keywords, mutiple base classes, decorators

int plain_clz(PyArena *arena, stmt_ty *stmt){
    int id;
    *stmt = _PyAST_ClassDef(
        gen_name(0, &id),
        get_asdl_expr_seq(0, arena),
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
int clz_inherited(PyArena *arena, const char *base, stmt_ty *stmt){
    int id;
    *stmt = _PyAST_ClassDef(
        gen_name(0, &id),
        get_asdl_expr_seq(1, arena),
        NULL,
        NULL,
        NULL,
        #if PYTHON_VER == 313
        NULL,
        #endif
        LINE,
        arena
    );
    (*stmt)->v.ClassDef.bases->typed_elements[0] = _PyAST_Name(PyUnicode_FromString_Arena(base, arena), Load, LINE, arena);
    return id;
}
