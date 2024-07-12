#include "ast.h"

// TODO keywords, mutiple base classes, decorators

int plain_clz(PyArena *arena, stmt_ty *stmt){
    int id;
    *stmt = _PyAST_ClassDef(
        gen_name(0, &id),
        _Py_asdl_expr_seq_new(0, arena),
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
        _Py_asdl_expr_seq_new(1, arena),
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

int get_clz_count(asdl_stmt_seq *stmt_seq, int *plain_clz)
{
    int cnt = 0;
    if(plain_clz != NULL){
        *plain_clz = 0;
    }
    for (int i = 0; i < stmt_seq->size; i++)
    {
        if (stmt_seq->typed_elements[i]->kind == ClassDef_kind)
        {
            if(plain_clz != NULL && (stmt_seq->typed_elements[i]->v.ClassDef.bases == NULL || stmt_seq->typed_elements[i]->v.ClassDef.bases->size == 0)){
                *plain_clz = *plain_clz + 1;
            }
            cnt++;
        }
    }
    return cnt;
}

stmt_ty get_clz(asdl_stmt_seq *stmt_seq, int index, int plain_clz_required)
{
    int cnt = 0;
    for (int i = 0; i < stmt_seq->size; i++)
    {
        if (stmt_seq->typed_elements[i]->kind == ClassDef_kind)
        {
            if(plain_clz_required && stmt_seq->typed_elements[i]->v.ClassDef.bases != NULL && stmt_seq->typed_elements[i]->v.ClassDef.bases->size > 0){
                continue;
            }
            if (cnt == index)
            {
                return stmt_seq->typed_elements[i];
            }
            cnt++;
        }
    }
    return NULL;
}

stmt_ty find_clz(asdl_stmt_seq *stmt_seq, PyObject *clz_name)
{
    for (int i = 0; i < stmt_seq->size; i++)
    {
        if (stmt_seq->typed_elements[i]->kind == ClassDef_kind)
        {
            // because all names are generated, the address should be same if content is same
            if (((stmt_ty)stmt_seq->typed_elements[i])->v.ClassDef.name == clz_name)
            {
                return stmt_seq->typed_elements[i];
            }
        }
    }
    return NULL;
}
