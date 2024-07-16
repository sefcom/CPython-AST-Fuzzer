#include "ast.h"

// TODO keywords, mutiple base classes, decorators

stmt_ty plain_clz(ast_data_t *data, PyObject *name){
    stmt_ty stmt = _PyAST_ClassDef(
        name,
        NULL,
        NULL,
        _Py_asdl_stmt_seq_new(1, data->arena), // body is required
        NULL,
        #if PYTHON_VER == 313
        NULL,
        #endif
        LINE,
        data->arena
    );
    stmt->v.ClassDef.body->typed_elements[0] = _PyAST_Pass(LINE, data->arena); // placeholder
    data->plain_clz_cnt++;
    return stmt;
}
stmt_ty clz_inherited(ast_data_t *data, const char *base, PyObject *name){
    stmt_ty stmt = _PyAST_ClassDef(
        name,
        _Py_asdl_expr_seq_new(1, data->arena),
        NULL,
        _Py_asdl_stmt_seq_new(1, data->arena), // body is required,
        NULL,
        #if PYTHON_VER == 313
        NULL,
        #endif
        LINE,
        data->arena
    );
    data->inherited_clz_cnt++;
    stmt->v.ClassDef.body->typed_elements[0] = _PyAST_Pass(LINE, data->arena); // placeholder
    stmt->v.ClassDef.bases->typed_elements[0] = _PyAST_Name(PyUnicode_FromString_Arena(base, data->arena), Load, LINE, data->arena);
    return stmt;
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
    PANIC("get_clz: index out of range %d/%d\n", cnt, index);
    return NULL;
}

stmt_ty find_clz(asdl_stmt_seq *stmt_seq, PyObject *clz_name)
{
    for (int i = 0; i < stmt_seq->size; i++)
    {
        if (stmt_seq->typed_elements[i]->kind == ClassDef_kind)
        {
            if (PyUnicode_Compare((stmt_seq->typed_elements[i])->v.ClassDef.name, clz_name) == 0)
            {
                return stmt_seq->typed_elements[i];
            }
        }
    }
    PANIC("find_clz: class %s not found\n", PyUnicode_AsUTF8(clz_name));
    return NULL;
}
