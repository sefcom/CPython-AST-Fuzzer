#include "ast.h"

// TODO keywords, mutiple base classes, decorators

int plain_clz(ast_data_t *data, stmt_ty *stmt){
    int id = (data->gen_name_cnt)++;
    *stmt = _PyAST_ClassDef(
        gen_name_id(id),
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
    (*stmt)->v.ClassDef.body->typed_elements[0] = _PyAST_Pass(LINE, data->arena); // placeholder
    data->plain_clz_cnt++;
    return id;
}
int clz_inherited(ast_data_t *data, const char *base, stmt_ty *stmt){
    int id = (data->gen_name_cnt)++;
    *stmt = _PyAST_ClassDef(
        gen_name_id(id),
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
    (*stmt)->v.ClassDef.body->typed_elements[0] = _PyAST_Pass(LINE, data->arena); // placeholder
    (*stmt)->v.ClassDef.bases->typed_elements[0] = _PyAST_Name(PyUnicode_FromString_Arena(base, data->arena), Load, LINE, data->arena);
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
            if (PyUnicode_Compare((stmt_seq->typed_elements[i])->v.ClassDef.name, clz_name) == 0)
            {
                return stmt_seq->typed_elements[i];
            }
        }
    }
    return NULL;
}
