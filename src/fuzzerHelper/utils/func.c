#include "ast.h"

stmt_ty func_w_name(ast_data_t *data, PyObject *name, arguments_ty args){
    stmt_ty stmt = _PyAST_FunctionDef(
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
    stmt->v.FunctionDef.body->typed_elements[0] = _PyAST_Pass(LINE, data->arena); // placeholder
    data->func_cnt++;
    return stmt;
}

stmt_ty get_func_internal(int *index, asdl_stmt_seq *stmt_seq){
    for (int i = 0; i < stmt_seq->size; i++)
    {
        stmt_ty stmt = stmt_seq->typed_elements[i];
        stmt_ty res;
        switch (stmt->kind)
        {
        case FunctionDef_kind:
            if(*index == 0){
                return stmt;
            }
            (*index)--;
            break;
        case ClassDef_kind:
            res = get_func_internal(index, stmt->v.ClassDef.body);
            if(res != NULL){
                return res;
            }
            break;
        case While_kind:
            res = get_func_internal(index, stmt->v.While.body);
            if(res != NULL){
                return res;
            }
            break;
        case If_kind:
            res = get_func_internal(index, stmt->v.If.body);
            if(res != NULL){
                return res;
            }
            break;
        case For_kind:
            res = get_func_internal(index, stmt->v.For.body);
            if(res != NULL){
                return res;
            }
            break;
        case With_kind:
            res = get_func_internal(index, stmt->v.With.body);
            if(res != NULL){
                return res;
            }
            break;
        default:
            break;
        }
    }
    return NULL;
}

stmt_ty get_func(ast_data_t *data, int index){
    int idx = index;
    stmt_ty re = get_func_internal(&idx, data->mod->v.Module.body);
    if(re == NULL){
        PANIC("get_func: index out of range %d/%d\n", idx, index);
    }
    return re;
}
