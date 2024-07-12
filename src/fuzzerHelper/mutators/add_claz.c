#include "mutators.h"
#include "deepcopy.h"

int add_clz_and_init(ast_data_t *data)
{
    data->mod->v.Module.body = asdl_stmt_seq_copy_add(data->mod->v.Module.body, data->arena, 2);
    int id = plain_clz(data->arena, &data->mod->v.Module.body->typed_elements[data->mod->v.Module.body->size - 2]);
    data->mod->v.Module.body->typed_elements[data->mod->v.Module.body->size - 1] = stmt(
        _PyAST_Call(
            _PyAST_Name(gen_name_id(id), Load, LINE, data->arena),
            _Py_asdl_expr_seq_new(0, data->arena),
            _Py_asdl_keyword_seq_new(0, data->arena),
            LINE,
            data->arena),
        data->arena);
    return 0;
}

int make_clz_inherit(ast_data_t *data, PyObject *clz_name, const char *base)
{
    stmt_ty clz = find_clz(data->mod->v.Module.body, clz_name);
    assert(clz != NULL);
    if(clz->v.ClassDef.bases != NULL){
        // TODO there maybe conflict between multiple base classes
        fprintf(stderr, "don't support inherit multiple classes\n");
        return -1;
    }
    clz->v.ClassDef.bases = _Py_asdl_expr_seq_new(1, data->arena);
    clz->v.ClassDef.bases->typed_elements[clz->v.ClassDef.bases->size - 1] = _PyAST_Name(PyUnicode_FromString_Arena(base, data->arena), Load, LINE, data->arena);
    return 0;
}