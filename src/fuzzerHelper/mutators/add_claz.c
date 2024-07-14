#include "mutators.h"
#include "deepcopy.h"

int add_clz_and_init(ast_data_t *data)
{
    data->mod->v.Module.body = asdl_stmt_seq_copy_add(data->mod->v.Module.body, data->arena, 2);
    asdl_stmt_seq *body = data->mod->v.Module.body;
    int id = plain_clz(data, &(body->typed_elements[body->size - 2]));
    body->typed_elements[body->size - 1] = stmt(
        _PyAST_Call(
            _PyAST_Name(gen_name_id(id), Load, LINE, data->arena),
            NULL,
            NULL,
            LINE,
            data->arena),
        data->arena);
    return 0;
}

int make_clz_inherit(ast_data_t *data, stmt_ty clz, PyObject *base)
{
    assert(clz && clz->kind == ClassDef_kind);
    if(clz->v.ClassDef.bases != NULL && clz->v.ClassDef.bases->size > 0){
        // TODO there maybe conflict between multiple base classes
        fprintf(stderr, "don't support inherit multiple classes\n");
        return -1;
    }
    clz->v.ClassDef.bases = asdl_expr_seq_copy_add(clz->v.ClassDef.bases, data->arena, 1);
    clz->v.ClassDef.bases->typed_elements[clz->v.ClassDef.bases->size - 1] = _PyAST_Name(base, Load, LINE, data->arena);
    data->inherited_clz_cnt++;
    data->plain_clz_cnt--;
    return 0;
}