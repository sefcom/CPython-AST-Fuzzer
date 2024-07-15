#include "mutators.h"
#include "deepcopy.h"

int add_clz_and_init(ast_data_t *data)
{
    data->mod->v.Module.body = asdl_stmt_seq_copy_add(data->mod->v.Module.body, data->arena, 2);
    asdl_stmt_seq *body = data->mod->v.Module.body;
    int id = plain_clz(data, &(body->typed_elements[body->size - 2]));
    body->typed_elements[body->size - 1] = _PyAST_Assign(
        _Py_asdl_expr_seq_new(1, data->arena),
        _PyAST_Call(
            _PyAST_Name(gen_name_id(id), Load, LINE, data->arena),
            NULL,
            NULL,
            LINE,
            data->arena),
        NULL,
        LINE,
        data->arena);
    body->typed_elements[body->size - 1]->v.Assign.targets->typed_elements[0] = _PyAST_Name(gen_name_id((data->gen_name_cnt)++), Store, LINE, data->arena);
    return STATE_OK;
}

int make_clz_inherit(ast_data_t *data, stmt_ty clz, PyObject *base)
{
    assert(clz && clz->kind == ClassDef_kind);
    if (clz->v.ClassDef.bases != NULL && clz->v.ClassDef.bases->size > 0)
    {
        // TODO there maybe conflict between multiple base classes
        ERROR("don't support inherit multiple classes\n");
        return STATE_REROLL;
    }
    clz->v.ClassDef.bases = asdl_expr_seq_copy_add(clz->v.ClassDef.bases, data->arena, 1);
    clz->v.ClassDef.bases->typed_elements[clz->v.ClassDef.bases->size - 1] = _PyAST_Name(base, Load, LINE, data->arena);
    data->inherited_clz_cnt++;
    data->plain_clz_cnt--;
    return STATE_OK;
}