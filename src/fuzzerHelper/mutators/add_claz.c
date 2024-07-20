#include "mutators.h"

int add_clz_and_init(ast_data_t *data)
{
    data->mod->v.Module.body = asdl_stmt_seq_copy_add(data->mod->v.Module.body, data->arena, 2);
    asdl_stmt_seq *body = data->mod->v.Module.body;
    int id = (data->gen_name_cnt)++;
    body->typed_elements[body->size - 2] = plain_clz(data, gen_name_id(id));
    body->typed_elements[body->size - 1] = _PyAST_Assign(
        _Py_asdl_expr_seq_new(1, data->arena),
        _PyAST_Call(
            NAME_L(gen_name_id(id)),
            NULL,
            NULL,
            LINE,
            data->arena),
        NULL,
        LINE,
        data->arena);
    body->typed_elements[body->size - 1]->v.Assign.targets->typed_elements[0] = NAME_S(gen_name_id((data->gen_name_cnt)++));
    data->locals_cnt++;
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
    clz->v.ClassDef.bases->typed_elements[clz->v.ClassDef.bases->size - 1] = NAME_L(base);
    data->inherited_clz_cnt++;
    data->plain_clz_cnt--;
    return STATE_OK;
}

int init_builtin_instance(ast_data_t *data, PyObject *type, asdl_stmt_seq **body_raw)
{
    *body_raw = asdl_stmt_seq_copy_add(*body_raw, data->arena, 1);
    asdl_stmt_seq *body = *body_raw;
    body->typed_elements[body->size - 1] = _PyAST_Assign(
        _Py_asdl_expr_seq_new(1, data->arena),
        _PyAST_Call(
            NAME_L(type),
            NULL,
            NULL,
            LINE,
            data->arena),
        NULL,
        LINE,
        data->arena);
    body->typed_elements[body->size - 1]->v.Assign.targets->typed_elements[0] = NAME_S(gen_name_id((data->gen_name_cnt)++));
    data->locals_cnt++;
    return STATE_OK;
}