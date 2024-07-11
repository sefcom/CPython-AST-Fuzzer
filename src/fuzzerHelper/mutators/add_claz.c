#include "mutators.h"
#include "deepcopy.h"

void add_clz_and_init(ast_data_t *data)
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
}