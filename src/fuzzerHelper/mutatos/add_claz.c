#include "mutators.h"

int add_clz(ast_data_t *data){
    data->mod->v.Module.body = asdl_stmt_seq_copy(data->mod->v.Module.body, data->arena, 1);
}