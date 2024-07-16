#include "mutators.h"
#include "deepcopy.h"

int operate_locals_global(ast_data_t *data){
    int picked_local_id = rand() % data->locals_cnt;
    int picked_local_id2 = rand() % (data->locals_cnt - 1);
    if(picked_local_id2 >= picked_local_id){
        picked_local_id2++;
    }
    expr_ty picked_local = _PyAST_Name(get_locals(data, picked_local_id), Load, LINE, data->arena);
    expr_ty picked_local2 = _PyAST_Name(get_locals(data, picked_local_id2), Load, LINE, data->arena);

    int picked_op = rand() % (FloorDiv + USub + NotIn - 1) + 1;
    INFO("blend locals %d %d %d\n", picked_local_id, picked_local_id2, picked_op);
    expr_ty re;
    if(picked_op <= FloorDiv){
        re = _PyAST_BinOp(picked_local, picked_op, picked_local2, LINE, data->arena);
    }else if(picked_op <= USub + FloorDiv){
        re = _PyAST_UnaryOp(picked_op - FloorDiv, picked_local, LINE, data->arena);
    }else{
        re = _PyAST_Compare(picked_local, _Py_asdl_int_seq_new(1, data->arena), _Py_asdl_expr_seq_new(1, data->arena), LINE, data->arena);
        re->v.Compare.ops->typed_elements[0] = picked_op - USub - FloorDiv;
        re->v.Compare.comparators->typed_elements[0] = picked_local2;
    }
    data->mod->v.Module.body = asdl_stmt_seq_copy_add(data->mod->v.Module.body, data->arena, 1);
    asdl_stmt_seq *body = data->mod->v.Module.body;
    body->typed_elements[body->size - 1] = _PyAST_Assign(_Py_asdl_expr_seq_new(1, data->arena), re, NULL, LINE, data->arena);
    body->typed_elements[body->size - 1]->v.Assign.targets->typed_elements[0] = _PyAST_Name(gen_name_id((data->gen_name_cnt)++), Store, LINE, data->arena);
    data->locals_cnt++;
    return STATE_OK;
}
