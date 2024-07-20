#include "mutators.h"

int blend_locals_global(ast_data_t *data){
    int picked_local_id = rand() % data->locals_cnt;
    int picked_local_id2 = rand() % (data->locals_cnt - 1);
    if(picked_local_id2 >= picked_local_id){
        picked_local_id2++;
    }
    expr_ty picked_local = NAME_L(get_locals(data, picked_local_id));
    expr_ty picked_local2 = NAME_L(get_locals(data, picked_local_id2));

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
    if(picked_op <= USub + FloorDiv){
        body->typed_elements[body->size - 1] = _PyAST_Assign(_Py_asdl_expr_seq_new(1, data->arena), re, NULL, LINE, data->arena);
        body->typed_elements[body->size - 1]->v.Assign.targets->typed_elements[0] = NAME_S(gen_name_id((data->gen_name_cnt)++));
        data->locals_cnt++;
    }else{
        // boolean is no need to assign
        body->typed_elements[body->size - 1] = _PyAST_Expr(re, LINE, data->arena);
    }
    return STATE_OK;
}
