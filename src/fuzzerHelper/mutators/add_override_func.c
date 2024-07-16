#include "mutators.h"
#include "deepcopy.h"

int add_rand_override(ast_data_t *data, stmt_ty clz, overridable_func func)
{
    assert(clz != NULL);
    if(clz->v.ClassDef.body != NULL && clz->v.ClassDef.body->size > 0){
        for(int i = 0; i < clz->v.ClassDef.body->size; i++){
            if(clz->v.ClassDef.body->typed_elements[i]->kind == FunctionDef_kind && clz->v.ClassDef.body->typed_elements[i]->v.FunctionDef.name == func.name){
                INFO("function %s already exists in class\n", func.name);
                return STATE_REROLL; // re-roll w/o copy
            }
        }
    }
    clz->v.ClassDef.body = asdl_stmt_seq_copy_add(clz->v.ClassDef.body, data->arena, 1);
    INFO("inherit func %s\n", func.key);
    arguments_ty args = _PyAST_arguments(
        NULL,
        _Py_asdl_arg_seq_new(func.args_size, data->arena),
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        data->arena);
    assert(args != NULL);
    for(int i = 0; i < func.args_size; i++){
        if(i == 0 && (func.arg_type & HAS_SELF)){
            args->args->typed_elements[i] = _PyAST_arg(SELF_OBJ, NULL, NULL, LINE, data->arena);
            continue;
        }
        args->args->typed_elements[i] = _PyAST_arg(gen_name_id((data->gen_name_cnt)++), NULL, NULL, LINE, data->arena);
    }
    if(func.arg_type & HAS_KWARGS){
        args->kwarg = _PyAST_arg(KWARGS_OBJ, NULL, NULL, LINE, data->arena);
    }
    if(func.arg_type & HAS_VARARGS){
        args->vararg = _PyAST_arg(VARARGS_OBJ, NULL, NULL, LINE, data->arena);
    }
    clz->v.ClassDef.body->typed_elements[clz->v.ClassDef.body->size - 1] = func_w_name(data, func.name, args);
    return STATE_OK;
}