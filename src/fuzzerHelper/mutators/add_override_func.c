#include "mutators.h"
#include "deepcopy.h"

int add_rand_override(ast_data_t *data, PyObject *clz_name, overridable_func func)
{
    stmt_ty clz = find_clz(data->mod->v.Module.body, clz_name);
    assert(clz != NULL);
    clz->v.ClassDef.body = asdl_stmt_seq_copy_add(clz->v.ClassDef.body, data->arena, 1);
    arguments_ty args = _PyAST_arguments(
        NULL,
        _Py_asdl_arg_seq_new(func.args_size, data->arena),
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        data->arena);
    for(int i = 0; i < func.args_size; i++){
        args->args->typed_elements[i] = _PyAST_arg(gen_name(0, NULL), NULL, NULL, LINE, data->arena);
    }
    if(func.arg_type & HAS_KWARGS){
        args->kwarg = _PyAST_arg(PyUnicode_FromString_Arena("kwargs", data->arena), NULL, NULL, LINE, data->arena);
    }
    if(func.arg_type & HAS_VARARGS){
        args->vararg = _PyAST_arg(PyUnicode_FromString_Arena("varargs", data->arena), NULL, NULL, LINE, data->arena);
    }
    func_w_name(data->arena, func.name, &clz->v.ClassDef.body->typed_elements[clz->v.ClassDef.body->size - 1], args);
    return 0;
}