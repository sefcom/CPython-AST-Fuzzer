#include "mutators.h"

int add_rand_override(ast_data_t *data, stmt_ty clz, overridable_func func)
{
    assert(clz != NULL);
    if (clz->v.ClassDef.body != NULL && clz->v.ClassDef.body->size > 0)
    {
        for (int i = 0; i < clz->v.ClassDef.body->size; i++)
        {
            if (clz->v.ClassDef.body->typed_elements[i]->kind == FunctionDef_kind && clz->v.ClassDef.body->typed_elements[i]->v.FunctionDef.name == func.name)
            {
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
    for (int i = 0; i < func.args_size; i++)
    {
        if (i == 0 && (func.arg_type & HAS_SELF))
        {
            args->args->typed_elements[i] = _PyAST_arg(SELF_OBJ, NULL, NULL, LINE, data->arena);
            continue;
        }
        args->args->typed_elements[i] = _PyAST_arg(gen_name_id((data->gen_name_cnt)++), NULL, NULL, LINE, data->arena);
    }
    if (func.arg_type & HAS_KWARGS)
    {
        args->kwarg = _PyAST_arg(KWARGS_OBJ, NULL, NULL, LINE, data->arena);
    }
    if (func.arg_type & HAS_VARARGS)
    {
        args->vararg = _PyAST_arg(VARARGS_OBJ, NULL, NULL, LINE, data->arena);
    }
    clz->v.ClassDef.body->typed_elements[clz->v.ClassDef.body->size - 1] = func_w_name(data, func.name, args);
    return STATE_OK;
}

int feed_func_locals(ast_data_t *data, stmt_ty func, stmt_ty base_clz)
{
    int has_self = 0;
    int required_locals = func->v.FunctionDef.args->args->size;
    if (required_locals > 0 && PyUnicode_Compare(func->v.FunctionDef.args->args->typed_elements[0]->arg, SELF_OBJ) == 0)
    {
        required_locals--;
        has_self = 1;
    }
    if (data->locals_cnt < required_locals)
    {
        INFO("not enough locals to feed function\n");
        return STATE_REROLL;
    }
    expr_ty f;
    if (base_clz == NULL)
    {
        f = NAME_L(func->v.FunctionDef.name);
    }
    else
    {
        if (has_self == 0)
        {
            // maybe static method
            f = _PyAST_Attribute(NAME_L(base_clz->v.ClassDef.name), func->v.FunctionDef.name, Load, LINE, data->arena);
        }
        else
        {
            PyObject *instance_name = NULL;
            asdl_stmt_seq *body = data->mod->v.Module.body;
            for (int i = 0; i < body->size; i++)
            {
                stmt_ty ele = body->typed_elements[i];
                if (ele->kind == ClassDef_kind && ele == base_clz)
                {
                    assert(i + 1 < body->size);
                    assert(body->typed_elements[i + 1]->kind == Assign_kind);
                    assert(body->typed_elements[i + 1]->v.Assign.targets->size == 1);
                    assert(body->typed_elements[i + 1]->v.Assign.targets->typed_elements[0]->kind == Name_kind);
                    assert(body->typed_elements[i + 1]->v.Assign.targets->typed_elements[0]->v.Name.id != NULL);
                    // trial fast path
                    instance_name = body->typed_elements[i + 1]->v.Assign.targets->typed_elements[0]->v.Name.id;
                    break;
                }
            }
            assert(instance_name != NULL);
            f = _PyAST_Attribute(NAME_L(instance_name), func->v.FunctionDef.name, Load, LINE, data->arena);
        }
    }
    expr_ty call = _PyAST_Call(
        f,
        _Py_asdl_expr_seq_new(required_locals, data->arena),
        NULL,
        LINE,
        data->arena);
    int *locals = (int *)malloc(sizeof(int) * required_locals);
    for (int i = 0; i < required_locals; i++)
    {
    PICK_LOCAL:
        int picked_local = rand() % data->locals_cnt;
        if (i != 0)
        {
            for (int j = 0; j < i; j++)
            {
                if (locals[j] == picked_local)
                {
                    goto PICK_LOCAL;
                }
            }
        }
        locals[i] = picked_local;
        call->v.Call.args->typed_elements[i] = NAME_L(get_locals(data, picked_local));
    }
    data->mod->v.Module.body = asdl_stmt_seq_copy_add(data->mod->v.Module.body, data->arena, 1);
    stmt_ty ass = _PyAST_Assign(
        _Py_asdl_expr_seq_new(1, data->arena),
        call,
        NULL,
        LINE,
        data->arena);
    ass->v.Assign.targets->typed_elements[0] = NAME_S(gen_name_id(data->gen_name_cnt++));
    data->mod->v.Module.body->typed_elements[data->mod->v.Module.body->size - 1] = ass;
    return STATE_OK;
}

int func_variable_lifetime(ast_data_t *data, stmt_ty func)
{
    int local_cnt = 0;
    for (int i = 0; i < func->v.FunctionDef.body->size; i++)
    {
        stmt_ty ele = func->v.FunctionDef.body->typed_elements[i];
        if (ele->kind == Assign_kind && ele->v.Assign.targets->size > 0 && ele->v.Assign.targets->typed_elements[0]->kind == Name_kind)
        {
            local_cnt++;
        }
    }
    if (local_cnt == 0)
    {
        return STATE_REROLL;
    }
    int picked_local_id = rand() % local_cnt;
    PyObject *name = NULL;
    for (int i = 0; i < func->v.FunctionDef.body->size; i++)
    {
        stmt_ty ele = func->v.FunctionDef.body->typed_elements[i];
        if (ele->kind == Assign_kind && ele->v.Assign.targets->size > 0 && ele->v.Assign.targets->typed_elements[0]->kind == Name_kind)
        {
            if (picked_local_id == 0)
            {
                name = ele->v.Assign.targets->typed_elements[0]->v.Name.id;
                break;
            }
            picked_local_id--;
        }
    }
    assert(Global_kind + 1 == Nonlocal_kind);
    int picked_kind = rand() % 2 + Global_kind;
    // structure of global and nonlocal is the same
    if(func->v.FunctionDef.body->typed_elements[0]->kind == picked_kind){
        stmt_ty old = func->v.FunctionDef.body->typed_elements[0];
        old->v.Global.names = asdl_identifier_seq_copy_add(old->v.Global.names, data->arena, 1);
        old->v.Global.names->typed_elements[old->v.Global.names->size - 1] = name;
    }else{
        stmt_ty re = _PyAST_Global(_Py_asdl_identifier_seq_new(1, data->arena), LINE, data->arena);
        re->kind = picked_kind;
        re->v.Global.names->typed_elements[0] = name;
        func->v.FunctionDef.body = asdl_stmt_seq_copy_add_front(func->v.FunctionDef.body, data->arena, 1);
        func->v.FunctionDef.body->typed_elements[0] = re;
    }
    return STATE_OK;
}