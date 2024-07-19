#include "helper.h"
#include "override_func.h"

static mod_ty dummy_ast;

mod_ty init_dummy_ast(ast_data_t *data)
{
    if(dummy_ast != NULL){
        return dummy_ast;
    }
    if(last_case != NULL){
        INFO("use last-case instead of dummy ast\n");
        char *read_buf = malloc(AST_DUMP_BUF_SIZE);
        if(read_buf == NULL){
            PANIC("Failed to allocate read_buf\n");
        }
        // find file size
        fseek(last_case, 0, SEEK_END);
        size_t read_size = ftell(last_case);
        rewind(last_case);
        if(read_size <= 0 || read_size >= AST_DUMP_BUF_SIZE - 1){
            PANIC("Failed to seek last case\n");
        }
        size_t size = fread(read_buf, 1, read_size, last_case);
        if(size < 1){
            PANIC("Failed to read last case\n");
        }
        INFO("read %zu bytes from last case\n", size);
        read_buf[size] = '\0';
        fclose(last_case);
        dummy_ast = load_ast(data, read_buf);
        free(read_buf);
    }else{
        PyArena *arena = data->arena;
        // dummy AST
        asdl_stmt_seq *body = _Py_asdl_stmt_seq_new(1, arena);
        body->elements[0] = _PyAST_Pass(LINE, arena);

        dummy_ast = _PyAST_Module(body, NULL, arena);
    }
    assert(!(dummy_ast == NULL || !_PyAST_Validate(dummy_ast)));
    return dummy_ast;
}

mod_ty init_UAF2(ast_data_t *data)
{
    PyArena *arena = data->arena;
    // motivation sample 2
    // Module(body=[ClassDef(name='A', bases=[], keywords=[], body=[FunctionDef(name='__eq__', args=arguments(posonlyargs=[], args=[arg(arg='self', annotation=Name(id='A', ctx=Load())), arg(arg='other', annotation=Name(id='dict', ctx=Load()))], kwonlyargs=[], kw_defaults=[], defaults=[]), body=[Assign(targets=[Subscript(value=Name(id='other', ctx=Load()), slice=Constant(value='items'), ctx=Store())], value=Constant(value=0))], decorator_list=[])], decorator_list=[]), Expr(value=Compare(left=Attribute(value=Name(id='dict', ctx=Load()), attr='__dict__', ctx=Load()), ops=[Eq()], comparators=[Call(func=Name(id='A', ctx=Load()), args=[], keywords=[])]))], type_ignores=[])
    arguments_ty args = _PyAST_arguments(
       NULL,
        _Py_asdl_arg_seq_new(2, arena),
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        arena);
    // optional type hints
    expr_ty dict_type = NAME_L(PyUnicode_FromString_Arena("dict", arena));

    args->args->typed_elements[0] = _PyAST_arg(PyUnicode_FromString_Arena("self", arena), NULL, NULL, LINE, arena);
    args->args->typed_elements[1] = _PyAST_arg(PyUnicode_FromString_Arena("other", arena), dict_type, NULL, LINE, arena);

    stmt_ty malicious_assign = _PyAST_Assign(
        _Py_asdl_expr_seq_new(1, arena),
        CONST(PyLong_FromLong_Arena(0, arena)),
        NULL,
        LINE,
        arena);
    malicious_assign->v.Assign.targets->typed_elements[0] = _PyAST_Subscript(
        NAME_L(PyUnicode_FromString_Arena("other", arena)),
        CONST(PyUnicode_FromString_Arena("items", arena)),
        Store,
        LINE,
        arena);

    stmt_ty malicious_eq_func;
    assert(override_func("__eq__") != NULL);
    malicious_eq_func = func_w_name(data, override_func("__eq__")->name, args);
    malicious_eq_func->v.FunctionDef.body = _Py_asdl_stmt_seq_new(1, arena);
    malicious_eq_func->v.FunctionDef.body->elements[0] = malicious_assign;

    stmt_ty class_def;
    int clz_name = (data->gen_name_cnt)++;
    class_def = plain_clz(data, gen_name_id(clz_name));
    class_def->v.ClassDef.body = _Py_asdl_stmt_seq_new(1, arena);
    class_def->v.ClassDef.body->elements[0] = malicious_eq_func;

    expr_ty target_call = _PyAST_Compare(
        _PyAST_Attribute(
            NAME_L(PyUnicode_FromString_Arena("dict", arena)),
            PyUnicode_FromString_Arena("__dict__", arena),
            Load,
            LINE,
            arena),
        _Py_asdl_int_seq_new(1, arena),
        _Py_asdl_expr_seq_new(1, arena),
        LINE,
        arena);
    target_call->v.Compare.ops->typed_elements[0] = Eq;
    target_call->v.Compare.comparators->typed_elements[0] = _PyAST_Call(
        NAME_L(gen_name_id(clz_name)),
        _Py_asdl_expr_seq_new(0, arena),
        _Py_asdl_keyword_seq_new(0, arena),
        LINE,
        arena);
    stmt_ty target_call_wrapper = _PyAST_Expr(target_call, LINE, arena);

    expr_ty dict_obj = _PyAST_Call(
        NAME_L(PyUnicode_FromString_Arena("dict", arena)),
        _Py_asdl_expr_seq_new(0, arena),
        _Py_asdl_keyword_seq_new(0, arena),
        LINE,
        arena);
    expr_ty call_items = _PyAST_Call(
        _PyAST_Attribute(dict_obj, PyUnicode_FromString_Arena("items", arena), Load, LINE, arena),
        _Py_asdl_expr_seq_new(0, arena),
        _Py_asdl_keyword_seq_new(0, arena),
        LINE,
        arena);
    stmt_ty call_items_wrapper = _PyAST_Expr(call_items, LINE, arena);

    mod_ty mod = _PyAST_Module(
        _Py_asdl_stmt_seq_new(3, arena),
        _Py_asdl_type_ignore_seq_new(0, arena),
        arena);
    
    mod->v.Module.body->elements[0] = class_def;
    mod->v.Module.body->elements[1] = target_call_wrapper;
    mod->v.Module.body->elements[2] = call_items_wrapper;

    assert(!(mod == NULL || !_PyAST_Validate(mod)));
    return mod;
}
