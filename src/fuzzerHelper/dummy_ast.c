#include "helper.h"

mod_ty init_dummy_ast(PyArena *arena)
{
    // dummy AST
    // print("Hellow world")
    expr_ty call_name = _PyAST_Name(PyUnicode_FromString_Arena("print", arena), Load, LINE, arena);
    asdl_expr_seq *call_args = _Py_asdl_expr_seq_new(1, arena);
    call_args->typed_elements[0] = _PyAST_Constant(PyUnicode_FromString_Arena("Hello world", arena), NULL, LINE, arena);
    asdl_keyword_seq *call_keywords = _Py_asdl_keyword_seq_new(0, arena);
    stmt_ty call = _PyAST_Expr(
        _PyAST_Call(call_name, call_args, call_keywords, LINE, arena),
        LINE, arena);
    asdl_stmt_seq *body = _Py_asdl_stmt_seq_new(1, arena);
    body->elements[0] = call;
    asdl_type_ignore_seq *ignored = _Py_asdl_type_ignore_seq_new(0, arena);

    mod_ty mod = _PyAST_Module(body, ignored, arena);
    int val = _PyAST_Validate(mod);
    if (PyErr_Occurred())
    {
        PyErr_Print();
    }
    assert(val != 0);
    return mod;
}

mod_ty init_UAF2(PyArena *arena)
{
    // motivation sample 2
    // Module(body=[ClassDef(name='A', bases=[], keywords=[], body=[FunctionDef(name='__eq__', args=arguments(posonlyargs=[], args=[arg(arg='self', annotation=Name(id='A', ctx=Load())), arg(arg='other', annotation=Name(id='dict', ctx=Load()))], kwonlyargs=[], kw_defaults=[], defaults=[]), body=[Assign(targets=[Subscript(value=Name(id='other', ctx=Load()), slice=Constant(value='items'), ctx=Store())], value=Constant(value=0))], decorator_list=[])], decorator_list=[]), Expr(value=Compare(left=Attribute(value=Name(id='dict', ctx=Load()), attr='__dict__', ctx=Load()), ops=[Eq()], comparators=[Call(func=Name(id='A', ctx=Load()), args=[], keywords=[])]))], type_ignores=[])
    arguments_ty args = _PyAST_arguments(
        _Py_asdl_arg_seq_new(0, arena),
        _Py_asdl_arg_seq_new(2, arena),
        NULL,
        _Py_asdl_arg_seq_new(0, arena),
        _Py_asdl_expr_seq_new(0, arena),
        NULL,
        _Py_asdl_expr_seq_new(0, arena),
        arena);
    // optional type hints
    expr_ty dict_type = _PyAST_Name(PyUnicode_FromString_Arena("dict", arena), Load, LINE, arena);

    args->args->typed_elements[0] = _PyAST_arg(PyUnicode_FromString_Arena("self", arena), NULL, NULL, LINE, arena);
    args->args->typed_elements[1] = _PyAST_arg(PyUnicode_FromString_Arena("other", arena), dict_type, NULL, LINE, arena);

    stmt_ty malicious_assign = _PyAST_Assign(
        _Py_asdl_expr_seq_new(1, arena),
        _PyAST_Constant(PyLong_FromLong_Arena(0, arena), NULL, LINE, arena),
        NULL,
        LINE,
        arena);
    malicious_assign->v.Assign.targets->typed_elements[0] = _PyAST_Subscript(
        _PyAST_Name(PyUnicode_FromString_Arena("other", arena), Load, LINE, arena),
        _PyAST_Constant(PyUnicode_FromString_Arena("items", arena), NULL, LINE, arena),
        Store,
        LINE,
        arena);

    stmt_ty malicious_eq_func;
    assert(override_func("__eq__") != NULL);
    func_w_name(arena, override_func("__eq__")->name, &malicious_eq_func, args);
    malicious_eq_func->v.FunctionDef.body = _Py_asdl_stmt_seq_new(1, arena);
    malicious_eq_func->v.FunctionDef.body->elements[0] = malicious_assign;

    stmt_ty class_def;
    int clz_name = plain_clz(arena, &class_def);
    class_def->v.ClassDef.body = _Py_asdl_stmt_seq_new(1, arena);
    class_def->v.ClassDef.body->elements[0] = malicious_eq_func;

    expr_ty target_call = _PyAST_Compare(
        _PyAST_Attribute(
            _PyAST_Name(PyUnicode_FromString_Arena("dict", arena), Load, LINE, arena),
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
        _PyAST_Name(gen_name_id(clz_name), Load, LINE, arena),
        _Py_asdl_expr_seq_new(0, arena),
        _Py_asdl_keyword_seq_new(0, arena),
        LINE,
        arena);
    stmt_ty target_call_wrapper = _PyAST_Expr(target_call, LINE, arena);

    expr_ty dict_obj = _PyAST_Call(
        _PyAST_Name(PyUnicode_FromString_Arena("dict", arena), Load, LINE, arena),
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

    int val = _PyAST_Validate(mod);
    if (PyErr_Occurred())
    {
        PyErr_Print();
    }
    assert(val != 0);
    return mod;
}
