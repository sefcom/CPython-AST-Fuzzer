#include "helper.h"

mod_ty init_dummy_ast(PyArena *arena)
{
    // dummy AST
    // print("Hellow world")
    expr_ty call_name = _PyAST_Name(PyUnicode_FromString_Arena("print", arena), Load, 0, 0, 0, 0, arena);
    asdl_expr_seq *call_args = _Py_asdl_expr_seq_new(1, arena);
    call_args->typed_elements[0] = _PyAST_Constant(PyUnicode_FromString_Arena("Hello world", arena), NULL, 0, 0, 0, 0, arena);
    asdl_keyword_seq *call_keywords = _Py_asdl_keyword_seq_new(0, arena);
    stmt_ty call = _PyAST_Expr(
        _PyAST_Call(call_name, call_args, call_keywords, 0, 0, 0, 0, arena),
        0, 0, 0, 0, arena);
    asdl_stmt_seq *body = _Py_asdl_stmt_seq_new(1, arena);
    body->elements[0] = call;
    asdl_type_ignore_seq *ignored = _Py_asdl_type_ignore_seq_new(0, arena);
    
    mod_ty mod = _PyAST_Module(body, ignored, arena);
    int val = _PyAST_Validate(mod);
    if(PyErr_Occurred()){
        PyErr_Print();
    }
    assert(val != 0);
    return mod;
}
