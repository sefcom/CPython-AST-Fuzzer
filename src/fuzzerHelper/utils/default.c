#include "default.h"

#include "ast.h"

identifier default_identifier(ast_data_t *data) {
    return gen_name_id(data->gen_name_cnt++);
}

arguments_ty default_arguments_ty(ast_data_t *data) {
    return _PyAST_arguments(NULL, _Py_asdl_arg_seq_new(0, data->arena), NULL,
                            NULL, NULL, NULL, NULL, data->arena);
}

stmt_ty default_stmt_ty(ast_data_t *data) {
    return _PyAST_Pass(LINE, data->arena);
}

string default_string(ast_data_t *data) { return NULL; }

alias_ty default_alias(ast_data_t *data) {
    return _PyAST_alias(default_identifier(data), default_identifier(data),
                        LINE, data->arena);
}

expr_ty default_expr_ty(ast_data_t *data) { return _PyLong_GetZero(); }

int default_int(ast_data_t *data) { return 0; }

constant default_constant(ast_data_t *data) { return _PyLong_GetZero(); }

expr_context_ty default_expr_context_ty(ast_data_t *data) { return Load; }

operator_ty default_operator_ty(ast_data_t *data) { return Add; }

asdl_identifier_seq *default_asdl_identifier_seq_ptr(ast_data_t *data) {
    asdl_identifier_seq *tmp = _Py_asdl_identifier_seq_new(1, data->arena);
    tmp->typed_elements[0] = default_identifier(data);
    return tmp;
}

asdl_keyword_seq *default_asdl_keyword_seq_ptr(ast_data_t *data) {
    return _Py_asdl_keyword_seq_new(0, data->arena);
}

asdl_stmt_seq *default_asdl_stmt_seq_ptr(ast_data_t *data) {
    asdl_stmt_seq *tmp = _Py_asdl_stmt_seq_new(1, data->arena);
    tmp->typed_elements[0] = default_stmt_ty(data->arena);
    return tmp;
}

asdl_expr_seq *default_asdl_expr_seq_ptr(ast_data_t *data) {
    asdl_expr_seq *tmp = _Py_asdl_expr_seq_new(1, data->arena);
    tmp->typed_elements[0] = default_expr_ty(data);
    return tmp;
}

asdl_type_param_seq *default_asdl_type_param_seq_ptr(ast_data_t *data) {
    return _Py_asdl_type_param_seq_new(0, data->arena);
}

asdl_withitem_seq *default_asdl_withitem_seq_ptr(ast_data_t *data) {
    asdl_withitem_seq *tmp = _Py_asdl_withitem_seq_new(1, data->arena);
    tmp->typed_elements[0] = _PyAST_Pass(LINE, data->arena);
    return tmp;
}

asdl_match_case_seq *default_asdl_match_case_seq_ptr(ast_data_t *data) {
    asdl_match_case_seq *tmp = _Py_asdl_match_case_seq_new(1, data->arena);
    tmp->typed_elements[0] = _PyAST_Pass(LINE, data->arena);
    return tmp;
}

asdl_excepthandler_seq *default_asdl_excepthandler_seq_ptr(ast_data_t *data) {
    asdl_excepthandler_seq *tmp =
        _Py_asdl_excepthandler_seq_new(1, data->arena);
    tmp->typed_elements[0] = _PyAST_Pass(LINE, data->arena);
    return tmp;
}

asdl_alias_seq *default_asdl_alias_seq_ptr(ast_data_t *data) {
    asdl_alias_seq *tmp = _Py_asdl_alias_seq_new(1, data->arena);
    tmp->typed_elements[0] = default_alias(data);
    return tmp;
}

unaryop_ty default_unaryop(ast_data_t *data) { return Invert; }
