#ifndef AST_DEFAULT_H
#define AST_DEFAULT_H

#include "common.h"

identifier default_identifier(ast_data_t *data);
arguments_ty default_arguments_ty(ast_data_t *data);
stmt_ty default_stmt_ty(ast_data_t *data);
string default_string(ast_data_t *data);
expr_ty default_expr_ty(ast_data_t *data);
int default_int(ast_data_t *data);
constant default_constant(ast_data_t *data);
expr_context_ty default_expr_context_ty(ast_data_t *data);
alias_ty default_alias(ast_data_t *data);
unaryop_ty default_unaryop(ast_data_t *data);
operator_ty default_operator_ty(ast_data_t *data);

asdl_identifier_seq *default_asdl_identifier_seq_ptr(ast_data_t *data);
asdl_keyword_seq *default_asdl_keyword_seq_ptr(ast_data_t *data);
asdl_stmt_seq *default_asdl_stmt_seq_ptr(ast_data_t *data);
asdl_expr_seq *default_asdl_expr_seq_ptr(ast_data_t *data);
asdl_type_param_seq *default_asdl_type_param_seq_ptr(ast_data_t *data);
asdl_withitem_seq *default_asdl_withitem_seq_ptr(ast_data_t *data);
asdl_match_case_seq *default_asdl_match_case_seq_ptr(ast_data_t *data);
asdl_excepthandler_seq *default_asdl_excepthandler_seq_ptr(ast_data_t *data);
asdl_alias_seq *default_asdl_alias_seq_ptr(ast_data_t *data);

#endif  // AST_DEFAULT_H