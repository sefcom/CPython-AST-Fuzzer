#ifndef FUZZER_H
#define FUZZER_H

#define Py_BUILD_CORE 1
#include "Python.h"
#include "pycore_ast.h"

typedef struct{
    void *ast_buf;
    size_t ast_buf_size;
    size_t ast_buf_used;
} ast_data_t;

int ensure_add(size_t, ast_data_t *);
mod_ty new_mod(ast_data_t *data);
asdl_stmt_seq *new_body(ast_data_t *data, size_t n_ele);
asdl_type_ignore_seq *empty_type_ignore_seq(ast_data_t *data, size_t n_ele);
stmt_ty new_stmt(ast_data_t *data);
expr_ty new_expr(ast_data_t *data);
expr_ty new_func(ast_data_t *data, const char *name);
asdl_expr_seq *new_args(ast_data_t *data, size_t n_ele);
asdl_keyword_seq *new_keywords(ast_data_t *data, size_t n_ele);
void add_python_obj_int(ast_data_t *data, size_t offset, size_t number);
void add_python_obj_str(ast_data_t *data, size_t offset, const char *str);

#endif