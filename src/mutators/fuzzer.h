#ifndef FUZZER_H
#define FUZZER_H

#include "afl-fuzz.h"

#define Py_BUILD_CORE 1
#include "Python.h"
#include "pycore_ast.h"

typedef struct{
    size_t free_list_size;
    size_t base_addr;
} meta_data_t;

typedef struct{
    void *ast_buf;
    size_t ast_buf_size;
    size_t ast_buf_used;
    size_t ast_freelist_size;
} ast_data_t;

typedef struct my_mutator
{
    afl_state_t *afl;

    ast_data_t dummy_ast;
    ast_data_t ast_buf;
} my_mutator_t;

typedef enum{
    STRING,
    NUMBER
} python_obj_kind_t;

typedef struct{
    python_obj_kind_t kind;
    size_t offset;
    union{
        size_t number;
        const char *string;
    }val;
} python_obj_t;

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