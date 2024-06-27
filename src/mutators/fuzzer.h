#ifndef FUZZER_H
#define FUZZER_H

#include "afl-fuzz.h"

#define Py_BUILD_CORE 1
#include "Python.h"
#include "pycore_ast.h"

typedef struct my_mutator
{
    afl_state_t *afl;

    void *ast_buf;
    size_t ast_buf_size;
    size_t ast_buf_used;
} my_mutator_t;

int ensure_add(size_t, my_mutator_t *);
mod_ty new_mod(my_mutator_t *data);
asdl_stmt_seq *new_body(my_mutator_t *data, size_t n_ele);
stmt_ty new_stmt(my_mutator_t *data);
expr_ty new_expr(my_mutator_t *data);
expr_ty new_func(my_mutator_t *data, const char *name);
asdl_expr_seq *new_args(my_mutator_t *data, size_t n_ele);
asdl_keyword_seq *new_keywords(my_mutator_t *data, size_t n_ele);

#endif