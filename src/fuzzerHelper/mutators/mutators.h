#ifndef MUTATORS_H
#define MUTATORS_H

#include "../utils/ast.h"

int entry_mutate(ast_data_t **data, size_t max_size, size_t seed);

// --- mutators ---

// -- class --
int add_clz_and_init(ast_data_t *data);
int make_clz_inherit(ast_data_t *data, stmt_ty clz, PyObject *base);

// -- function --
int add_rand_override(ast_data_t *data, stmt_ty clz, overridable_func func);

#endif // MUTATORS_H