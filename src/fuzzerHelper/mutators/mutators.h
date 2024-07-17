#ifndef MUTATORS_H
#define MUTATORS_H

#include "../utils/ast.h"

typedef enum STATE_FLAG{
    STATE_OK = 0,
    STATE_COPY_REROLL = -1,
    STATE_REROLL = -2,
} STATE_FLAG;

int entry_mutate(ast_data_t **data, size_t max_size, size_t seed);

// --- mutators ---

// -- class --
int add_clz_and_init(ast_data_t *data);
int make_clz_inherit(ast_data_t *data, stmt_ty clz, PyObject *base);
int init_builtin_instance(ast_data_t *data, PyObject *type, asdl_stmt_seq **body_raw);

// -- function --
int add_rand_override(ast_data_t *data, stmt_ty clz, overridable_func func);
int feed_func_locals(ast_data_t *data, stmt_ty func, stmt_ty base_clz);

// -- variables --
int mutate_dict_entry(ast_data_t *data, stmt_ty picked_func);
int operate_locals_global(ast_data_t *data);

#endif // MUTATORS_H