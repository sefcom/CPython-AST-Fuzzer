#ifndef FUZZER_H
#define FUZZER_H

#include "defs.h"
#include "common.h"
#include "log.h"

typedef enum
{
    HAS_VARARGS = 0b1,
    HAS_KWARGS = 0b10,
    HAS_SELF = 0b100,
} overridable_func_flags;

typedef struct
{
    const char *key;
    PyObject *name;
    int args_size;
    overridable_func_flags arg_type;
    UT_hash_handle hh;
} overridable_func;

// --- Arena helpers ---

PyObject *PyUnicode_FromString_Arena(const char *s, PyArena *arena);
PyObject *PyUnicode_Copy_Arena(PyObject *s, PyArena *arena);
PyObject *PyLong_FromLong_Arena(long n, PyArena *arena);
PyObject *PyLong_Copy_Arena(PyObject *s, PyArena *arena);

// --- name helpers ---

void gen_name_init();
PyObject *gen_name_id(int id);
void override_name_init();
overridable_func rand_override_func(int base_clz_id);
overridable_func *override_func(const char *name);

// --- AST helpers ---

stmt_ty stmt(expr_ty expr, PyArena *arena);
PyObject *get_locals(ast_data_t *data, int index);

// -- class helpers --
stmt_ty plain_clz(ast_data_t *data, PyObject *name);
stmt_ty clz_inherited(ast_data_t *data, const char *base, PyObject *name);
stmt_ty find_clz(asdl_stmt_seq *stmt_seq, PyObject *clz_name);

// -- function helpers --
stmt_ty func_w_name(ast_data_t *data, PyObject *name, arguments_ty args);
stmt_ty get_func(ast_data_t *data, int index);

// --- mutator helpers ---

int get_clz_count(asdl_stmt_seq *stmt_seq, int *plain_clz);
stmt_ty get_clz(asdl_stmt_seq *stmt_seq, int index, int plain_clz_required);

// --- constants ---

#define GEN_CONST(name) extern PyObject *name##_OBJ
GEN_CONST(KEYS);
GEN_CONST(LEN);
GEN_CONST(ISINSTANTANCE);
GEN_CONST(SELF);
GEN_CONST(KWARGS);
GEN_CONST(VARARGS);
#undef GEN_CONST
void init_constants();

// --- variable helpers ---

// -- dict --
// instanceof(in_var, dict) and +len(in_var.keys())
stmt_ty dict_non_empty_and_type_cond(ast_data_t *data, PyObject *in_var, stmt_ty body);
stmt_ty dict_del(ast_data_t *data, PyObject *in_var, PyObject *index);
stmt_ty dict_assign(ast_data_t *data, PyObject *in_var, expr_ty value, PyObject *index);

#endif