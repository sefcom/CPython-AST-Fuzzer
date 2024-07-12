#ifndef FUZZER_H
#define FUZZER_H

#include "defs.h"
#include "common.h"

typedef enum {
    HAS_VARARGS = 0b1,
    HAS_KWARGS = 0b10,
    HAS_SELF = 0b100,
}overridable_func_flags;

typedef struct
{
    const char *key;
    PyObject *name;
    int args_size;
    int arg_type; // 0: no, 0b1: has varargs, 0b10: has kwargs, 0b100 has self as one arg
    UT_hash_handle hh;
} overridable_func;

// --- Arena helper ---

PyObject *PyUnicode_FromString_Arena(const char *s, PyArena *arena);
PyObject *PyUnicode_Copy_Arena(PyObject *s, PyArena *arena);
PyObject *PyLong_FromLong_Arena(long n, PyArena *arena);
PyObject *PyLong_Copy_Arena(PyObject *s, PyArena *arena);

// --- name helpers ---

void gen_name_init();
PyObject *gen_name_id(int id);
void override_name_init();
overridable_func *rand_override_func(const char *builtin_tp_name);
overridable_func *override_func(const char *name);

// --- AST helpers ---

stmt_ty stmt(expr_ty expr, PyArena *arena);

// -- class helpers --
int plain_clz(ast_data_t *data, stmt_ty *stmt);
int clz_inherited(ast_data_t *data, const char *base, stmt_ty *stmt);
stmt_ty find_clz(asdl_stmt_seq *stmt_seq, PyObject *clz_name);

// -- function helpers --
int plain_func(ast_data_t *data, stmt_ty *expr, arguments_ty args);
void func_w_name(ast_data_t *data, PyObject *name, stmt_ty *expr, arguments_ty args);

// --- mutator helper ---

int get_clz_count(asdl_stmt_seq *stmt_seq, int *plain_clz);
stmt_ty get_clz(asdl_stmt_seq *stmt_seq, int index, int plain_clz_required);

// --- override func codgen ---
extern overridable_func *overridable_funcs;
extern overridable_func *overridable_funcs_raw; 
extern int builtin_clz_start[];
extern unsigned long builtin_clz_str[]; // hash list
extern const int builtin_type_cnt;
extern PyObject **builtin_clz_obj;

#endif