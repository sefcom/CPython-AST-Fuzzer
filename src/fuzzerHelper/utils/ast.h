#ifndef FUZZER_H
#define FUZZER_H

#include "defs.h"
#include "common.h"

typedef struct
{
    uint32_t hash;
    PyObject *obj;
} simple_item_t;

// -- Arena helper --
PyObject *PyUnicode_FromString_Arena(const char *s, PyArena *arena);
PyObject *PyUnicode_Copy_Arena(PyObject *s, PyArena *arena);
PyObject *PyLong_FromLong_Arena(long n, PyArena *arena);

// -- name helpers --

void gen_name_init();
PyObject *gen_name(int clear, int *id);
PyObject *gen_name_id(int id);
void override_name_init();
PyObject *rand_override_name();
PyObject *override_name(const char *name);

// -- AST helpers --

stmt_ty stmt(expr_ty expr, PyArena *arena);
int plain_clz(PyArena *arena, stmt_ty *stmt);
int clz_inherited(PyArena *arena, const char *base, stmt_ty *stmt);
int plain_func(PyArena *arena, stmt_ty *expr, arguments_ty args);
void func_w_name(PyArena *arena, PyObject *name, stmt_ty *expr, arguments_ty args);

#define ASDL_SEQ_GETTER_HEADER(type) type *get_##type(int size, PyArena *arena);
ASDL_SEQ_GETTER_HEADER(asdl_arg_seq)
ASDL_SEQ_GETTER_HEADER(asdl_stmt_seq)
ASDL_SEQ_GETTER_HEADER(asdl_expr_seq)
ASDL_SEQ_GETTER_HEADER(asdl_keyword_seq)
ASDL_SEQ_GETTER_HEADER(asdl_int_seq)

// according to "_PyArena_Malloc()-obtained pointers remain valid until _PyArena_Free(ar) is called, at which point all pointers obtained"
#define ASDL_SEQ_COPY_HEADER(type) type * type##_copy(type *seq, PyArena *arena, int add_size);
ASDL_SEQ_COPY_HEADER(asdl_expr_seq)
ASDL_SEQ_COPY_HEADER(asdl_stmt_seq)
ASDL_SEQ_COPY_HEADER(asdl_keyword_seq)
ASDL_SEQ_COPY_HEADER(asdl_int_seq)
ASDL_SEQ_COPY_HEADER(asdl_arg_seq)

// -- mutator helper --
int get_clz_count(asdl_stmt_seq *stmt_seq);
stmt_ty get_clz(asdl_stmt_seq *stmt_seq, int index);

#endif