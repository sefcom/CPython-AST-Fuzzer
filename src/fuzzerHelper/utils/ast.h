#ifndef FUZZER_H
#define FUZZER_H

#include "defs.h"
#include "common.h"

typedef struct{
    uint32_t hash;
    PyObject *obj;
} simple_item_t;

PyObject *PyUnicode_FromString_Arena(const char *s, PyArena *arena);
PyObject *PyUnicode_Copy_Arena(PyObject *s, PyArena *arena);
PyObject *PyLong_FromLong_Arena(long n, PyArena *arena);

void gen_name_init();
PyObject *gen_name(int clear, int *id);
PyObject *gen_name_id(int id);
void override_name_init();
PyObject *rand_override_name();
PyObject *override_name(const char *name);

stmt_ty stmt(expr_ty expr, PyArena *arena);
int plain_clz(PyArena *arena, stmt_ty *stmt);
int clz_inherited(PyArena *arena, const char *base, stmt_ty *stmt);
int plain_func(PyArena *arena, stmt_ty *expr, arguments_ty args);
void func_w_name(PyArena *arena, PyObject *name, stmt_ty *expr, arguments_ty args);

#endif