#ifndef FUZZER_H
#define FUZZER_H

#include "defs.h"
#define Py_BUILD_CORE 1
#include "Python.h"
#include "pycore_ast.h"

typedef struct{
    mod_ty mod;
    PyArena *arena;
} ast_data_t;

PyObject *PyUnicode_FromString_Arena(const char *s, PyArena *arena);
PyObject *PyLong_FromLong_Arena(long n, PyArena *arena);
PyObject *ptr2addr(void *ptr);

#endif