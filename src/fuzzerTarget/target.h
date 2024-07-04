#ifndef TARGET_H
#define TARGET_H

#define Py_BUILD_CORE 1
#include "Python.h"
#include "pycore_ast.h"

typedef struct{
    mod_ty mod;
    PyArena *arena;
} ast_data_t;

PyObject *run_mod(mod_ty mod);

#endif // TARGET_H