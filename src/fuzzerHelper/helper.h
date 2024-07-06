#ifndef HELPER_H
#define HELPER_H

#include "utils/ast.h"
mod_ty init_dummy_ast(PyArena **arena_ptr);
PyObject *dump_ast(PyObject *self, PyObject *args);

#endif // HELPER_H