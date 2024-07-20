#ifndef ARENA_H
#define ARENA_H

#include "common.h"

// --- Arena helpers ---

// construct a new PyUnicode from C-style string by PyArena
PyObject *PyUnicode_FromString_Arena(const char *s, PyArena *arena);
// copy a PyUnicode object into PyArena
PyObject *PyUnicode_Copy_Arena(PyObject *s, PyArena *arena);
// construct a new PyLong from long by PyArena
PyObject *PyLong_FromLong_Arena(long n, PyArena *arena);
// copy a PyLong object into PyArena
PyObject *PyLong_Copy_Arena(PyObject *s, PyArena *arena);

#endif // ARENA_H