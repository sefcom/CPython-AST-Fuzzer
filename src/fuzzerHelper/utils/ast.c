#include "ast.h"

PyObject *PyUnicode_FromString_Arena(const char *s, PyArena *arena)
{
    PyObject *re = (PyObject *)PyUnicode_FromString(s);
    _PyArena_AddPyObject(arena, re);
    // check obj2ast_constant
    Py_INCREF(re);
    assert(PyUnicode_READY(re) == 0);
    return re;
}

PyObject *PyLong_FromLong_Arena(long n, PyArena *arena)
{
    PyObject *re = (PyObject *)PyLong_FromLong(n);
    _PyArena_AddPyObject(arena, re);
    // check obj2ast_constant
    Py_INCREF(re);
    return re;
}

PyObject *ptr2addr(void *ptr)
{
    PyObject *re = (PyObject *)PyLong_FromSize_t((size_t)ptr);
    Py_INCREF(re);
    return re;
}