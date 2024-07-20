#include "ast.h"

PyObject *PyUnicode_FromString_Arena(const char *s, PyArena *arena)
{
    PyObject *re = (PyObject *)PyUnicode_FromString(s);
    _PyArena_AddPyObject(arena, re);
    // check obj2ast_constant from CPython source code
    Py_INCREF(re);
    return re;
}

PyObject *PyLong_Copy_Arena(PyObject *s, PyArena *arena)
{
    if (s == NULL)
    {
        return NULL;
    }
    PyObject *re = (PyObject *)PyLong_FromLongLong(PyLong_AsLongLong(s));
    _PyArena_AddPyObject(arena, re);
    // check obj2ast_constant from CPython source code
    Py_INCREF(re);
    return re;
}

PyObject *PyUnicode_Copy_Arena(PyObject *s, PyArena *arena)
{
    if (s == NULL)
    {
        return NULL;
    }
    Py_ssize_t length = PyUnicode_GET_LENGTH(s);
    PyObject *re = (PyObject *)PyUnicode_New(length, PyUnicode_MAX_CHAR_VALUE(s));
    memcpy(PyUnicode_DATA(re), PyUnicode_DATA(s), length * PyUnicode_KIND(s)); // from _PyUnicode_Copy but no checks
    _PyArena_AddPyObject(arena, re);
    // check obj2ast_constant from CPython source code
    Py_INCREF(re);
    return re;
}

PyObject *PyLong_FromLong_Arena(long n, PyArena *arena)
{
    PyObject *re = (PyObject *)PyLong_FromLong(n);
    _PyArena_AddPyObject(arena, re);
    // check obj2ast_constant from CPython source code
    Py_INCREF(re);
    return re;
}

stmt_ty stmt(expr_ty expr, PyArena *arena)
{
    return _PyAST_Expr(expr, LINE, arena);
}

stmt_ty do_w_cond(ast_data_t *data, expr_ty cond, stmt_ty body)
{
    stmt_ty stmt = _PyAST_If(
        cond,
        _Py_asdl_stmt_seq_new(1, data->arena),
        NULL,
        LINE,
        data->arena);
    stmt->v.If.body->typed_elements[0] = body;
    return stmt;
}
