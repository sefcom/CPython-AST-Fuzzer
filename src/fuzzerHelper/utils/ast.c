#include "ast.h"

PyObject *PyUnicode_FromString_Arena(const char *s, PyArena *arena)
{
    PyObject *re = (PyObject *)PyUnicode_FromString(s);
    _PyArena_AddPyObject(arena, re);
    // check obj2ast_constant from CPython source code
    Py_INCREF(re);
    assert(PyUnicode_READY(re) == 0);
    return re;
}

PyObject *PyLong_Copy_Arena(PyObject *s, PyArena *arena)
{
    if(s == NULL){
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
    if(s == NULL){
        return NULL;
    }
    Py_ssize_t length = PyUnicode_GET_LENGTH(s);
    PyObject *re = (PyObject *)PyUnicode_New(length, PyUnicode_MAX_CHAR_VALUE(s));
    memcpy(PyUnicode_DATA(re), PyUnicode_DATA(s), length * PyUnicode_KIND(s)); // from _PyUnicode_Copy but no checks
    _PyArena_AddPyObject(arena, re);
    // check obj2ast_constant from CPython source code
    Py_INCREF(re);
    assert(PyUnicode_READY(re) == 0);
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

static PyObject **names = NULL;

PyObject *gen_name(int clear, int *id)
{
    static int cnt = 0;
    if (clear)
    {
        cnt = 0;
    }
    if(id != NULL){
        *id = cnt;
    }
    return names[cnt++ % 50];
}

PyObject *gen_name_id(int id)
{
    return names[id];
}

void gen_name_init()
{
    names = (PyObject **)malloc(50 * sizeof(PyObject *));
    char name[10];
    for (int i = 0; i < 50; i++)
    {
        sprintf(name, "name%d", i);
        names[i] = PyUnicode_FromString(name);
    }
}

overridable_func *rand_override_func(const char *builtin_tp_name)
{
    int i = 0;
    unsigned long hash = 0;
    while(i < builtin_type_cnt){
        HASH_VALUE(builtin_tp_name, strlen(builtin_tp_name), hash);
        if(builtin_clz_str[i] == hash){
            return &overridable_funcs_raw[builtin_clz_start[i] + rand() % (builtin_clz_start[i - 1] - builtin_clz_start[i])];
        }
    }
    return NULL;
}

overridable_func *override_func(const char *name)
{
    overridable_func *s;
    HASH_FIND_STR(overridable_funcs, name, s);
    return s;
}

static PyObject **types = NULL;

stmt_ty stmt(expr_ty expr, PyArena *arena)
{
    return _PyAST_Expr(expr, LINE, arena);
}
