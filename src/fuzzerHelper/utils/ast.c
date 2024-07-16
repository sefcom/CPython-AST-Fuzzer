#include "ast.h"
#include "override_func.h"

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

overridable_func rand_override_func(int base_clz_id)
{
    return overridable_funcs_raw[builtin_clz_start[base_clz_id] + rand() % (builtin_clz_start[base_clz_id + 1] - builtin_clz_start[base_clz_id])];
}

overridable_func *override_func(const char *name)
{
    overridable_func *s;
    HASH_FIND_STR(overridable_funcs, name, s);
    return s;
}

stmt_ty stmt(expr_ty expr, PyArena *arena)
{
    return _PyAST_Expr(expr, LINE, arena);
}

PyObject *get_locals_internal(int *index, asdl_stmt_seq *body_raw)
{
    for (int i = 0; i < body_raw->size; i++)
    {
        stmt_ty ele = body_raw->typed_elements[i];
        PyObject *re;
        switch (ele->kind)
        {
        case Assign_kind:
            if (*index == 0)
            {
                return ele->v.Assign.targets->typed_elements[0]->v.Name.id;
            }
            *index = *index - 1;
            break;
        case FunctionDef_kind:
            re = get_locals_internal(index, ele->v.FunctionDef.body);
            if (re != NULL)
            {
                return re;
            }
            break;
        case ClassDef_kind:
            re = get_locals_internal(index, ele->v.ClassDef.body);
            if (re != NULL)
            {
                return re;
            }
            break;
        case If_kind:
            re = get_locals_internal(index, ele->v.If.body);
            if (re != NULL)
            {
                return re;
            }
            break;
        case While_kind:
            re = get_locals_internal(index, ele->v.While.body);
            if (re != NULL)
            {
                return re;
            }
            break;
        case For_kind:
            re = get_locals_internal(index, ele->v.For.body);
            if (re != NULL)
            {
                return re;
            }
            break;
        case With_kind:
            re = get_locals_internal(index, ele->v.With.body);
            if (re != NULL)
            {
                return re;
            }
            break;
        default:
            break;
        }
    }
    return NULL;
}

PyObject *get_locals(ast_data_t *data, int index)
{
    int idx = index;
    PyObject *re = get_locals_internal(&idx, data->mod->v.Module.body);
    if (re == NULL)
    {
        PANIC("no locals found: req %d, remaining %d\n", index, idx);
    }
    return re;
}
