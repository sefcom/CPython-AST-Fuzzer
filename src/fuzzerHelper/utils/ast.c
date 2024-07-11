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

PyObject *PyUnicode_Copy_Arena(PyObject *s, PyArena *arena)
{
    PyObject *re = (PyObject *)PyUnicode_FromObject(s);
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
    *id = cnt;
    return names[cnt++ % 50];
}

PyObject *gen_name_id(int id)
{
    return names[id];
}

void gen_name_init(){
    names = (PyObject **)malloc(50 * sizeof(PyObject *));
    char name[10];
    for (int i = 0; i < 50; i++)
    {
        sprintf(name, "name%d", i);
        names[i] = PyUnicode_FromString(name);
    }
}

static simple_item_t *overrides = NULL;

void override_name_init()
{
    // ['__new__', '__repr__', '__hash__', '__str__', '__getattribute__', '__setattr__', '__delattr__', '__lt__', '__le__', '__eq__', '__ne__', '__gt__', '__ge__', '__init__', '__reduce_ex__', '__reduce__', '__getstate__', '__subclasshook__', '__init_subclass__', '__format__', '__sizeof__', '__dir__', '__class__', '__doc__']
    overrides = (simple_item_t *)malloc(24 * sizeof(simple_item_t));
    overrides[0] = GEN_ITEM("__new__");
    overrides[1] = GEN_ITEM("__repr__");
    overrides[2] = GEN_ITEM("__hash__");
    overrides[3] = GEN_ITEM("__str__");
    overrides[4] = GEN_ITEM("__getattribute__");
    overrides[5] = GEN_ITEM("__setattr__");
    overrides[6] = GEN_ITEM("__delattr__");
    overrides[7] = GEN_ITEM("__lt__");
    overrides[8] = GEN_ITEM("__le__");
    overrides[9] = GEN_ITEM("__eq__");
    overrides[10] = GEN_ITEM("__ne__");
    overrides[11] = GEN_ITEM("__gt__");
    overrides[12] = GEN_ITEM("__ge__");
    overrides[13] = GEN_ITEM("__init__");
    overrides[14] = GEN_ITEM("__reduce_ex__");
    overrides[15] = GEN_ITEM("__reduce__");
    overrides[16] = GEN_ITEM("__getstate__");
    overrides[17] = GEN_ITEM("__subclasshook__");
    overrides[18] = GEN_ITEM("__init_subclass__");
    overrides[19] = GEN_ITEM("__format__");
    overrides[20] = GEN_ITEM("__sizeof__");
    overrides[21] = GEN_ITEM("__dir__");
    overrides[22] = GEN_ITEM("__class__");
    overrides[23] = GEN_ITEM("__doc__");
}

PyObject *rand_override_name()
{
    return overrides[rand() % 24].obj;
}

PyObject *override_name(const char *name)
{
    uint32_t hash = SuperFastHash(name, strlen(name));
    for (int i = 0; i < 24; i++)
    {
        if (overrides[i].hash == hash)
        {
            return overrides[i].obj;
        }
    }
    return NULL;
}

stmt_ty stmt(expr_ty expr, PyArena *arena)
{
    return _PyAST_Expr(expr, LINE, arena);
}