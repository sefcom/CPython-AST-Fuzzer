#include "ast.h"
#include "override_func_gen.h"

static PyObject **names = NULL;

PyObject *gen_name_id(int id)
{
    if (unlikely(id >= CACHED_NAMES))
    {
        char name[10];
        sprintf(name, "name%d", id);
        // TODO arena version?
        return PyUnicode_FromString(name);
    }
    return names[id];
}

void gen_name_init()
{
    names = (PyObject **)malloc(CACHED_NAMES * sizeof(PyObject *));
    char name[10];
    for (int i = 0; i < CACHED_NAMES; i++)
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
