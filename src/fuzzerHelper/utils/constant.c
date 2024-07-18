#include "ast.h"

#define GEN_CONST(name) PyObject *name##_OBJ = NULL
#define GEN_CONST2(name, val) name##_OBJ = PyUnicode_FromString(val)

GEN_CONST(KEYS);
GEN_CONST(LEN);
GEN_CONST(ISINSTANTANCE);
GEN_CONST(SELF);
GEN_CONST(KWARGS);
GEN_CONST(VARARGS);
GEN_CONST(CLEAR);

void init_constants()
{
    GEN_CONST2(KEYS, "keys");
    GEN_CONST2(LEN, "__len__");
    GEN_CONST2(ISINSTANTANCE, "isinstance");
    GEN_CONST2(SELF, "self");
    GEN_CONST2(KWARGS, "kwargs");
    GEN_CONST2(VARARGS, "varargs");
    GEN_CONST2(CLEAR, "clear");
}