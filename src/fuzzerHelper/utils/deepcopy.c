#include "deepcopy.h"
#include "arena.h"
#include "log.h"

#define TRIAL_COPY(type)                                 \
    type##_ty type##_copy(type##_ty val, PyArena *arena) \
    {                                                    \
        return val;                                      \
    }
TRIAL_COPY(boolop)
TRIAL_COPY(operator)
TRIAL_COPY(unaryop)
TRIAL_COPY(cmpop)
TRIAL_COPY(expr_context)

identifier identifier_copy(identifier val, PyArena *arena)
{
    return PyUnicode_Copy_Arena(val, arena);
}
PyObject *string_copy(PyObject *val, PyArena *arena)
{
    return PyUnicode_Copy_Arena(val, arena);
}
PyObject *constant_copy(PyObject *val, PyArena *arena)
{
    if (PyLong_CheckExact(val))
    {
        return PyLong_Copy_Arena(val, arena);
    }
    else if (PyUnicode_CheckExact(val))
    {
        return PyUnicode_Copy_Arena(val, arena);
    }
    ERROR("Unknown constant type, use fallback - %s\n", val->ob_type->tp_name);
    _PyArena_AddPyObject(arena, val);
    Py_INCREF(val);
    return val;
}

#define ASDL_SEQ_COPY_COMBINED(type) \
    ASDL_SEQ_COPY_ADD_FRONT(type)    \
    ASDL_SEQ_COPY_ADD(type)          \
    ASDL_SEQ_COPY(type)

#define ASDL_SEQ_COPY_ADD(type)                                                                           \
    asdl_##type##_seq *asdl_##type##_seq##_copy_add(asdl_##type##_seq *seq, PyArena *arena, int add_size) \
    {                                                                                                     \
        asdl_##type##_seq *re;                                                                            \
        if (seq == NULL)                                                                                  \
        {                                                                                                 \
            re = _Py_##asdl_##type##_seq##_new(add_size, arena);                                          \
        }                                                                                                 \
        else                                                                                              \
        {                                                                                                 \
            re = _Py_##asdl_##type##_seq##_new(seq->size + add_size, arena);                              \
            for (int i = 0; i < seq->size; i++)                                                           \
            {                                                                                             \
                re->typed_elements[i] = type##_copy(seq->typed_elements[i], arena);                       \
            }                                                                                             \
        }                                                                                                 \
        return re;                                                                                        \
    }

#define ASDL_SEQ_COPY_ADD_FRONT(type)                                                                           \
    asdl_##type##_seq *asdl_##type##_seq##_copy_add_front(asdl_##type##_seq *seq, PyArena *arena, int add_size) \
    {                                                                                                           \
        asdl_##type##_seq *re;                                                                                  \
        if (seq == NULL)                                                                                        \
        {                                                                                                       \
            re = _Py_##asdl_##type##_seq##_new(add_size, arena);                                                \
        }                                                                                                       \
        else                                                                                                    \
        {                                                                                                       \
            re = _Py_##asdl_##type##_seq##_new(seq->size + add_size, arena);                                    \
            for (int i = 1; i < seq->size + 1; i++)                                                             \
            {                                                                                                   \
                re->typed_elements[i] = type##_copy(seq->typed_elements[i - 1], arena);                         \
            }                                                                                                   \
        }                                                                                                       \
        return re;                                                                                              \
    }

#define ASDL_SEQ_COPY(type)                                                             \
    asdl_##type##_seq *asdl_##type##_seq##_copy(asdl_##type##_seq *seq, PyArena *arena) \
    {                                                                                   \
        if (seq == NULL)                                                                \
        {                                                                               \
            return NULL;                                                                \
        }                                                                               \
        asdl_##type##_seq *re = _Py_##asdl_##type##_seq##_new(seq->size, arena);        \
        for (int i = 0; i < seq->size; i++)                                             \
        {                                                                               \
            re->typed_elements[i] = type##_copy(seq->typed_elements[i], arena);         \
        }                                                                               \
        return re;                                                                      \
    }

ASDL_SEQ_COPY_COMBINED(expr)
ASDL_SEQ_COPY_COMBINED(stmt)
ASDL_SEQ_COPY_COMBINED(keyword)
asdl_int_seq *asdl_int_seq_copy(asdl_int_seq *seq, PyArena *arena)
{
    asdl_int_seq *re = _Py_asdl_int_seq_new(seq->size, arena);
    for (int i = 0; i < seq->size; i++)
    {
        re->typed_elements[i] = seq->typed_elements[i];
    }
    return re;
}
asdl_int_seq *asdl_int_seq_copy_add(asdl_int_seq *seq, PyArena *arena, int add_size)
{
    asdl_int_seq *re = _Py_asdl_int_seq_new(seq->size + add_size, arena);
    for (int i = 0; i < seq->size; i++)
    {
        re->typed_elements[i] = seq->typed_elements[i];
    }
    return re;
}
ASDL_SEQ_COPY_COMBINED(arg)
ASDL_SEQ_COPY_COMBINED(comprehension)
ASDL_SEQ_COPY_COMBINED(type_param)
ASDL_SEQ_COPY_COMBINED(alias)
ASDL_SEQ_COPY_COMBINED(excepthandler)
ASDL_SEQ_COPY_COMBINED(type_ignore)
ASDL_SEQ_COPY_COMBINED(withitem)
ASDL_SEQ_COPY_COMBINED(match_case)
ASDL_SEQ_COPY_COMBINED(identifier)
ASDL_SEQ_COPY_COMBINED(pattern)
