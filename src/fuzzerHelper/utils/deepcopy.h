#ifndef DEEPCOPY_H
#define DEEPCOPY_H

#include "common.h"
#include "deepcopy_gen.h"

expr_ty expr_copy(expr_ty val, PyArena *arena);
stmt_ty stmt_copy(stmt_ty val, PyArena *arena);

#define ASDL_SEQ_COPY_HEADER(type)                                  \
    type *type##_copy(type *seq, PyArena *arena);                   \
    type *type##_copy_add(type *seq, PyArena *arena, int add_size); \
    type *type##_copy_add_front(type *seq, PyArena *arena, int add_size);

ASDL_SEQ_COPY_HEADER(asdl_expr_seq)
ASDL_SEQ_COPY_HEADER(asdl_stmt_seq)
ASDL_SEQ_COPY_HEADER(asdl_keyword_seq)
ASDL_SEQ_COPY_HEADER(asdl_int_seq)
ASDL_SEQ_COPY_HEADER(asdl_arg_seq)
ASDL_SEQ_COPY_HEADER(asdl_type_param_seq)
ASDL_SEQ_COPY_HEADER(asdl_comprehension_seq)
ASDL_SEQ_COPY_HEADER(asdl_alias_seq)
ASDL_SEQ_COPY_HEADER(asdl_excepthandler_seq)
ASDL_SEQ_COPY_HEADER(asdl_type_ignore_seq)
ASDL_SEQ_COPY_HEADER(asdl_withitem_seq)
ASDL_SEQ_COPY_HEADER(asdl_match_case_seq)
ASDL_SEQ_COPY_HEADER(asdl_identifier_seq)
ASDL_SEQ_COPY_HEADER(asdl_pattern_seq)

#define TRIAL_COPY_HEDER(type) type##_ty type##_copy(type##_ty val, PyArena *arena);
TRIAL_COPY_HEDER(boolop)
TRIAL_COPY_HEDER(operator)
TRIAL_COPY_HEDER(unaryop)
TRIAL_COPY_HEDER(cmpop)
TRIAL_COPY_HEDER(expr_context)
identifier identifier_copy(identifier val, PyArena *arena);
PyObject *constant_copy(PyObject *val, PyArena *arena);
PyObject *string_copy(PyObject *val, PyArena *arena);
// PyObject *object_copy(PyObject *val, PyArena *arena);

#endif // DEEPCOPY_H