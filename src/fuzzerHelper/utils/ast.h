#ifndef FUZZER_H
#define FUZZER_H

#include "defs.h"
#include "common.h"
#include "arena.h"
#include "log.h"
#include "override_func.h"
#include "deepcopy.h"

// --- name helpers ---

// init the static buffer for name generator
void gen_name_init();
// get the name by id
PyObject *gen_name_id(int id);
// init the static buffer for override function generator
void override_name_init();
// get the function by id
overridable_func rand_override_func(int base_clz_id);
// get the function by name
overridable_func *override_func(const char *name);

// --- AST helpers ---

// simple expr -> stmt
stmt_ty stmt(expr_ty expr, PyArena *arena);
// get index-th local variable (defined by _PyAST_Assign) name recursively
PyObject *get_locals(ast_data_t *data, int index);

// -- class helpers --
// create a plain class with given name
stmt_ty plain_clz(ast_data_t *data, PyObject *name);
// create a class inherited from base class with given name
stmt_ty clz_inherited(ast_data_t *data, const char *base, PyObject *name);
// find a class by name in given stmt_seq
stmt_ty find_clz(asdl_stmt_seq *stmt_seq, PyObject *clz_name);

// -- function helpers --
// create a function with given name and arguments pointer
stmt_ty func_w_name(ast_data_t *data, PyObject *name, arguments_ty args);
// get index-th function recursively
stmt_ty get_func(ast_data_t *data, int index);
// get index-th function with specific base class recursively
stmt_ty get_func_w_base_clz(ast_data_t *data, int index, stmt_ty *base);

// --- mutator helpers ---

// get the count of class definition in the stmt_seq
// pass a int pointer to get the count of plain class
int get_clz_count(asdl_stmt_seq *stmt_seq, int *plain_clz);
// get the index-th class definition in the stmt_seq
// if plain_clz_required is 1, then only count plain class
stmt_ty get_clz(asdl_stmt_seq *stmt_seq, int index, int plain_clz_required);

// --- constants ---

#define CACHED_NAMES 50
#define GEN_CONST(name) extern PyObject *name##_OBJ
GEN_CONST(KEYS);
GEN_CONST(LEN);
GEN_CONST(ISINSTANTANCE);
GEN_CONST(SELF);
GEN_CONST(KWARGS);
GEN_CONST(VARARGS);
GEN_CONST(CLEAR);
GEN_CONST(APPEND);
GEN_CONST(POP);
#undef GEN_CONST
void init_constants();

// --- variable helpers ---

// construct a If block with given condition and body
stmt_ty do_w_cond(ast_data_t *data, expr_ty cond, stmt_ty body);

// -- iterable --
// isinstance(<in_var>, <type>) and len(<in_var>) > 0
stmt_ty iterable_non_empty_and_type_cond(ast_data_t *data, PyObject *in_var, PyObject *type, stmt_ty body);
// <in_var>[index % len(in_var)] for load context
expr_ty iterable_get_element_load(ast_data_t *data, expr_ty in_var, PyObject *index);
// <in_var>[index % len(in_var)] for del context
expr_ty iterable_get_element_del(ast_data_t *data, expr_ty in_var, PyObject *index);

// -- dict --
// del <in_var>[<index>]
stmt_ty dict_del(ast_data_t *data, PyObject *in_var, PyObject *index);
// <in_var>[<index>] = <value>
stmt_ty dict_assign(ast_data_t *data, PyObject *in_var, expr_ty value, PyObject *index);

#endif