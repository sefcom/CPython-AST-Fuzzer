#include "fuzzer.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define Py_BUILD_CORE 1
#include "Python.h"
#include "pycore_ast.h"

#define MAX_DEPTH 5

/**
 * Initialize this custom mutator
 *
 * @param[in] afl a pointer to the internal state object. Can be ignored for
 * now.
 * @param[in] seed A seed for this mutator - the same seed should always mutate
 * in the same way.
 * @return Pointer to the data object this custom mutator instance should use.
 *         There may be multiple instances of this mutator in one afl-fuzz run!
 *         Return NULL on error.
 */
my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed)
{
    srand(seed); // needed also by surgical_havoc_mutate()

    my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
    if (!data)
    {

        perror("afl_custom_init alloc");
        return NULL;
    }

    data->dummy_ast.ast_buf_size = 0x500;

    if ((data->dummy_ast.ast_buf = calloc(1, data->dummy_ast.ast_buf_size)) == NULL)
    {

        perror("afl_custom_init malloc");
        return NULL;
    }

    // dummy AST
    // print(1)
    ast_data_t *dummy_ast = &(data->dummy_ast);
    mod_ty root = new_mod(dummy_ast);
    asdl_stmt_seq *body = new_body(dummy_ast, 2);
    root->v.Interactive.body = body;

    // docstring
    stmt_ty stmt_doc = new_stmt(dummy_ast);
    body->elements[0] = stmt_doc;
    stmt_doc->kind = Expr_kind;
    expr_ty expr_doc = new_expr(dummy_ast);
    stmt_doc->v.Expr.value = expr_doc;
    expr_doc->kind = Constant_kind;
    add_python_obj_str(dummy_ast, (size_t)&(expr_doc->v.Constant.value) - (size_t)root, "dummy");

    stmt_ty stmt = new_stmt(dummy_ast);
    body->elements[1] = stmt;
    stmt->kind = Expr_kind;

    expr_ty expr = new_expr(dummy_ast);
    expr->kind = Call_kind;
    expr->v.Call.func = new_func(dummy_ast, "print");

    asdl_expr_seq *args = new_args(dummy_ast, 1);
    expr_ty arg = new_expr(dummy_ast);
    arg->kind = Constant_kind;
    add_python_obj_int(dummy_ast, (size_t)&(arg->v.Constant.value) - (size_t)root, 1);
    arg->v.Constant.kind = NULL;
    args->elements[0] = arg;
    expr->v.Call.args = args;
    expr->v.Call.keywords = new_keywords(dummy_ast, 0);

    data->afl = afl;

    return data;
}

/**
 * Perform custom mutations on a given input
 *
 * (Optional for now. Required in the future)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[in] buf Pointer to input data to be mutated
 * @param[in] buf_size Size of input data
 * @param[out] out_buf the buffer we will work on. we can reuse *buf. NULL on
 * error.
 * @param[in] add_buf Buffer containing the additional test case
 * @param[in] add_buf_size Size of the additional test case
 * @param[in] max_size Maximum size of the mutated output. The mutation must not
 *     produce data larger than max_size.
 * @return Size of the mutated output.
 */
size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf,
                       size_t add_buf_size, // add_buf can be NULL
                       size_t max_size)
{

    if(strcmp(buf, "PLAC") == 0){
        // ignore buf
        // do mutation on dummy AST
        // TODO
        *out_buf = data->dummy_ast.ast_buf;
        return data->dummy_ast.ast_buf_size;
    }
    return 0;
}

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(my_mutator_t *data)
{
    if(data->dummy_ast.ast_buf_size !=0){
        free(data->dummy_ast.ast_buf);
    }

    if(data->ast_buf.ast_buf_size != 0){
        free(data->ast_buf.ast_buf);
    }

    free(data);
}