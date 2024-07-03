#include "ast.h"

mod_ty new_mod(ast_data_t *data)
{
    assert(data);
    mod_ty mod = data->ast_buf + data->ast_buf_used;
    ensure_add(sizeof(struct _mod), data);
    mod->kind = Module_kind;
    mod->v.Module.type_ignores = empty_type_ignore_seq(data, 0); //empty
    return mod;
}

asdl_stmt_seq *new_body(ast_data_t *data, size_t n_ele)
{
    assert(data);
    assert(n_ele > 0);
    asdl_stmt_seq *body = data->ast_buf + data->ast_buf_used;
    ensure_add(sizeof(asdl_stmt_seq) + (n_ele - 1) * sizeof(stmt_ty), data);
    body->size = n_ele;
    body->elements = (void **)body->typed_elements;
    return body;
}

asdl_type_ignore_seq *empty_type_ignore_seq(ast_data_t *data, size_t n_ele)
{
    assert(data);
    asdl_type_ignore_seq *type_ignore_seq = data->ast_buf + data->ast_buf_used;
    ensure_add(sizeof(asdl_type_ignore_seq), data);
    type_ignore_seq->size = n_ele;
    type_ignore_seq->elements = (void**)type_ignore_seq->typed_elements;
    return type_ignore_seq;
}

stmt_ty new_stmt(ast_data_t *data)
{
    assert(data);
    stmt_ty stmt = data->ast_buf + data->ast_buf_used;
    ensure_add(sizeof(struct _stmt), data);
    return stmt;
}

expr_ty new_expr(ast_data_t *data)
{
    assert(data);
    expr_ty expr = data->ast_buf + data->ast_buf_used;
    ensure_add(sizeof(struct _expr), data);
    return expr;
}

expr_ty new_func(ast_data_t *data, const char *name)
{
    assert(data);
    expr_ty func = new_expr(data);
    func->kind = Name_kind;
    func->v.Name.id = PyUnicode_FromString(name);
    func->v.Name.ctx = Load;
    return func;
}

asdl_expr_seq *new_args(ast_data_t *data, size_t n_ele)
{
    assert(data);
    assert(n_ele >= 0);
    asdl_expr_seq *args = data->ast_buf + data->ast_buf_used;
    ensure_add(sizeof(asdl_expr_seq) + (n_ele - 1) * sizeof(expr_ty), data);
    args->size = n_ele;
    args->elements = (void **)args->typed_elements;
    return args;
}

asdl_keyword_seq *new_keywords(ast_data_t *data, size_t n_ele)
{
    assert(data);
    assert(n_ele >= 0);
    asdl_keyword_seq *keywords = data->ast_buf + data->ast_buf_used;
    ensure_add(sizeof(asdl_keyword_seq) + (n_ele - 1) * sizeof(keyword_ty), data);
    keywords->size = n_ele;
    keywords->elements = (void **)keywords->typed_elements;
    return keywords;
}

PyObject *mod2addr(mod_ty mod)
{
    return (PyObject *) mod;
}