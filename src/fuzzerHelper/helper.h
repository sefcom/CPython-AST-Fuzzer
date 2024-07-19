#ifndef HELPER_H
#define HELPER_H

#include "utils/ast.h"
mod_ty init_dummy_ast(ast_data_t *arena);
mod_ty init_UAF2(ast_data_t *arena);
mod_ty load_ast(ast_data_t *data, const char *buf); // implement in fuzzerTarget

extern FILE *last_case;

#endif // HELPER_H