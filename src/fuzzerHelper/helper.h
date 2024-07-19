#ifndef HELPER_H
#define HELPER_H

#include "utils/ast.h"

// init a dummy ast (only contain pass)
// if there is known corpus as base (passed by -last-case), then use it instead
mod_ty init_dummy_ast(ast_data_t *arena);
// init a ast equivalent to motivation sample 2 in the design document
mod_ty init_UAF2(ast_data_t *arena);
// use ast.parse to load ast
mod_ty load_ast(ast_data_t *data, const char *buf); // implement in fuzzerTarget

extern FILE *last_case;

#endif // HELPER_H