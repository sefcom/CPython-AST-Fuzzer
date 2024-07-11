#ifndef MUTATORS_H
#define MUTATORS_H

#include "../utils/ast.h"

void entry_mutate(ast_data_t **data, size_t max_size, size_t seed);

// --- mutators ---
void add_clz_and_init(ast_data_t *data);

#endif // MUTATORS_H