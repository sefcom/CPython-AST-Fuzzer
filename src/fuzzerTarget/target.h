#ifndef TARGET_H
#define TARGET_H

#define Py_BUILD_CORE 1
#include "Python.h"
#include "pycore_ast.h"

typedef struct{
    mod_ty mod;
    PyArena *arena;
} ast_data_t;
void dump_ast(const ast_data_t *data, char *buf, size_t max_len);
void __sanitizer_set_death_callback(void (*callback)(void));
uint32_t SuperFastHash (const char * data, int len);
#endif