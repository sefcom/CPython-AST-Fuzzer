#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

uint32_t SuperFastHash (const char * data, int len);

#define Py_BUILD_CORE 1
#include "Python.h"
#include "pycore_ast.h"

#define AST_DUMP_BUF_SIZE 2048

typedef struct{
    mod_ty mod;
    PyArena *arena;
} ast_data_t;

typedef struct{
    const char *ast_dump;
} global_info_t;

#endif