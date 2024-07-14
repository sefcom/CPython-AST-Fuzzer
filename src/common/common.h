#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include "hash.h"

#define Py_BUILD_CORE 1
#include "Python.h"
#include "pycore_ast.h"

#define AST_DUMP_BUF_SIZE 2048

typedef struct{
    mod_ty mod;
    PyArena *arena;
    int gen_name_cnt;

    // mutation helpers
    int plain_clz_cnt;
    int inherited_clz_cnt;
    int func_cnt;
} ast_data_t;

typedef struct{
    char *ast_dump;
} global_info_t;

#endif