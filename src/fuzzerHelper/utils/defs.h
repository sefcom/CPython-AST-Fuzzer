#ifndef _DEFS_H
#define _DEFS_H

#include <stdint.h>
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
// int lineno, int col_offset, int end_lineno, int end_col_offset
#define LINE            0,0,0,0

#define NAME_L(name) _PyAST_Name(name, Load, LINE, data->arena)
#define NAME_S(name) _PyAST_Name(name, Store, LINE, data->arena)
#define CONST(name) _PyAST_Constant(name, NULL, LINE, data->arena)

#endif