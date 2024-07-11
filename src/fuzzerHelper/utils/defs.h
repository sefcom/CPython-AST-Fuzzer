#ifndef _DEFS_H
#define _DEFS_H

#include <stdint.h>
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
// int lineno, int col_offset, int end_lineno, int end_col_offset
#define LINE            0,0,0,0
#define GEN10(func, a) func(a "0"), func(a "1"), func(a "2"), func(a "3"), func(a "4"), func(a "5"), func(a "6"), func(a "7"), func(a "8"), func(a "9")
#define GEN_ITEM(n) (simple_item_t){SuperFastHash(n, strlen(n)), PyUnicode_FromString(n)}

#define MAX_DEPTH 5
#define FREED_ASL_SEQ_SIZE 20

#endif