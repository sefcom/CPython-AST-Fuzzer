#ifndef _DEFS_H
#define _DEFS_H

#include <stdint.h>
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#endif