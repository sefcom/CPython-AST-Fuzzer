#ifndef LOGH
#define LOGH

#include <stdio.h>

void info(const char *fmt, ...);
void error(const char *fmt, ...);
void panic(const char *fmt, ...);

#endif // LOGH