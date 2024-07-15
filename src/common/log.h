#ifndef LOGH
#define LOGH

#include <stdio.h>

#define INFO(fmt, ...) info(fmt, ##__VA_ARGS__)
#define ERROR(fmt, ...) error(fmt, ##__VA_ARGS__)
#define PANIC(fmt, ...) panic(fmt, ##__VA_ARGS__)

void info(const char *fmt, ...);
void error(const char *fmt, ...);
void panic(const char *fmt, ...);

#endif // LOGH