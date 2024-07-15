#include "log.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#define RED "\033[0;31m"
#define RESET "\033[0m"

void info(const char *fmt, ...)
{
    #ifndef QUIET
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    #endif
}

void error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, RED);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, RESET);
    va_end(args);
}

void panic(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, RED);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, RESET);
    va_end(args);
    signal(SIGABRT, SIG_DFL);
}
