#ifndef TARGET_H
#define TARGET_H

#include "common.h"
#include "log.h"

#define SAVE_PERIOD 1000

int dump_ast(const ast_data_t *data, char *buf, size_t max_len);
void __sanitizer_set_death_callback(void (*callback)(void));

#endif