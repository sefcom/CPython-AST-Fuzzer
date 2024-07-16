#include "mutators.h"
#include "deepcopy.h"

#define LONG(name) PyLong_FromLong_Arena(name, data->arena)

int mutate_list_entry(ast_data_t *data, stmt_ty picked_func){
    return STATE_OK;
}