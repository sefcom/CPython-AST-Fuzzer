#ifndef MUTATE_TYPE_H
#define MUTATE_TYPE_H

#define MUTATE_TYPE(type) \
    int mutate_##type##_entry(ast_data_t *data, stmt_ty picked_func)
#define PICK_ARG_OFS(range_ofs, ofs)                         \
    picked_arg_id = rand() % (args->size + range_ofs) + ofs; \
    picked_arg = args->typed_elements[picked_arg_id]->arg;
#define PICK_ARG PICK_ARG_OFS(0, 0)
#define MERGE_STMT                                                                                             \
    picked_func->v.FunctionDef.body = asdl_stmt_seq_copy_add(picked_func->v.FunctionDef.body, data->arena, 1); \
    picked_func->v.FunctionDef.body->typed_elements[picked_func->v.FunctionDef.body->size - 1] = add_stmt;
#define MUTATE_TYPE_LOOP      \
    int state = STATE_REROLL; \
    stmt_ty add_stmt = NULL;  \
    int picked_arg_id;        \
    PyObject *picked_arg;     \
    while (state != STATE_OK)

#endif