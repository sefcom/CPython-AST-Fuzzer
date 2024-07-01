#include "fuzzer.h"

#define MALLOC_STEP 0x1000

int ensure_add(size_t new_buf, ast_data_t *data)
{
    if (1 + new_buf + data->ast_buf_used + data->ast_freelist_size + sizeof(meta_data_t) > data->ast_buf_size)
    {
        data->ast_buf = (u8 *)realloc(data->ast_buf, data->ast_buf_size + MALLOC_STEP);
        if (!data->ast_buf)
        {
            perror("ensure_add realloc");
            assert(0); // TODO
            return -1;
        }
        data->ast_buf_size += MALLOC_STEP;
    }
    data->ast_buf_used += new_buf;
    return 0;
}

int ensure_add_py_obj(size_t new_buf, ast_data_t *data)
{
    if (1 + new_buf + data->ast_buf_used + data->ast_freelist_size + sizeof(meta_data_t) > data->ast_buf_size)
    {
        data->ast_buf = (u8 *)realloc(data->ast_buf, data->ast_buf_size + MALLOC_STEP);
        if (!data->ast_buf)
        {
            perror("ensure_add realloc");
            assert(0); // TODO
            return -1;
        }
        data->ast_buf_size += MALLOC_STEP;
    }
    data->ast_freelist_size += new_buf;
    return 0;
}

void add_python_obj_int(ast_data_t *data, size_t offset, size_t number)
{
    ensure_add_py_obj(sizeof(python_obj_t), data);
    python_obj_t *dst = data->ast_buf + data->ast_buf_size - data->ast_freelist_size - sizeof(size_t) - sizeof(python_obj_t);
    dst->kind = NUMBER;
    dst->offset = offset;
    dst->val.number = number;

    data->ast_freelist_size += sizeof(python_obj_t);
    ((meta_data_t*)(data->ast_buf + data->ast_buf_size - sizeof(meta_data_t)))->free_list_size = data->ast_freelist_size;
}

void add_python_obj_str(ast_data_t *data, size_t offset, const char *str)
{
    ensure_add_py_obj(sizeof(python_obj_t) + strlen(str), data);
    python_obj_t *dst = data->ast_buf + data->ast_buf_size - data->ast_freelist_size - sizeof(size_t) - sizeof(python_obj_t) - strlen(str);
    char *dst_str = (char *)(dst + 1);
    dst->kind = STRING;
    dst->offset = offset;
    dst->val.string = dst_str;
    strcpy(dst_str, str);

    data->ast_freelist_size += sizeof(python_obj_t);
    ((meta_data_t*)(data->ast_buf + data->ast_buf_size - sizeof(meta_data_t)))->free_list_size = data->ast_freelist_size;
}