#include "fuzzer.h"

#define MALLOC_STEP 0x1000

int ensure_add(size_t new_buf, my_mutator_t *data)
{
    if (new_buf + data->ast_buf_used > data->ast_buf_size)
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