#include "helper.h"
#include "mutators/mutators.h"

void get_dummy_ast(ast_data_t **data_ptr)
{
	PyArena *arena = _PyArena_New();
	*data_ptr = (ast_data_t *)_PyArena_Malloc(arena, sizeof(ast_data_t));
	(*data_ptr)->arena = arena;
	(*data_ptr)->mod = init_dummy_ast((*data_ptr)->arena);
}

void get_UAF2_ast(ast_data_t **data_ptr)
{
	PyArena *arena = _PyArena_New();
	*data_ptr = (ast_data_t *)_PyArena_Malloc(arena, sizeof(ast_data_t));
	(*data_ptr)->arena = arena;
	(*data_ptr)->mod = init_UAF2((*data_ptr)->arena);
}

void free_ast(ast_data_t **data_ptr)
{
	_PyArena_Free((*data_ptr)->arena);
	PyMem_Free(*data_ptr);
	*data_ptr = NULL;
}

global_info_t *data_backup;

size_t __attribute__((visibility("default"))) LLVMFuzzerCustomMutator(ast_data_t **data, size_t size, size_t max_size, unsigned int seed)
{
	if (data == NULL || *data == NULL || size != sizeof(ast_data_t *))
	{
		printf("retrieving dummy ast, size=%d\n", size);
		get_dummy_ast(data);
	}
	else
	{
		// free_ast(data);
		// get_UAF2_ast(data);
		entry_mutate(data, max_size, seed);
	}
	return sizeof(ast_data_t *);
}

int __attribute__((visibility("default"))) LLVMFuzzerInitialize(int *argc, char ***argv) {
	data_backup = (global_info_t *)malloc(sizeof(global_info_t));
	data_backup->ast_dump = (const char *)calloc(AST_DUMP_BUF_SIZE, 1);
    Py_Initialize();
	gen_name_init();
	override_name_init();
    return 0;
}