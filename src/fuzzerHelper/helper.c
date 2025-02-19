#include "helper.h"
#include "mutators/mutators.h"

FILE *last_case = NULL;

void init_ast_data(ast_data_t **buf, PyArena *arena)
{
	ast_data_t *data = (ast_data_t *)_PyArena_Malloc(arena, sizeof(ast_data_t));
	memset(data, 0, sizeof(ast_data_t));
	data->arena = arena;
	*buf = data;
}

void get_dummy_ast(ast_data_t **data_ptr)
{
	PyArena *arena = _PyArena_New();
	if (arena == NULL)
	{
		error("arena is NULL\n");
	}
	init_ast_data(data_ptr, arena);
	(*data_ptr)->mod = init_dummy_ast(*data_ptr);
}

void get_UAF2_ast(ast_data_t **data_ptr)
{
	PyArena *arena = _PyArena_New();
	if (arena == NULL)
	{
		error("arena is NULL\n");
	}
	init_ast_data(data_ptr, arena);
	(*data_ptr)->mod = init_UAF2(*data_ptr);
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
		INFO("retrieving dummy ast, previous size=%d\n", size);
		get_dummy_ast(data);
		return sizeof(ast_data_t *);
	}
	else
	{
		// free_ast(data);
		// get_UAF2_ast(data);
		return entry_mutate(data, max_size, seed);
	}
}

int __attribute__((visibility("default"))) LLVMFuzzerInitialize(int *argc, char ***argv)
{
	data_backup = (global_info_t *)malloc(sizeof(global_info_t));
	data_backup->ast_dump = (char *)calloc(AST_DUMP_BUF_SIZE, 1);
	Py_Initialize();
	gen_name_init();
	override_name_init();
	init_constants();
	last_case = NULL;
	if (argc != NULL && argv != NULL)
	{
		for (int i = 0; i < *argc; i++)
		{
			if (strncmp((*argv)[i], "-last-case=", strlen("-last-case=")) == 0)
			{
				INFO("Using last-case file: %s\n", (*argv)[i] + strlen("-last-case="));
				last_case = fopen((*argv)[i] + strlen("-last-case="), "r");
				if (last_case == NULL)
				{
					ERROR("failed to open last_case file\n");
				}
				break;
			}
		}
	}
	return 0;
}