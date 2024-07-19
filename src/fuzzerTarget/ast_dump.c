#include "target.h"

static PyObject *ast_module = NULL;
static PyObject *ast_dump_func = NULL;
static PyObject *ast_dump_func_fallback = NULL;
static PyObject *ast_load_func = NULL;

int init_statics()
{
	if (ast_module == NULL)
	{
		ast_module = PyImport_ImportModule("ast");
		if (ast_module == NULL)
		{
			PANIC("Cannot import ast_module\n");
		}
	}
	if (ast_dump_func == NULL)
	{
		ast_dump_func = PyObject_GetAttrString(ast_module, "unparse");
		if (ast_dump_func == NULL)
		{
			PANIC("Cannot find ast_dump\n");
		}
	}
	if (ast_dump_func_fallback == NULL)
	{
		ast_dump_func_fallback = PyObject_GetAttrString(ast_module, "dump");
		if (ast_dump_func_fallback == NULL)
		{
			PANIC("Cannot find ast_dump_fallback\n");
		}
	}
	if (ast_load_func == NULL)
	{
		ast_load_func = PyObject_GetAttrString(ast_module, "parse");
		if (ast_load_func == NULL)
		{
			PANIC("Cannot find ast_load\n");
		}
	}
	return 0;
}

int dump_ast(const ast_data_t *data, char *buf, size_t max_len)
{
	PyObject *code = PyAST_mod2obj(data->mod);
	if (code == NULL)
	{
		PANIC("Failed to convert mod to code\n");
		return -1;
	}
	init_statics();
	// Warning Trying to unparse a highly complex expression would result with RecursionError.
	PyObject *ast_str = PyObject_CallOneArg(ast_dump_func, code);
	// printf("AST=%s\n", PyUnicode_AsUTF8(ast_str));
	Py_ssize_t len;
	if (PyErr_Occurred())
	{
		PyErr_Print();
		PyErr_Clear();
		ast_str = PyObject_CallOneArg(ast_dump_func_fallback, code);
		if (PyErr_Occurred())
		{
			PyErr_Print();
			PANIC("Failed to dump ast\n");
		}
	}
	if (ast_str == NULL)
	{
		PANIC("Failed to dump ast\n");
	}
	const char *str = PyUnicode_AsUTF8AndSize(ast_str, &len);
	if (len >= max_len)
	{
		ERROR("Buffer is not enough for backup ast data for crash report\n");
		Py_DECREF(code);
		Py_DECREF(ast_str);
		return -1;
	}
	else
	{
		memcpy(buf, str, len);
		buf[len] = '\0';
	}
	// Py_DECREF(addr);
	Py_DECREF(code);
	Py_DECREF(ast_str);
	return 0;
}

mod_ty load_ast(ast_data_t *data, const char *buf)
{
	init_statics();
	PyObject *ast_str = PyUnicode_FromString(buf);
	PyObject *code = PyObject_CallOneArg(ast_load_func, ast_str);
	if (code == NULL)
	{
		PANIC("Failed to load ast\n");
		return NULL;
	}
	// 0 for exec
	mod_ty mod = PyAST_obj2mod(code, data->arena, 0);
	Py_DECREF(ast_str);
	assert(!(mod == NULL || !_PyAST_Validate(mod)));
	return mod;
}