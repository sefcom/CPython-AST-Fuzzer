#include "target.h"

static PyObject *ast_module = NULL;
static PyObject *ast_dump_func = NULL;
static PyObject *ast_dump_func_fallback = NULL;

void dump_ast(const ast_data_t *data, char *buf, size_t max_len)
{
	PyObject *code = PyAST_mod2obj(data->mod);
	if (code == NULL)
	{
		return;
	}
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
	if(ast_dump_func_fallback == NULL)
	{
		ast_dump_func_fallback = PyObject_GetAttrString(ast_module, "dump");
		if (ast_dump_func_fallback == NULL)
		{
			PANIC("Cannot find ast_dump_fallback\n");
		}
	}
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
	if(ast_str == NULL){
		PANIC("Failed to dump ast\n");
	}
	const char *str = PyUnicode_AsUTF8AndSize(ast_str, &len);
	if (len >= max_len)
	{
		ERROR("Buffer is not enough for backup ast data for crash report\n");
	}
	else
	{
		memcpy(buf, str, len);
		buf[len] = '\0';
	}
	// Py_DECREF(addr);
	Py_DECREF(code);
	Py_DECREF(ast_str);
}