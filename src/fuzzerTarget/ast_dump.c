#include "target.h"

static PyObject *ast_module = NULL;
static PyObject *ast_dump = NULL;

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
	if (ast_dump == NULL)
	{
		ast_dump = PyObject_GetAttrString(ast_module, "dump");
		if (ast_dump == NULL)
		{
			PANIC("Cannot find ast_dump\n");
		}
	}
	PyObject *ast_str = PyObject_CallFunctionObjArgs(ast_dump, code, NULL);
	// printf("AST=%s\n", PyUnicode_AsUTF8(ast_str));
	Py_ssize_t len;
	if (PyErr_Occurred())
	{
		PyErr_Print();
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