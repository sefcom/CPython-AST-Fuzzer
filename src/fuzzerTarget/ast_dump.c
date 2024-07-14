#include "target.h"
#include <signal.h>

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
			fprintf(stderr, "Cannot import ast_module\n");
			Py_DECREF(code);
			signal(SIGABRT, SIG_DFL);
		}
	}
	if (ast_dump == NULL)
	{
		ast_dump = PyObject_GetAttrString(ast_module, "dump");
		if (ast_dump == NULL)
		{
			fprintf(stderr, "Cannot find ast_dump\n");
			Py_DECREF(code);
			Py_DECREF(ast_module);
			signal(SIGABRT, SIG_DFL);
		}
	}
	PyObject *ast_str = PyObject_CallFunctionObjArgs(ast_dump, code, NULL);
	// printf("AST=%s\n", PyUnicode_AsUTF8(ast_str));
	Py_ssize_t len;
	if (PyErr_Occurred())
	{
		PyErr_Print();
		signal(SIGABRT, SIG_DFL);
	}
	const char *str = PyUnicode_AsUTF8AndSize(ast_str, &len);
	if (len >= max_len)
	{
		fprintf(stderr, "Buffer is not enough for backup ast data for crash report\n");
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