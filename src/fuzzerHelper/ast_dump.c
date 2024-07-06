#include "helper.h"

PyObject *dump_ast(PyObject *self, PyObject *args)
{
	PyObject *addr;
	if (!PyArg_ParseTuple(args, "O", &addr))
	{
		return NULL;
	}
	ast_data_t *data = (ast_data_t *)PyLong_AsVoidPtr(addr);
	PyObject *code = PyAST_mod2obj(data->mod);
	if (code == NULL)
	{
		Py_DECREF(addr);
		return NULL;
	}
	PyObject *ast_module = PyImport_ImportModule("ast");
	if (ast_module == NULL)
	{
		Py_DECREF(addr);
		Py_DECREF(code);
		return NULL;
	}
	PyObject *ast_dump = PyObject_GetAttrString(ast_module, "dump");
	if (ast_dump == NULL)
	{
		Py_DECREF(addr);
		Py_DECREF(code);
		Py_DECREF(ast_module);
		return NULL;
	}
	PyObject *ast_str = PyObject_CallFunctionObjArgs(ast_dump, code, NULL);
	printf("AST=%s\n", PyUnicode_AsUTF8(ast_str));
	Py_DECREF(addr);
	Py_DECREF(code);
	Py_DECREF(ast_module);
	Py_DECREF(ast_dump);
	Py_DECREF(ast_str);
	return code;
}