#include "target.h"

void dump_ast(const ast_data_t *data, char *buf, size_t max_len)
{
	PyObject *code = PyAST_mod2obj(data->mod);
	if (code == NULL)
	{
		return;
	}
	PyObject *ast_module = PyImport_ImportModule("ast");
	if (ast_module == NULL)
	{
		fprintf(stderr, "ast_module\n");
		Py_DECREF(code);
		return;
	}
	PyObject *ast_dump = PyObject_GetAttrString(ast_module, "dump");
	if (ast_dump == NULL)
	{
		fprintf(stderr, "ast_dump\n");
		Py_DECREF(code);
		Py_DECREF(ast_module);
		return;
	}
	PyObject *ast_str = PyObject_CallFunctionObjArgs(ast_dump, code, NULL);
	// printf("AST=%s\n", PyUnicode_AsUTF8(ast_str));
	Py_ssize_t len;
	const char *str = PyUnicode_AsUTF8AndSize(ast_str, &len);
	if(len >= max_len){
		fprintf(stderr, "Buffer is not enough for backup ast data for crash report\n");
	}else{
		memcpy(buf, str, len);
		buf[len] = '\0';
	}
	if(PyErr_Occurred()){
		PyErr_Print();
		return;
	}
	// Py_DECREF(addr);
	Py_DECREF(code);
	Py_DECREF(ast_module);
	Py_DECREF(ast_dump);
	Py_DECREF(ast_str);
}