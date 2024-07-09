#include "helper.h"
#include "marshal.h"

PyObject *get_dummy_ast(PyObject *self, PyObject *args) {
	ast_data_t *data = (ast_data_t *)PyMem_Calloc(sizeof(ast_data_t), 1);
	data->arena = _PyArena_New();
	data->mod = init_dummy_ast(data->arena);
	return ptr2addr(data);
}

PyObject *get_UAF2_ast(PyObject *self, PyObject *args) {
	ast_data_t *data = (ast_data_t *)PyMem_Calloc(sizeof(ast_data_t), 1);
	data->arena = _PyArena_New();
	data->mod = init_UAF2(data->arena);
	return ptr2addr(data);
}

PyObject *free_ast(PyObject *self, PyObject *args) {
	PyObject *addr;
	if (!PyArg_ParseTuple(args, "O", &addr))
	{
		PyErr_SetString(PyExc_TypeError, "Invalid argument of free_ast");
		return NULL;
	}
	ast_data_t *data = (ast_data_t *)PyLong_AsVoidPtr(addr);
	_PyArena_Free(data->arena);
	PyMem_Free(data);
	// Py_DECREF(addr);
	Py_RETURN_NONE;
}

static struct PyMethodDef pyFuzzerHelperMethods[] = {
	{"get_dummy_ast", get_dummy_ast, METH_NOARGS, "Get dummy AST"},
	{"get_UAF2_ast", get_UAF2_ast, METH_NOARGS, "get UAF2 in motivated samples"},
	{"dump_ast", dump_ast, METH_VARARGS, "Dump AST"},
	{"free_ast", free_ast, METH_VARARGS, "Free AST"},
	{NULL, NULL, 0, NULL}
};

static struct PyModuleDef pyFuzzerHelperModule = {
	PyModuleDef_HEAD_INIT, "pyFuzzerHelper", NULL, -1, pyFuzzerHelperMethods,
	NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit_pyFuzzerHelper(void) {
	return PyModule_Create(&pyFuzzerHelperModule);
}