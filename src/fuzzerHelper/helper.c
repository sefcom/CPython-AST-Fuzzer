#include "helper.h"
#include "marshal.h"

PyObject *get_dummy_ast(PyObject *self, PyObject *args) {
	ast_data_t *data = (ast_data_t *)PyMem_RawMalloc(sizeof(ast_data_t));
	data->arena = _PyArena_New();
	data->mod = init_dummy_ast(&(data->arena));
	return ptr2addr(data);
}

PyObject *free_ast(PyObject *self, PyObject *args) {
	PyObject *addr;
	if (!PyArg_ParseTuple(args, "O", &addr))
	{
		return NULL;
	}
	ast_data_t *data = (ast_data_t *)PyLong_AsVoidPtr(addr);
	_PyArena_Free(data->arena);
	PyMem_RawFree(data);
	Py_DECREF(addr);
	Py_RETURN_NONE;
}

static struct PyMethodDef pyFuzzerHelperMethods[] = {
	{"get_dummy_ast", get_dummy_ast, METH_NOARGS, "Get dummy AST"},
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