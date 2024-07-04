#include "helper.h"

PyObject *get_dummy_ast(PyObject *self, PyObject *args) {
	ast_data_t *data = (ast_data_t *)PyMem_RawMalloc(sizeof(ast_data_t));
	data->arena = _PyArena_New();
	data->mod = init_dummy_ast(&(data->arena));
	return ptr2addr(data);
}

static struct PyMethodDef pyFuzzerHelperMethods[] = {
	{"get_dummy_ast", get_dummy_ast, METH_NOARGS, "Get dummy AST"},
	{NULL, NULL, 0, NULL}
};

static struct PyModuleDef pyFuzzerHelperModule = {
	PyModuleDef_HEAD_INIT, "pyFuzzer", NULL, -1, pyFuzzerHelperMethods,
	NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit_pyFuzzerHelper(void) {
	return PyModule_Create(&pyFuzzerHelperModule);
}