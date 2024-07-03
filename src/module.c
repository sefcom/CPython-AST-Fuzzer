#include <Python.h>

static struct PyMethodDef pyFuzzerMethods[] = {
	{NULL, NULL, 0, NULL}
};

static struct PyModuleDef pyFuzzerModule = {
	PyModuleDef_HEAD_INIT, "pyFuzzer", NULL, -1, pyFuzzerMethods,
	NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit_pyFuzzer(void) {
	return PyModule_Create(&pyFuzzerModule);
}