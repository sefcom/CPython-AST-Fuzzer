#include "target.h"

#define Py_BUILD_CORE 1
#include "Python.h"
#include "pycore_ast.h"
#include "pycore_compile.h"
#include "pycore_global_strings.h"

PyObject *run_mod(mod_ty mod)
{
    assert(mod != NULL);
    PyObject *fname = PyUnicode_FromString("<fuzzed>");
    PyCompilerFlags flag = _PyCompilerFlags_INIT;
    PyArena *arena = _PyArena_New();
    if(arena == NULL){
        return NULL;
    }
    if(PyErr_Occurred()){
        PyErr_Print();
    }
    PyObject *code = (PyObject *)_PyAST_Compile(mod, fname, &flag, -1, arena);
    if (code == NULL)
    {
        _PyArena_Free(arena);
        Py_DECREF(fname);
        return NULL;
    }
    PyObject *result = PyEval_EvalCode(code, PyEval_GetGlobals(), PyEval_GetLocals());
    _PyArena_Free(arena);
    Py_DECREF(fname);
    Py_DECREF(code);
    return result;
}

PyObject *run_mod_py(PyObject *self, PyObject *args)
{
    PyObject *mod;
    if (!PyArg_ParseTuple(args, "O", &mod))
    {
        return NULL;
    }
    ast_data_t *data = (ast_data_t *) PyLong_AsVoidPtr(mod);
    PyObject *re = run_mod(data->mod);
    // if(re) Py_DECREF(mod);
    return re;
}

static struct PyMethodDef pyFuzzerTargetMethods[] = {
    {"run_mod", run_mod_py, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}};

static struct PyModuleDef pyFuzzerTargetModule = {
    PyModuleDef_HEAD_INIT, "pyFuzzerTarget", NULL, -1, pyFuzzerTargetMethods,
    NULL, NULL, NULL, NULL};

PyMODINIT_FUNC PyInit_pyFuzzerTarget(void)
{
    return PyModule_Create(&pyFuzzerTargetModule);
}