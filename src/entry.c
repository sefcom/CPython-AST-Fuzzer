#define Py_BUILD_CORE 1
#include "Python.h"
#include "pycore_ast.h"
#include "pycore_pyarena.h"
#include "pycore_runtime.h"
#include "pycore_global_objects.h"
#include "pycore_global_strings.h"

static PyObject *run_mod(mod_ty, PyObject *, PyObject *, PyObject *,
                          PyCompilerFlags *, PyArena *);

// from pythonrun.c
int fuzzer_entry(mod_ty mod){
    Py_Initialize();
    PyArena *arena = _PyArena_New();
    if (arena == NULL) {
        return -1;
    }
    PyObject *m = PyImport_AddModuleObject(&_Py_ID(__main__));
    if (m == NULL) {
        _PyArena_Free(arena);
        return -1;
    }
    PyObject *d = PyModule_GetDict(m);
    PyCompilerFlags *flags = &_PyCompilerFlags_INIT;
    PyObject *re = run_mod(mod, PyUnicode_FromString("test.py"), d, d, flags, arena);
    _PyArena_Free(arena);
    if(re != NULL){
        Py_DECREF(re);
    }
    Py_Finalize();
}