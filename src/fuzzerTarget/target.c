#include "target.h"
#include "pycore_compile.h"

void run_mod(const mod_ty mod)
{
    assert(mod != NULL);
    PyObject *fname = PyUnicode_FromString("<fuzzed>");
    PyCompilerFlags flag = _PyCompilerFlags_INIT;
    PyArena *arena = _PyArena_New();
    if(arena == NULL){
        if(!PyErr_Occurred()) PyErr_SetString(PyExc_RuntimeError, "Failed to create arena");
        PyErr_Print();
    }
    PyObject *code = (PyObject *)_PyAST_Compile(mod, fname, &flag, -1, arena);
    if(PyErr_Occurred()){
        PyErr_Print();
    }
    if (code == NULL)
    {
        if(!PyErr_Occurred()) PyErr_SetString(PyExc_RuntimeError, "Failed to compile mod_ty");
        _PyArena_Free(arena);
        Py_DECREF(fname);
        PyErr_Print();
    }
    PyObject *globals = PyEval_GetBuiltins();
    PyObject *locals = PyDict_New();
    if(PyErr_Occurred()){
        PyErr_Print();
    }
    PyObject *result = PyEval_EvalCode(code, globals, locals);
    if(PyErr_Occurred()){
        PyErr_Print();
    }
    _PyArena_Free(arena);
    Py_DECREF(locals);
    Py_DECREF(fname);
    Py_DECREF(code);
    Py_DECREF(result);
}

extern const char *data_backup;

void __attribute__((visibility("default"))) crash_handler(){
	fprintf(stderr, "crash! saving states\n");
	char str[19];
    unsigned int hash = SuperFastHash(data_backup, strlen(data_backup));
	sprintf(str, "crash-%08d.txt", hash % 100000000);
	FILE *f = fopen(str, "w");
	fwrite(data_backup, 1, strlen(data_backup), f);
	fclose(f);
}

int __attribute__((visibility("default"))) LLVMFuzzerTestOneInput(const ast_data_t **data_ptr, size_t size) {
    __sanitizer_set_death_callback(crash_handler);
    if(data_ptr == NULL || size != sizeof(ast_data_t*)){
        // let's cock
        return -1;
    }
    dump_ast(*data_ptr, data_backup, 2048);
    run_mod((*data_ptr)->mod);
    return 0;  // Values other than 0 and -1 are reserved for future use.
}
