#include "target.h"
#include "pycore_compile.h"

extern global_info_t *data_backup;

void run_mod(PyObject *code)
{
    PyObject *globals = PyEval_GetBuiltins();
    PyObject *locals = PyDict_New();
    if(PyErr_Occurred()){
        PyErr_Print();
        PANIC("Failed to create locals or globals\n");
    }
    // don't be fooled by "eval" in name, PyRun_StringFlags -> _PyRun_StringFlagsWithName -> run_mod -> run_eval_code_obj -> PyEval_EvalCode
    PyObject *result = PyEval_EvalCode(code, globals, locals);
    if(PyErr_Occurred()){
        // ignore python error
        PyErr_Print();
        // treat memory error as crash
        if(PyErr_ExceptionMatches(PyExc_MemoryError)){
            PANIC("MemoryError\n");
        }
        // INFO("AST=%s\n", data_backup->ast_dump);
    }else{
        Py_XDECREF(result); // X for null check
    }
    // NO NEED TO FREE GLOBALS
    Py_DECREF(locals);
    Py_DECREF(code);
}

void __attribute__((visibility("default"))) crash_handler(){
	ERROR("crash! saving states\n");
	char str[19];
    unsigned int hash;
    HASH_VALUE(data_backup->ast_dump, strlen(data_backup->ast_dump), hash);
	sprintf(str, "crash-%08d.py", hash % 100000000);
	FILE *f = fopen(str, "w");
	fwrite(data_backup->ast_dump, 1, strlen(data_backup->ast_dump), f);
	fclose(f);
    INFO("AST=%s\n", data_backup->ast_dump);
}

int __attribute__((visibility("default"))) LLVMFuzzerTestOneInput(const ast_data_t **data_ptr, size_t size) {
    __sanitizer_set_death_callback(crash_handler);
    if(data_ptr == NULL || size != sizeof(ast_data_t*)){
        // let's cook
        return -1;
    }
    static PyObject *fname = NULL;
    if(fname == NULL){
        fname = PyUnicode_FromString("<fuzzed>");
    }
    PyCompilerFlags flag = _PyCompilerFlags_INIT;
    PyArena *arena = _PyArena_New();
    if(arena == NULL){
        if(PyErr_Occurred()) PyErr_Print();
        PANIC("Failed to create arena\n");
    }
    PyObject *code = (PyObject *)_PyAST_Compile((*data_ptr)->mod, fname, &flag, -1, arena);
    if(code == NULL || PyErr_Occurred()){
        if(PyErr_Occurred()) PyErr_Print();
        _PyArena_Free(arena);
        ERROR("Failed to compile AST\n");
        // bad data so we will not want to add it to corpus
        return -1;
    }
    dump_ast(*data_ptr, data_backup->ast_dump, AST_DUMP_BUF_SIZE);
    // INFO("ast=%s\n", data_backup->ast_dump);
    run_mod(code);
    return 0;  // Values other than 0 and -1 are reserved for future use.
}
