#define Py_BUILD_CORE 1
#include "Python.h"
#include "pycore_ast.h"
#include "pycore_pyarena.h"
#include "pycore_runtime.h"
#include "pycore_global_objects.h"
#include "pycore_global_strings.h"

typedef enum
{
  STRING,
  NUMBER
} python_obj_kind_t;

typedef struct
{
  python_obj_kind_t kind;
  size_t offset;
  union
  {
    size_t number;
    const char *string;
  } val;
} python_obj_t;

// patched in ./cpython/Python/pythonrun.c for AST execution
extern PyObject *(*run_mod_fuzzer)(mod_ty, PyObject *, PyObject *, PyObject *,
                                   PyCompilerFlags *, PyArena *);

PyObject **recover_python_objs(void *buf, size_t len)
{
  size_t size = *(size_t *)(buf + len - sizeof(size_t));
  PyObject **objs = calloc(size / sizeof(python_obj_t) + 1, sizeof(PyObject *));
  python_obj_t *obj_head = (python_obj_t *)(buf + len - sizeof(size_t) - size);
  for (size_t i = 0; i < size / sizeof(python_obj_t); i++)
  {
    python_obj_t *obj = obj_head + i;
    switch (obj->kind)
    {
    case STRING:
      objs[i] = PyUnicode_FromString(obj->val.string);
      break;
    case NUMBER:
      objs[i] = PyLong_FromSize_t(obj->val.number);
      break;
    }
    (PyObject **)(buf + obj->offset) = objs[i];
  }
  return objs;
}

// from pythonrun.c
int fuzzer_entry(mod_ty mod, size_t len)
{
  Py_Initialize();
  PyArena *arena = _PyArena_New();
  if (arena == NULL)
  {
    return -1;
  }
  PyObject *m = PyImport_AddModuleObject(&_Py_ID(__main__));
  if (m == NULL)
  {
    _PyArena_Free(arena);
    return -1;
  }

  PyObject **objs = recover_python_objs(mod, len);
  
  PyObject *d = PyModule_GetDict(m);
  PyCompilerFlags *flags = &_PyCompilerFlags_INIT;
  PyObject *file_name = PyUnicode_FromString("test.py");
  PyObject *re = run_mod_fuzzer(mod, file_name, d, d, flags, arena);
  _PyArena_Free(arena);
  if (re != NULL)
  {
    Py_DECREF(re);
  }
  Py_DECREF(file_name);
  while(*objs)
  {
    Py_DECREF(*objs);
    objs++;
  }
  free(objs);
  Py_Finalize();
}

__AFL_FUZZ_INIT();

int main()
{

  // anything else here, e.g. command line arguments, initialization, etc.
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  mod_ty buf = __AFL_FUZZ_TESTCASE_BUF; // must be after __AFL_INIT
                                        // and before __AFL_LOOP!

  while (__AFL_LOOP(10000))
  {

    int len = __AFL_FUZZ_TESTCASE_LEN; // don't use the macro directly in a
                                       // call!

    if (len == 0)
      continue; // check for a required/useful minimum input length

    /* Setup function call, e.g. struct target *tmp = libtarget_init() */
    /* Call function to be fuzzed, e.g.: */
    fuzzer_entry(buf, len);
    /* Reset state. e.g. libtarget_free(tmp) */
  }

  return 0;
}