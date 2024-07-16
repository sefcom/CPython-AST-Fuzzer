import sys
import inspect

def get_spec(func):
    try:
        # args, varargs , kwargs
        return list(inspect.getfullargspec(func))[:3]
    except TypeError:
        return []

if len(sys.argv) != 2:
    print("Usage: python override_func.py <output_file>")
    sys.exit(1)

codes = """
#include "HEADER"
#define GEN_ITEM(n, a, b) (overridable_func){n, PyUnicode_FromString(n), a, b, NULL}
overridable_func *overridable_funcs = NULL;
overridable_func *overridable_funcs_raw = NULL;
PyObject **builtin_clz_obj = NULL;
const int builtin_type_cnt;
builtin_clz_start
void override_name_init(){
BODY
}
"""
codes = codes.replace("HEADER", sys.argv[1].split("/")[-1] + ".h")

body = ""

obj_dict = object().__dir__()
obj_specs = [(f, get_spec(getattr(object(), f))) for f in obj_dict]

builtin_clz_start = "int builtin_clz_start[] = {\n"
builtin_clz_str = "unsigned long builtin_clz_str[] = {\n"
TARGETS = [int, float, str, list, tuple, dict, set, frozenset, bytes, bytearray]
targets_specs = {"object": obj_specs} | {type(t()).__name__: [(f, get_spec(getattr(t(), f))) for f in t().__dir__() if f not in obj_dict] for t in TARGETS}

obj_cnt = sum(len(v) for _, v in targets_specs.items())
body += f"\nbuiltin_clz_obj = malloc(sizeof(PyObject*) * {len(targets_specs.keys())});\n"
body += f"overridable_funcs_raw = malloc(sizeof(overridable_func) * {obj_cnt});\n"
i = 0
j = 0
flatten = [f for _, v in targets_specs.items() for f,_ in v]
for k, v in targets_specs.items():
    builtin_clz_start += " " * 4 + f"{i},// {k} start\n"
    builtin_clz_str += " " * 4 + f"{0},// {k}\n"
    for f, spec in v:
        if f in flatten and flatten.index(f) < i:
            body += f"overridable_funcs_raw[{i}] = overridable_funcs_raw[{flatten.index(f)}];\n"
        elif spec == []:
            body += f"overridable_funcs_raw[{i}] = GEN_ITEM(\"{f}\", 1, {0b100});\n" # self
        else:
            body += f"overridable_funcs_raw[{i}] = GEN_ITEM(\"{f}\", {len(spec[0])}, {int(spec[1] is not None) + int(spec[2] is not None) << 1 + int("self" in spec[0]) << 2});\n"
        i += 1
    body += f"builtin_clz_obj[{j}] = PyUnicode_FromString(\"{k}\");\n"
    body += f"HASH_VALUE(\"{k}\", {len(k)}, builtin_clz_str[{j}]);\n"
    j += 1
body += """
for(int i = 0; i < %d; i++){
    HASH_ADD_STR(overridable_funcs, key, overridable_funcs_raw + i);
}
""" % obj_cnt
# print(body)
body = body.replace("\n", "\n" + " " * 4)
codes = codes.replace("BODY", body)
builtin_clz_start += " " * 4 + f"{obj_cnt},// end\n"
builtin_clz_start += "};\n"
builtin_clz_str += "};\n"
builtin_clz_start += builtin_clz_str
codes = codes.replace("builtin_clz_start", builtin_clz_start)
codes = codes.replace("const int builtin_type_cnt;", f"const int builtin_type_cnt = {len(targets_specs.keys())};")

with open(sys.argv[1] + ".c", "w", encoding="utf-8") as f:
    f.write(codes)


HEADER_TEMPLATE = """
#ifndef OVERRIDE_FUNC_GEN_H
# define OVERRIDE_FUNC_GEN_H
#include "ast.h"
extern overridable_func *overridable_funcs;
extern overridable_func *overridable_funcs_raw;
extern PyObject **builtin_clz_obj;
extern const int builtin_type_cnt;
extern int builtin_clz_start[];
extern unsigned long builtin_clz_str[];
ENUM
void override_name_init();
#endif
"""

enum = "typedef enum{\n"
for k, _ in targets_specs.items():
    enum += " " * 4 + f"CLZ_{k.upper()},\n"
enum += "} builtin_clz_t;\n"
HEADER_TEMPLATE = HEADER_TEMPLATE.replace("ENUM", enum)

with open(sys.argv[1] + ".h", "w", encoding="utf-8") as f:
    f.write(HEADER_TEMPLATE)
