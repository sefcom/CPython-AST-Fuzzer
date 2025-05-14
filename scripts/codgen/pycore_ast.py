import pathlib
from glob import glob
import re
import sys


def extract_enum_kinds(source):
    enums = {}
    for match in re.finditer(r"enum (\w+_kind)\s*\{([^}]+)\};", source):
        enum_name = match.group(1)
        body = match.group(2)
        values = re.findall(r"\b(\w+_kind)\b", body)
        enums[enum_name] = values
    return enums


def extract_pyast_constructors(source):
    constructors = []
    pattern = re.compile(r"PyAPI_FUNC\((\w+_ty)\)\s+(_PyAST_\w+)\s*\(([^)]*)\);")
    for match in pattern.finditer(source):
        return_type = match.group(1)
        name = match.group(2)
        args = [
            a.strip()
            for a in match.group(3)
            .strip()
            .replace("\\\n", "")
            .replace("\n", " ")
            .split(",")
        ]
        constructors.append({"return_type": return_type, "name": name, "args": args})
    return constructors


HEADER_PATH = "cpython_bin/include/python*/internal/pycore_ast.h"
HEADER_PATH = glob(HEADER_PATH)[0]
HEADER_PATH = pathlib.Path(HEADER_PATH).resolve()

FUNC_TEMPLATE = """
%s default%s(ast_data_t *data){
    return %s(%s);
}
"""

header_content = """
#ifndef DEFAULT_GEN_H
#define DEFAULT_GEN_H

#include "common.h"

typedef enum Node_kind {
   %s
} Node_kind_t;

extern int table_size[];

extern void(** implementation_tables[])(ast_data_t *);

#endif
""".strip()
source_content = """
#include "default_gen.h"
#include "default.h"

int table_size[] = {%s};
""".strip()


if len(sys.argv) != 2:
    print("Usage: python pycore_ast.py <output_file>")
    sys.exit(1)

print("parse from", HEADER_PATH)

with open(HEADER_PATH, "r") as f:
    source = f.read()
    enums = extract_enum_kinds(source)

enums.pop("_mod_kind")
constructors = extract_pyast_constructors(source)
# make a C style dict, enum -> function pointers
implementation_tables = {}
for enum_name, _ in enums.items():
    implementation_tables[enum_name] = [
        constructor
        for constructor in constructors
        if enum_name.removeprefix("_").removesuffix("_kind")
        in constructor["return_type"]
    ]

source_content = source_content % (
    (", ".join([str(len(v)) for v in implementation_tables.values()])).removesuffix(",")
)

header_content = header_content % (
    "\n   ".join([f"{name} = {i}," for i, name in enumerate(enums.keys())]),
)
for enum_name, functions in implementation_tables.items():
    for func in functions:
        args = ""
        for a in func["args"]:
            # remove abundant spaces
            a = " ".join(a.strip().split()).split(" ")
            if a[1][0] == "*":
                if a[0] == "PyArena":
                    args += "data->arena, "
                else:
                    args += f"default_{a[0]}_ptr(data), "
            else:
                args += f"default_{a[0]}(data), "
        source_content += FUNC_TEMPLATE % (
            func["return_type"],
            func["name"],
            func["name"],
            args.removesuffix(", "),
        )
    source_content += """
void(* %s_funcs[])(ast_data_t *) = {
   %s
};
""" % (
        enum_name,
        "\n   ".join([f"(void *)default{name['name']}," for name in functions]).removesuffix(
            ","
        ),
    )

source_content += """
void(** implementation_tables[])(ast_data_t *) = {
   %s
};
""" % (
    "\n   ".join([f"{name}_funcs," for name in enums.keys()]).removesuffix(",")
)

with open(sys.argv[1] + ".c", "w") as f:
    f.write(source_content)
with open(sys.argv[1] + ".h", "w") as f:
    f.write(header_content)
