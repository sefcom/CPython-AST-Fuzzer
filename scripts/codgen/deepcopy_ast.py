import sys

if len(sys.argv) != 3:
    print("Usage: python deepcopy_ast.py <header> <output>")
    sys.exit(1)

TARGETS = ["expr", "stmt", "excepthandler", "pattern", "type_ignore", "type_param", "mod"]
INDIVUAL_TARGETS = ["comprehension", "arguments", "arg", "keyword", "alias", "withitem", "match_case"]

header = sys.argv[1]
with open(header, "r", encoding="utf-8") as f:
    codes_raw = f.read().strip().split("\n")

def parse_struct(start: int, codes: list[str], name: str = ""):
    parse_code = "\n"
    end = start + 1
    while not codes[end].replace(" ", "").startswith("}"):
        end += 1
    if name == "":
        name = codes[end].replace(" ", "").removeprefix("}").removesuffix(";")
    for j in range(start + 1, end):
        code = codes[j].strip().split(" ")
        n = code[1].removesuffix(";").removeprefix("*")
        t = code[0].removesuffix("_ty")
        if t == "int":
            if name is None:
                parse_code += f"re->{n} = val->{n};\n"
            else:
                parse_code += f"re->v.{name}.{n} = val->v.{name}.{n};\n"
        else:
            # print(name, t, n)
            if name is None:
                parse_code += f"re->{n} = {t}_copy(val->{n}, arena);\n"
            else:
                parse_code += f"re->v.{name}.{n} = {t}_copy(val->v.{name}.{n}, arena);\n"
    parse_code = parse_code.replace("\n", "\n" + " " * 3)
    if name is not None:
        parse_code = f"case {name}_kind:{parse_code}break;"
    return (end, parse_code)

def gen_targets(codes: list[str], target: str):
    i = 0
    while i < len(codes) and codes[i].replace(" ", "") != "struct_%s{" % target:
        i += 1
    codes = codes[i + 1:]
    i = 0
    while i < len(codes) and codes[i].replace(" ", "") != "}v;":
        i += 1
    codes = codes[:i]

    template = """%s_ty %s_copy(%s_ty val, PyArena *arena)
{
    if(val == NULL){
        return NULL;
    }
    %s_ty re = _PyArena_Malloc(arena, sizeof(struct _%s));
    re->kind = val->kind;
    switch (val->kind) {
    BODY
    }
    return re;
}""" % (target, target, target, target, target)
    
    body = ""

    i = 0
    base = 0
    while True:
        while i < len(codes) and codes[i].replace(" ", "") != "struct{":
            i += 1
        if i == len(codes):
            break
        i, code = parse_struct(i + base, codes)
        body += code + "\n"
    if(target == "stmt"):
        body += """
case Pass_kind:
case Break_kind:
case Continue_kind:
    re->lineno = val->lineno;
    re->col_offset = val->col_offset;
    re->end_lineno = val->end_lineno;
    re->end_col_offset = val->end_col_offset;
    break;
""".strip()
    body = body.replace("\n", "\n" + " " * 6)
    return template.replace("BODY", " " * 3 + body)

def gen_inidvidual_targets(codes: list[str], target: str):
    i = 0
    while i < len(codes) and codes[i].replace(" ", "") != "struct_%s{" % target:
        i += 1
    codes = codes[i:]
    i = 0
    while i < len(codes) and codes[i] != "};":
        i += 1
    codes = codes[:i + 1]
    template = """%s_ty %s_copy(%s_ty val, PyArena *arena)
{
    if(val == NULL){
        return NULL;
    }
    %s_ty re = _PyArena_Malloc(arena, sizeof(struct _%s));
    BODY
    return re;
}""" % (target, target, target, target, target)
    _, body = parse_struct(0, codes, None)
    return template.replace("BODY", " " * 3 + body)

FILE_CONTENT = "#include \"deepcopy_gen.h\"\n"
HEADER_CONTENT = "#ifndef DEEPCOPY_GEN_H\n#define DEEPCOPY_GEN_H\n\n#include \"deepcopy.h\"\n\n"

for t in TARGETS:
    FILE_CONTENT += gen_targets(codes_raw, t) + "\n"
    HEADER_CONTENT += f"{t}_ty {t}_copy({t}_ty val, PyArena *arena);\n"
for t in INDIVUAL_TARGETS:
    FILE_CONTENT += gen_inidvidual_targets(codes_raw, t) + "\n"
    HEADER_CONTENT += f"{t}_ty {t}_copy({t}_ty val, PyArena *arena);\n"

with open(sys.argv[2] + ".c", "w", encoding="utf-8") as f:
    f.write(FILE_CONTENT)
with open(sys.argv[2] + ".h", "w", encoding="utf-8") as f:
    f.write(HEADER_CONTENT + "\n#endif")
