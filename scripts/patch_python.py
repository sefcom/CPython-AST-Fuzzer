import pathlib
import re

symbols = [
    r"^_PyAST_(.*?)",
    r"^_Py_asdl_(.*?)",
    "PyAST_mod2obj"
]
include_h = "#include <pyport.h>"

# type func(arg, ...
FUNCTION_DEF = r"^([a-zA-Z_0-9]+)([\* ]+)([a-zA-Z_0-9]+)\(([a-zA-Z_0-9]+)([\* ]*)([a-zA-Z_0-9]*)([,)])(.*?)"

PYTHON_PATH = pathlib.Path("./cpython")
if not PYTHON_PATH.exists():
    PYTHON_PATH = pathlib.Path("../cpython")
assert PYTHON_PATH.exists(), "cpython not found"
PYTHON_INCLUDE = PYTHON_PATH / "Include"

for header in PYTHON_INCLUDE.rglob("*.h"):
    with open(header, "r", encoding="utf8") as f:
        content = f.readlines()
    patched = False
    include_stat = False
    for i in range(len(content)):  # pylint: disable=consider-using-enumerate
        extern = False
        line = content[i]
        if line.startswith("extern "):
            extern = True
            line = line.removeprefix("extern ")
        if line.startswith(include_h):
            include_stat = True
            continue
        result = re.match(FUNCTION_DEF, line)
        if result:
            for symbol in symbols:
                if re.match(symbol, result.group(3)):
                    print("exported ", result.group(3))
                    line = line.replace(result.group(1) + result.group(2), "PyAPI_FUNC(" + result.group(1) + (result.group(2) if "*" in result.group(2) else "") + ") ")
                    if extern:
                        line = "extern " + line
                    # print("new line=", line, end="")
                    content[i] = line
                    patched = True
                    break
    if patched:
        if not include_stat:
            content.insert(0, include_h + "\n")
        with open(header, "w", encoding="utf8") as f:
            f.writelines(content)
            print("patching ", header)
