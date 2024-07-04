from lief import ELF
import sys, pathlib, os

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: {} <python root path> <out path>".format(sys.argv[0]))
        sys.exit(1)

PYTHON_PATH = pathlib.Path(sys.argv[1]).joinpath("lib/libpython3.11.so.1.0")
OUT_FOLDER = pathlib.Path(sys.argv[2])
assert PYTHON_PATH.exists(), "python lib not found"
print("patching python lib path:", PYTHON_PATH)

elf = ELF.parse(PYTHON_PATH.absolute().as_posix())

# make existing symbol dynamic
dyn_sym_name = [s.name for s in elf.dynamic_symbols]
for symbol in elf.symbols:
    print(symbol.name)
    if symbol.name.startswith("_PyAST") and symbol.name not in dyn_sym_name:
        print("patching symbol:", symbol.name)
        # elf.add_dynamic_symbol(symbol, ELF.SymbolVersion.global_)
        elf.add_exported_function(symbol.value, symbol.name)

OUT_FOLDER.mkdir(parents=True, exist_ok=True)
elf.write(OUT_FOLDER.joinpath(PYTHON_PATH.name).as_posix())