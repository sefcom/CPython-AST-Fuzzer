import sys, os
sys.path.insert(0, os.environ["PYTHON_PKGS_PATH"])
sys.path.insert(0, '.')
import atheris

with atheris.instrument_imports():
  import pyFuzzerHelper
  import pyFuzzerTarget

addr = pyFuzzerHelper.get_dummy_ast()
pyFuzzerHelper.dump_ast(addr)
pyFuzzerTarget.run_mod(addr)
pyFuzzerHelper.dump_ast(addr)
pyFuzzerHelper.free_ast(addr)


# def CustomMutator(data, max_size, seed):
# #   try:
# #     decompressed = zlib.decompress(data)
# #   except zlib.error:
# #     decompressed = b'Hi'
# #   else:
# #     decompressed = atheris.Mutate(decompressed, len(decompressed))
# #   return zlib.compress(decompressed)
#     pass


# @atheris.instrument_func  # Instrument the TestOneInput function itself
# def TestOneInput(data):
#   pyFuzzerTarget.run_target(data)


# if __name__ == '__main__':
#   if len(sys.argv) > 1 and sys.argv[1] == '--no_mutator':
#     atheris.Setup(sys.argv, TestOneInput)
#   else:
#     atheris.Setup(sys.argv, TestOneInput, custom_mutator=CustomMutator)
#   atheris.Fuzz()