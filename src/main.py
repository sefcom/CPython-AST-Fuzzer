import sys
import os
sys.path.insert(0, os.environ["PYTHON_PKGS_PATH"])
sys.path.insert(0, '.')


# class A:
#     def __eq__(self, other: dict):
#         # expressions below are equivalent

#         # del other["items"]

#         # this will free the original function
#         # by `decref` in `insertdict` function
#         other["items"] = 0
#         # other["items"] = []
#         # other["items"] = bytearray(100)

# # it will modify the member function in dict, and it should not?
# dict.__dict__ == A() # UAF reported by ASAN

import atheris
import pyFuzzerHelper

with atheris.instrument_imports():
    import pyFuzzerTarget

# following will crash
# re = pyFuzzerHelper.get_UAF2_ast()
# pyFuzzerHelper.dump_ast(re)
# pyFuzzerTarget.run_mod(re)
# pyFuzzerHelper.free_ast(re)

def CustomMutator(data, max_size, seed):
    if len(data) != 8:
        data = 0  # ignore invalid data
    else:
        data = int.from_bytes(data, 'little')
    if data == 0:
        # use dummy as initial case
        re = pyFuzzerHelper.get_dummy_ast().to_bytes(8, 'little')
    else:
        # TODO mutate
        pyFuzzerHelper.free_ast(data)
        re = pyFuzzerHelper.get_dummy_ast().to_bytes(8, 'little')
        # return data.to_bytes(8, 'little')
    print("re=", hex(int.from_bytes(re, 'little')))
    return re


@atheris.instrument_func  # Instrument the TestOneInput function itself
def TestOneInput(data):
    if len(data) != 8:
        # ignore invalid data
        return
    data = int.from_bytes(data, 'little')
    if data == 0:
        # let's cocked
        return
    try:
        print("data=", hex(data))
        pyFuzzerTarget.run_mod(data)
        pass
    except MemoryError as e:
        raise e
    except Exception:
        pass


if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput,
                  custom_mutator=CustomMutator, internal_libfuzzer=True)
    atheris.Fuzz()
