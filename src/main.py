import sys
import os
sys.path.insert(0, os.environ["PYTHON_PKGS_PATH"])
sys.path.insert(0, '.')

import atheris
with atheris.instrument_imports():
    import pyFuzzerHelper
    import pyFuzzerTarget


def CustomMutator(data, max_size, seed):
    if len(data) != 8:
        data = 0  # ignore invalid data
    else:
        data = int.from_bytes(data, 'little')
    if data == 0:
        # use dummy as initial case
        return pyFuzzerHelper.get_dummy_ast().to_bytes(8, 'little')
    else:
        # TODO mutate
        pyFuzzerHelper.free_ast(data)
        return pyFuzzerHelper.get_dummy_ast().to_bytes(8, 'little')
        # return data.to_bytes(8, 'little')


@atheris.instrument_func  # Instrument the TestOneInput function itself
def TestOneInput(data):
    if len(data) != 8:
        # ignore invalid data
        return
    data = int.from_bytes(data, 'little')
    if data == 0:
        # let's roll
        return
    pyFuzzerTarget.run_mod(data)


if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput,
                  custom_mutator=CustomMutator, internal_libfuzzer=True)
    atheris.Fuzz()
