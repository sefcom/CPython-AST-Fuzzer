# Interpreter fuzzer
Combination of languages features, builtin/standard libraries, and grammar fuzzing.  

## targets
script languages, e.g.. **`Python`**, **`PHP`**, `lua`, `JavaScript`, (`sql`?)

## Background, Goals
Interpreter is not only make up by basic syntax and operations, but also by builtin modules. So our goal is to build a more comprehensive interpreter fuzzer.
We believe that there are many and comprehensive unit tests for every individual module, but we aims to test the combinations of all of those.

## pipeline
<pre>
                                                doc auto parse?
                                                        |
                                                        |
                                                        |
                                                        \/
                                                Classes definitions
                                                        |
                                                        |
                                                        |
   (possibly officially provided)                       \/
        syntax grammar tree                     language features
                |                                       |
                |                                       |
                -----------------------------------------
                                |
                                |
                                |
                                \/
                AST based mutations --------> arguments based mutations
                                |                           |
                                |                           |
                                |----------------------------
                                |
                                \/
                        Atheris w/ ASAN enabled
                                |
                                |
                                |
                                \/
                        `run_mod` run python AST directly

</pre>
## Terminology
Firstly we can just build it for a subset of the whole language. I'm planning to make a prototype with `Python` and extend to other later.

Definitions for "language features" and examples:
- standard libraries
  - memory related: `gc`, `ctypes` (may not used, because `ctypes` is designed for memory unsafe operations)
  - types and functions under libraries: `gc.collect()`
- builtin
  - types: `bytearray`, `memoryview`, `bytes`
  - functions: `__dir__`, `__dict__`, `getattr`, `setattr`
  - member functions: `bytearray.clear()`(free the buffer), `dict.keys()`, `dict.items()`
- type cast, implicit or explicit: `bytesarray()[1] = A()`(custom class to byte)
- override/overload: `__index__`, `__eq__`, `__init__` from `object`
- inheritance
- keywords:
  - life-time declaration: `nonlocal`(captured closure in python), `global`
  - life-time operations `del`(`decref` -> `free` in python)
  - structure declaration: `def`, `class`, `lambda`
- TBD

### AST or CST(concrete syntax tree)?
AST, because we don't need that many information in CST, like whitespace or etc.

## Mutation methods
- CST(concrete syntax tree) mutators
  - add life-time declaration into variables
  - add overload functions in class definition and add calling later
  - create basic/standard types instances to variables
  - define inner or global classes
  - define inner or global functions
- arguments/value mutators
  - change return value
  - normal grammar based mutations: arithmetic operations(+, -, *, /, //, %, <, >, <=, >=, ==), assigning, passing variables as arguments
- TBD

## Motivation samples
### Python
#### Sample 1 - UAF
[issue91153](https://github.com/python/cpython/issues/91153) - in wild
```python
class UAF:
        def __index__(self):
                global memory
                uaf.clear() # uaf is in captured closure
                memory = bytearray() # use-after-free
                uaf.extend([0] * 56) # bypass the length check
                return 1

uaf = bytearray(56)
uaf[23] = UAF()
# # memory is UAF right now, UAF reported by ASAN

# -- exploit --

# memory[id(20) + 24] = 114
# print(20) # = 114

```
technic required:
- class definition
- overload `__index__`
- implicit cast from custom class instance `UAF()` to byte `uaf[23]`
- `bytearray` type and its member functions
- `global` life-time declaration

#### Sample 2 - prototype pollution / UAF
[issue43838](https://bugs.python.org/issue43838) - in wild
```python
class A:
        def __eq__(self, other):
                # expressions below are equivalent

                # del other["items"]

                # this will free the original function
                # by `decref` in `insertdict` function
                other["items"] = 0
                # other["items"] = []
                # other["items"] = bytearray(100)

# it will modify the member function in dict, and it should not?
dict.__dict__ == A() # UAF reported by ASAN
# {1:1}.items() # crash

# -- exploit --
# print(dict.items) # print will fill itself into `dict.items` freed buffer
# dict.items("output\n") # equivalent to `__import__("sys").stdout.write`
# dir(dict.items) # or dir will fill itself too
# dict.items == dir

```
technic required:
- class definition
- overload `__eq__`
- `dict` type and its member function
- calling of member function `dict.items()`
- equal operator

<!--
### PHP and other
TODO
-->

## Previous works
### PyRTFuzz
title: PyRTFuzz: Detecting Bugs in Python Runtimes via Two-Level Collaborative Fuzzing, CCS'23  
[paper](https://dl.acm.org/doi/pdf/10.1145/3576915.3623166) | [design](https://github.com/awen-li/PyRTFuzz/blob/master/documents/design1.0.pdf)  
- It's architecture and idea are similar with mine.
- built on [Google atheris](https://github.com/google/atheris) and `libFuzzer`
- limitations:
  - limited language features used, only used `function`, `class`, `import`, `statement`, `global` and workflow control. Since it cannot overload functions, there is no way for it to find the UAFs listed as my motivation samples.

### Gramatron
title: Gramatron: Effective Grammar-Aware Fuzzing ISSTA'21  
[paper](https://hexhive.epfl.ch/publications/files/21ISSTA.pdf)  
- built on `AFL++`
- limitations:
  - pure grammar-based fuzzer
- TODO

## Evaluations
Coverage?
There are some disadvantages for using coverage because we may more interested on some special combinations of builtin modules and syntax which will not contribute to the coverage.

## Limitations
- no multi-threads or concurrency

## references
Comby - general languages AST parser  
[Input Algebras](https://publications.cispa.saarland/3208/7/gopinath2021input.pdf)  
[Growing A Test Corpus with Bonsai Fuzzing ICSE21](https://rohan.padhye.org/files/bonsai-icse21.pdf) - for Python  
[CodeAlchemist: Semantics-Aware Code Generation to Find Vulnerabilities in JavaScript Engines NDSS19](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_05A-5_Han_paper.pdf) - for JavaScript

\-\-\-

[Python3 syntax grammar](https://docs.python.org/3/reference/grammar.html)  
[PHP syntax grammar](https://github.com/php/php-langspec/blob/master/spec/19-grammar.md)