"""
consts.py

    Contains module-level constant variables.
    
    TODO:
        - better annotation / documentation
        - add ability to modify through config manager, etc.

"""
import glob
import os.path


BUFFER_SIZE = 32

HEADERS = glob.glob(
     os.path.join(os.path.abspath(os.path.dirname(__file__)), "include/*.h")
)

COMPILER = "clang"

FUNC_FILE = "_test.c"
