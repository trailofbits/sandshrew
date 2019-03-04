"""
consts.py

    Contains module-level constant variables.

    TODO:
        - add ability to modify through config manager, etc.

"""
import glob
import os.path


#################
# USER
#################


# size of input/register buffers for symbolic executor to recognize
# when creating symbolic buffers. Default is 32, as most modern
# crytographic primitives work with 32 bytes
BUFFER_SIZE = 16

# compiler to use for generating preprocessed output. gcc is default,
# as it supports generating preprocessor code through -E
COMPILER = "gcc"

# name of preprocessed output C file
FUNC_FILE = "_test.c"


#################
# DEVELOPER
#################


# we provide a list of common C types to check against before
# FFI execution. This ensures that crypto lib type aliases gain
# appropriate pointer lexicon if not present in list.
C_DATATYPES = [

    # default C types - we include pointers to those
    # types as well if we ever check this list against
    # return types like "unsigned char *"
    "void",
    "int",              "int *",
    "char",             "char *",
    "short",            "short *"
    "long",             "long *",
    "unsigned int",     "unsigned int *",
    "unsigned char",    "unsigned char *",
    "unsigned short",   "unsigned short *",
    "unsigned long",    "unsigned long *",

    # commonly used type aliases
    "size_t",
    "u8",
    "u16",
    "u32",
    "i8",
    "i16",
    "i32",
    "i64"
]
