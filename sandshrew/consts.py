"""
consts.py
    
    TODO: refactor out
"""

# size of input/register buffers for symbolic executor to recognize
# when creating symbolic buffers. Default is 32, as most modern
# crytographic primitives work with 32 bytes
BUFFER_SIZE = 32

# default prepend symbol to recognize primitives that require
# concretize
PREPEND_SYM = "SANDSHREW_"
