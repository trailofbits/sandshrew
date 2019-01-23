#!/usr/bin/env python3
"""
sandshrew.py

    Unconstrained concolic execution tool for cryptographic verification

    METHODOLOGY:
    ============
    1. Generate parse tree of helper functions
    called by target function.
    Contain: funcname, argtypes, rtype

    2. During SE run, symbolicate func arguments
    for target function.

    3. Attach hooks to helper functions for concrete
    execution through FFI

"""
import argparse
import glob
import os.path

import cffi
import pycparser

from pycparser import c_ast
from manticore import issymbolic
from manticore.core.smtlib import operators
from manticore.native import Manticore
from manticore.native.cpu import abstractcpu

# TODO: move to seperate file
BUFFER_SIZE = 32
HEADERS = glob.glob(
    os.path.join(os.path.abspath(os.path.dirname(__file__)), "include/*.h")
)


class FuncDefVisitor(c_ast.NodeVisitor):
    """ object for traversing C AST nodes and
    generating a function parse tree """

    def __init__(self, funcname):
        self.funcname = funcname
        self.parse_tree = {}

    def visit_FuncDef(self, node):

        # retrieve function parameters
        func_params = node.decl.type.args.params

        # parse out functions appropriately
        param_list = []
        for params in func_params:

            # check if type is pointer declaration
            if type(params.type) == c_ast.PtrDecl:

                # awkward attributes because of single indirection
                ptype = params.type.type.type.names

            # else parameter is variable
            elif type(params.type.type) == c_ast.IdentifierType:
                ptype = params.type.type.names

            param_list.append(ptype)

        # append to parse tree
        self.parse_tree[node.decl.name] = param_list


def generate_parse_tree(filename, func):
    """ 
    helper method that generates a parse tree of 
    all functions within a target function

    :param filename: C file to generate AST
    :param func: name of target function to generate AST
    :rtype: dict
    """
    ast = pycparser.parse_file(filename,
                               use_cpp=True, cpp_path='gcc',
                               cpp_args=['-Iinclude', r'-Iutils/fake_libc_include'])
    v = FuncDefVisitor(func)
    v.visit(ast) # TODO: correct this!
    return v.parse_tree


def call_ffi(lib, funcname, args):
    """ 
    safe wrapper to calling C library
    functions through cffi  
    
    :param lib: cffi.FFI object to interact with
    :param funcname: name of target function to concretize
    :param args: list of arguments passed to function
    """
    func = lib.__getattr__(funcname)
    func(*args)


# TODO: get binary arch to determine proper reg calling convention
# when executing through FFI
def binary_arch():
    """ TODO """
    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--binary", dest="binary", required=True,
                        help="Target ELF binary for symbolic execution")
    parser.add_argument("-s", "--symbols", dest="symbols", required=True,
                        nargs='+', help="Target function symbols for equivalence analysis")
    parser.add_argument("-t", "--trace", action='store_true', required=False,
                        help="Set to execute instruction recording")
    parser.add_argument("-v", "--verbosity", dest="verbosity", required=False,
                        default=2, help="Set verbosity for Manticore (default is 2)")

    # parse or print help
    args = parser.parse_args()
    if args is None:
        parser.print_help()


    # initialize FFI through shared object
    obj = args.binary + ".so"
    obj_path = os.path.dirname(os.path.abspath(__file__)) + os.path.sep + obj
    ffi = cffi.FFI()
    lib = ffi.dlopen(obj_path)


    # initialize Manticore and context manager
    m = Manticore(args.binary, ['+' * BUFFER_SIZE])
    m.context['syms'] = args.symbols
    m.context['funcs'] = generate_parse_tree(args.binary + ".c", m.context['syms'])
    m.context['argv1'] = None


    # add record trace hook throughout execution if specified by user
    if args.trace:
        m.context['trace'] = []
        
        @m.hook(None)
        def record(state):
            pc = state.cpu.PC
            print(f"{hex(pc)}")
            with m.locked_context() as context:
                context['trace'] += [pc]


    # initialize state by constraining symbolic argv
    @m.init
    def init(initial_state):

        # determine argv[1] from state.input_symbols by label name
        argv1 = next(sym for sym in initial_state.input_symbols if sym.name == 'ARGV1')
        if argv1 is None:
            raise RuntimeException("ARGV was not provided and/or made symbolic")

        # apply constraint for only ASCII characters
        for i in range(BUFFER_SIZE):
            initial_state.constrain(operators.AND(ord(' ') <= argv1[i], argv1[i] <= ord('}')))

            # store argv1 in global state
            with m.locked_context() as context:
                context['argv1'] = argv1


    # at target symbols, attach checker hooks that error-checks
    # and tracks our symbolic inputs
    for n, sym in enumerate(m.context['syms']):

        # NOTE: if pycparser is unreliable, use this checker hook in order to
        # do a concrete run and gen parse tree instead during its run (??)
        @m.hook(m.resolve(sym))
        def checker(state):
            """ TODO """
            with m.locked_context('syms', list) as syms:
                print(f"Entering target function {syms[n]}")


    # for each helper function within those target symbols,
    # add concrete_hook, which enables them to be executed concretely
    # w/out the SE engine
    for n, (sym, argtypes) in enumerate(m.context['funcs'].items()):

        @m.hook(m.resolve(sym))
        def concrete_hook(state):
            """ concrete hook for non-symbolic execution through FFI """
            cpu = state.cpu

            with m.locked_context() as context:

                print(f"Concretely executing function {sym}")

                # TODO: args_regs list seperate based on x86/x86_64
                arg_regs = [cpu.RDI, cpu.RSI, cpu.RDX]

                # check if args are symbolic, and concretize if so
                for reg in arg_regs:
                    if issymbolic(reg):
                        raise abstractcpu.ConcretizeRegister(reg)

                # create concrete arg list with correctly FFI-typed inputs
                arglist = []
                for reg_num, ctype in enumerate(argtypes):
                    concrete_arg = ffi.new(ctype, state.cpu.read_bytes(arg_regs[reg_num]))
                    arglist.push(concrete_arg)

                # execute C function natively through FFI
                call_ffi(lib, sym, argtypes)


    # we finally attach a hook on the `abort` call, which must be called in the program
    # to abort from a fail/edge case path (i.e comparison b/w implementations failed), and
    # solve for the argv symbolic buffer 
    @m.hook(m.resolve('abort'))
    def fail_state(state):
        """ the program must make a call to abort() in 
        the edge case path. This way we can hook onto it
        with Manticore and solve for the input """

        print("Entering edge case path")
       
        # solve for the symbolic argv input
        with m.locked_context() as context:
            solution = state.solve_one(context['argv1'], BUFFER_SIZE)
            print("Edge case found: ", solution)
        
        m.terminate()


    # run manticore
    m.verbosity(args.verbosity)
    m.run()

    # output if arg is set
    if args.trace:
        print(f"Total instructions: {len(m.context['trace'])}\nLast instruction: {hex(m.context['trace'][-1])}")


if __name__ == "__main__":
    main()
