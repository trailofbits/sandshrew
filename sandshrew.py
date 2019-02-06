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
import subprocess

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
FUNC_FILE = "tests/_test.c"


class FuncDefVisitor(c_ast.NodeVisitor):
    """
    parent object that enables the traversal of
    functions to generate a call graph by spawning
    child visitors
    """

    def __init__(self, func_names):
        """
        :param func_names: list of target symbols
        """
        self.func_names = func_names
        self.child = FuncCallVisitor()
        super().__init__()


    def visit_FuncDef(self, node): 
        """
        method called by visit() in base class that
        spawns off child visitors for target functions

        :param node: abstract syntax tree
        """
        
        # TODO: some libraries might alias function name.
        print(node.decl.name)

        # each visitor appends to child.parse_tree
        if node.decl.name in self.func_names:
            self.child.visit(node)


class FuncCallVisitor(c_ast.NodeVisitor):

    def __init__(self):
        self.parse_tree = {}


    # TODO: recursively traverse typedef node to generate
    # type / struct with attributes
    def _expand_typedef(self, node):
        """ TODO """
        decl_copy = copy.deepcopy(node)
        return decl_copy


    def visit_FuncCall(self, node):
        """
        method called by visit() in base class that
        enables us to traverse node to extract function
        call parameters

        :param node: abstract syntax tree
        """

        args = []

        for param in node.decl.type.args.params:

            # check if param is pointer type
            if type(param.type) is c_ast.PtrDecl:

                # pointer to pointer type - awkward attributes result of
                # indirection
                if type(param.type.type) is c_ast.PtrDecl:
                    ptype = param.type.type.type.type.names
                else:
                    ptype = param.type.type.type.names

            # TODO: check if function pointer; also traverse??

            # check if type alias
            elif type(param.type.type) is c_ast.TypeDecl:
                ptype = param.type.type.type.names

            # else, a regular non-pointer type
            elif type(param.type.type) is c_ast.IdentifierType:
                ptype = param.type.type.names

            args += ptype

        # append result to parse tree
        self.parse_tree[node.decl.name] = args



def generate_parse_tree(filename, funcs):
    """
    helper method that generates a parse tree of
    all functions within a target function

    :param filename: C file to generate AST
    :param funcs: list of functions to extract call graph
    :rtype: dict

    TODO: parse additional compiler flags
    """

    # run a subprocess commmand to initialize a _test.c file with all function definitions from linked
    # libraries. pycparser can only reason if headers are preprocessed correctly.
    with open(FUNC_FILE, 'w+') as out:
        subprocess.call(['gcc', '-nostdinc', '-E', '-Iinclude', '-Iutils/fake_libc_include', filename],
                          stdout=out, stderr=subprocess.STDOUT)

    # use pycparser to generate an AST from the generated intermediate C file
    ast = pycparser.parse_file(FUNC_FILE)

    # spawn off call graph visitor
    parent = FuncDefVisitor(funcs)
    parent.visit(ast)
    print(parent.child.parse_tree)
    return parent.child.parse_tree


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
        return 0

    # initialize FFI through shared object
    obj = args.binary + ".so"
    obj_path = os.path.dirname(os.path.abspath(__file__)) + os.path.sep + obj
    ffi = cffi.FFI()
    lib = ffi.dlopen(obj_path)


    # initialize Manticore and context manager
    m = Manticore(args.binary, ['+' * BUFFER_SIZE])
    m.context['syms'] = args.symbols
    m.context['funcs'] = generate_parse_tree(args.binary + ".c", args.symbols)
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

        print("Constraining symbolic argument")

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
                        print(f"{reg} is symbolic! Concretizing...")
                        raise abstractcpu.ConcretizeRegister(reg)

                # create concrete arg list with correctly FFI-typed inputs
                # TODO: correctly handle invalid/unknown types
                arglist = []
                for reg_num, ctype in enumerate(argtypes):
                    concrete_arg = ffi.new(ctype, state.cpu.read_bytes(arg_regs[reg_num], BUFFER_SIZE))
                    print(concrete_arg)
                    arglist.push(concrete_arg)

                # execute C function natively through FFI
                call_ffi(lib, sym, argtypes)

                # TODO: get return value, re-symbolicate


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

    return 0

if __name__ == "__main__":
    main()
