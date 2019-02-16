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
import os.path

import cffi

from manticore import issymbolic
from manticore.core.smtlib import operators
from manticore.native import Manticore
from manticore.native.cpu import abstractcpu

import sandshrew.parse as parse
import sandshrew.consts as consts


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


def binary_arch(binary):
    """
    helper method for determining binary architecture

    TODO

    :param binary: str to binary to introspect.
    :rtype bool: True for x86_64, False otherwise
    """
    return True


def main():
    parser = argparse.ArgumentParser(prog="sandshrew")
    required = parser.add_argument_group("required arguments")

    # test gen and analysis
    required.add_argument("-t", "--test", dest="test", required=True,
                        help="Target binary for sandshrew analysis")
    required.add_argument("-s", "--symbols", dest="symbols", required=True,
                        nargs='+', help="Target function symbol(s) for equivalence analysis")

    # debugging options
    parser.add_argument("-d", "--trace", action='store_true', required=False,
                        help="Set to execute instruction recording")
    parser.add_argument("-v", "--verbosity", dest="verbosity", required=False,
                        default=2, help="Set verbosity for Manticore (default is 2)")


    # parse or print help
    args = parser.parse_args()
    if args is None:
        parser.print_help()
        return 0


    # initialize Manticore and context manager
    m = Manticore(args.test, ['+' * consts.BUFFER_SIZE])
    m.context['syms'] = args.symbols
    m.context['funcs'] = parse.generate_parse_tree(m.workspace, args.test + ".c", args.symbols)
    m.context['argv1'] = None

    # initialize FFI through shared object
    obj_path = args.test + ".so"
    ffi = cffi.FFI()
    lib = ffi.dlopen(obj_path)

    """
    with open(m.workspace + "/" + consts.FUNC_FILE, 'rb') as cf:
        defs = cf.read()
        ffi.cdef(str(defs))
    """

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
        for i in range(consts.BUFFER_SIZE):
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

                # args_regs list seperate based on x86/x86_64
                if binary_arch(args.test):
                    arg_regs = [cpu.RDI, cpu.RSI, cpu.RDX]
                else:
                    args_regs = [cpu.EDI, cpu.ESI, cpu.EDX]

                # check if args are symbolic, and concretize if so
                for reg in arg_regs:
                    if issymbolic(reg):
                        print(f"{reg} is symbolic! Concretizing...")
                        raise abstractcpu.ConcretizeRegister(reg)

                # create concrete arg list with correctly FFI-typed inputs
                # TODO: correctly handle invalid/unknown types
                arglist = []
                for reg_num, ctype in enumerate(argtypes):
                    concrete_arg = ffi.new(ctype, state.cpu.read_bytes(arg_regs[reg_num], consts.BUFFER_SIZE))
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
            solution = state.solve_one(context['argv1'], consts.BUFFER_SIZE)
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
