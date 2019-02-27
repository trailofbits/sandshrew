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
import logging

import cffi

from elftools.elf.elffile import ELFFile

from manticore import issymbolic
from manticore.core.state import Concretize
from manticore.core.smtlib import operators
from manticore.utils import log
from manticore.native import Manticore
from manticore.native.models import strcmp
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
    print(func.__name__)
    ret = func(*args)
    return ret


def binary_arch(binary):
    """
    helper method for determining binary architecture

    :param binary: str to binary to introspect.
    :rtype bool: True for x86_64, False otherwise
    """

    # initialize pyelftools
    with open(binary, 'rb') as f:
        elffile = ELFFile(f)

    # returns true for x86_64
    if elffile['e_machine'] == 'EM_X86_64':
        return True
    elif elffile['e_machine'] == 'EM_X86':
        return False
    else:
        raise RuntimeError("unsupported target architecture for binary")


def main():
    parser = argparse.ArgumentParser(prog="sandshrew")
    required = parser.add_argument_group("required arguments")

    # test gen and analysis
    required.add_argument("-t", "--test", dest="test", required=True,
                        help="Target binary for sandshrew analysis")
    required.add_argument("-s", "--symbol", dest="symbol", required=True,
                        help="Target function symbol for equivalence analysis")
    parser.add_argument("-x", "--exopts", dest="exopts", required=False,
                        default='-Iinclude', help="Extra compilation flags for dynamic parse tree generation")

    # constraint configuration
    parser.add_argument("-c", "--constraint", dest="constraint", required=False,
                        default='ascii', help="Constraint to apply to symbolic input. \
                        Includes ascii (default), alpha, num, or alphanum")

    # debugging options
    parser.add_argument("-d", "--debug", dest="debug", action='store_true', required=False,
                        help="Turns on debugging output for sandshrew")
    parser.add_argument("--trace", dest='trace', action='store_true', required=False,
                        help="Set to execute instruction recording")


    # parse or print help
    args = parser.parse_args()
    if args is None:
        parser.print_help()
        return 0

    # initialize verbosity
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)


    # initialize Manticore
    m = Manticore.linux(args.test, ['+' * consts.BUFFER_SIZE])
    m.verbosity(2)

    # initialize mcore context manager
    m.context['sym'] = args.symbol
    m.context['argv1'] = None
    m.context['funcs'] = parse.generate_parse_tree(m.workspace, args.test + ".c", args.symbol, args.exopts)
    m.context['exec_flag'] = False

    logging.debug(f"Generated parse tree: {m.context['funcs']}")

    # initialize FFI through shared object
    obj_path = args.test + ".so"
    ffi = cffi.FFI()

    # read definitions from
    defs = parse.generate_func_prototypes(m.context['funcs'])

    # initialize ffi interaction object
    lib = ffi.dlopen(obj_path)

    # add record trace hook throughout execution
    m.context['trace'] = []

    # initialize state by constraining symbolic argv
    @m.init
    def init(initial_state):

        logging.debug(f"Creating symbolic argument using '{args.constraint}' constraint")

        # determine argv[1] from state.input_symbols by label name
        argv1 = next(sym for sym in initial_state.input_symbols if sym.name == 'ARGV1')
        if argv1 is None:
            raise RuntimeException("ARGV was not provided and/or made symbolic")

        for i in range(consts.BUFFER_SIZE):

            # apply constraint set based on user input
            if args.constraint == "alpha":
                raise NotImplementedError("alpha constraint not yet implemented")

            elif args.constraint == "num":
                initial_state.constrain(operators.AND(ord('0') <= argv1[i], argv1[i] <= ord('9')))

            elif args.constraint == "alphanum":
                raise NotImplementedError("alpha constraint not yet implemented")

            # default case: ascii
            else:
                initial_state.constrain(operators.AND(ord(' ') <= argv1[i], argv1[i] <= ord('}')))

        # store argv1 in global state
        logging.debug("Applied constraint and storing argv in context")
        with m.locked_context() as context:
            context['argv1'] = argv1


    # store a trace counter, and output if arg was set
    @m.hook(None)
    def record(state):
        pc = state.cpu.PC
        if args.trace:
            print(f"{hex(pc)}")
        with m.locked_context() as context:
            context['trace'] += [pc]


    # at target symbol, attach a hook that achieves the following:
    #   - determine and concretize symbolic registers from naming convention
    #   - gather path constraints
    @m.hook(m.resolve(m.context['sym']))
    def checker(state):
        """ checker hook that concretizes symbolic input """
        cpu = state.cpu

        with m.locked_context() as context:
            logging.debug(f"Entering target function {context['sym']}")

            # args_regs list seperate based on x86/x86_64 target arch for binary.
            if binary_arch(args.test):
                context['arg_regs'] = [('RDI', cpu.RDI), ('RSI', cpu.RSI), ('RDX', cpu.RDX)]
            else:
                context['arg_regs'] = [('EDI', cpu.EDI), ('ESI', cpu.ESI), ('EDX', cpu.EDX)]

            logging.debug(f"Arguments: {context['arg_regs']}")

            # check if arguments are symbolic in function.
            # set `exec_flag` before raising exception.
            for (arg, reg) in context['arg_regs']:
                try:
                    data = cpu.read_register(arg)
                    if issymbolic(data):
                        context['exec_flag'] = True
                        raise abstractcpu.ConcretizeRegister(cpu, arg)

                # handle ConcretizeRegister by writing value to reg
                except abstractcpu.ConcretizeRegister as e:
                    expression = cpu.read_register(e.reg_name)

                    def setstate(state, value):
                        state.cpu.write_register(setstate.e.reg_name, value)
                    setstate.e = e

                    logging.debug(f"Concretizing {arg} register")
                    raise Concretize(str(e), expression=expression,
                                     setstate=setstate, policy=e.policy)


    # for each helper function within those target symbols,
    # add concrete_hook, which enables them to be executed concretely
    # w/out the SE engine
    for n, (sym, val) in enumerate(m.context['funcs'].items()):

        # add offset in order to hook onto after functon prologue
        @m.hook(m.resolve(sym) + 4)
        def concrete_hook(state):
            """ concrete hook for non-symbolic execution through FFI """
            cpu = state.cpu

            with m.locked_context() as context:

                # flag was set, time to concolically execute!
                # we undergo the trouble of calling ffi such that our SE
                # engine can still collect path constraints with a speedup
                if context['exec_flag'] == True:

                    logging.debug(f"Concolically executing function {sym}")

                    # next_pc represents the instruction after `call sym`.
                    # we backtrack to this `call` instruction through our trace counter
                    next_pc = context['trace'][-1] + 5

                    # create concrete arg list with correctly FFI-typed inputs
                    logging.debug("Enumerating parsed args and creating FFI-compatible types")
                    arglist = []
                    for reg_num, ctype in enumerate(val['args']):

                        reg = context['arg_regs'][reg_num][1]
                        if "char" in ctype:
                            arg = ffi.new(ctype, b" ".join(cpu.read_bytes(reg, consts.BUFFER_SIZE)))
                        else:
                            arg = ffi.new(ctype, cpu.read_int(reg))

                        # append ffi arg to list
                        arglist += [arg]


                    logging.debug(f"FFI arglist: {arglist}")

                    # execute C function natively through FFI
                    logging.debug(f"Executing FFI call for {sym}")
                    ret = call_ffi(lib, sym, arglist)

                    # write return value into RAX register, and call next instruction
                    logging.debug("Writing return value to rax")
                    cpu.write_register('RAX', ret)

                    # jump to next instruction in target symbol
                    logging.debug(f"Jumping to instruction {next_pc}")
                    state.cpu.PC = next_pc


                # if flag is not set, we do not concolically execute. No symbolic input is
                # present, so as a result, there is no need to collect path constraints.
                else:
                    logging.debug("No symbolic input present, so skipping concolic testing.")


    # FIXME(alan): strcmp hooks incorrectly, some implementations such __strcmp_avx2 optimization
    # crypto comparisons should be done in strcmp. Since we are writing only test cases, we don't
    # need to rely on "constant-time comparison" implementations that may only lead to slower
    # SE runtimes.
    '''
    @m.hook(m.resolve('strcmp'))
    def strcmp_model(state):
        """ when encountering strcmp(), just execute the function model """
        logging.debug("Invoking model for `strcmp()` call")
        state.invoke_model(strcmp)
    '''


    # we finally attach a hook on the `abort` call, which must be called in the program
    # to abort from a fail/edge case path (i.e comparison b/w implementations failed), and
    # solve for the argv symbolic buffer
    @m.hook(m.resolve('abort'))
    def fail_state(state):
        """ the program must make a call to abort() in
        the edge case path. This way we can hook onto it
        with Manticore and solve for the input """

        logging.debug("Entering edge case path")

        # solve for the symbolic argv input
        with m.locked_context() as context:
            solution = state.solve_one(context['argv1'], consts.BUFFER_SIZE)
            print("Edge case found: ", solution)

        m.terminate()


    # run manticore
    m.run()

    print(f"Total instructions: {len(m.context['trace'])}\nLast instruction: {hex(m.context['trace'][-1])}")
    return 0


if __name__ == "__main__":
    main()
