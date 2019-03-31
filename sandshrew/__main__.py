#!/usr/bin/env python3
"""
sandshrew.py

    Unconstrained concolic execution tool for cryptographic verification

"""
import random
import string
import argparse
import os.path
import logging

from manticore import issymbolic
from manticore.core.smtlib import operators
from manticore.native import Manticore
from manticore.native.models import strcmp
from manticore.utils.fallback_emulator import UnicornEmulator

import sandshrew.utils as utils
import sandshrew.consts as consts


def main():
    parser = argparse.ArgumentParser(prog="sandshrew")

    # required arg group for help display
    required = parser.add_argument_group("required arguments")
    required.add_argument("-t", "--test", dest="test", required=True,
                        help="Target binary for sandshrew analysis")

    # constraint configuration
    parser.add_argument("-c", "--constraint", dest="constraint", required=False,
                        help="Constraint to apply to symbolic input. Includes ascii, alpha, num, or alphanum")

    # debugging options
    parser.add_argument("--debug", dest="debug", action="store_true", required=False,
                        help="If set, turns on debugging output for sandshrew")
    parser.add_argument("--trace", dest="trace", action="store_true", required=False,
                        help="If set, trace instruction recording will be outputted to logger")
    parser.add_argument("--no-concolic", dest="no_concolic", action="store_true", required=False,
                        help="If set, no concretization will be performed")

    # other configuration settings
    parser.add_argument("--cmpsym", dest="cmp_sym", default="__strcmp_ssse3", required=False,
                        help="Overrides comparison function used to test for equivalence (default is strcmp)")

    # parse or print help
    args = parser.parse_args()
    if args is None:
        parser.print_help()
        return 0

    # initialize verbosity
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    # check binary arch support for x86_64
    if not utils.binary_arch(args.test):
        raise NotImplementedError("sandshrew only supports x86_64 binary concretization")

    # initialize Manticore
    m = Manticore.linux(args.test, ['+' * consts.BUFFER_SIZE])
    m.verbosity(2)

    # initialize mcore context manager
    m.context['syms'] = utils.binary_symbols(args.test)
    m.context['exec_flag'] = False
    m.context['argv1'] = None

    logging.debug(f"Functions for concretization: {m.context['syms']}")

    # add record trace hook throughout execution
    m.context['trace'] = []

    # initialize state by checking and storing symbolic argv
    @m.init
    def init(initial_state):

        logging.debug(f"Checking for symbolic ARGV")

        # determine argv[1] from state.input_symbols by label name
        argv1 = next(sym for sym in initial_state.input_symbols if sym.name == 'ARGV1')
        if argv1 is None:
            raise RuntimeException("ARGV was not provided and/or made symbolic")

        # store argv1 in global state
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


    for sym in m.context['syms']:

        @m.hook(m.resolve("SANDSHREW_" + sym))
        def concrete_checker(state):
            """
            initial checker hook for SANDSHREW_sym that checks for the presence of symbolic input.
            If so, an unconstrained hook is attached to the memory location to restore symbolic state after concretization
            """
            cpu = state.cpu

            with m.locked_context() as context:
                logging.debug(f"Entering target function SANDSHREW_{sym} at {hex(state.cpu.PC)}")

                # check if RSI, the assumed input arg, is symbolic
                data = cpu.read_int(cpu.RSI)
                if issymbolic(data):
                    logging.debug(f"Symbolic input parameter to function {sym}() detected")

                    # store instruction after `call SANDSHREW_*`
                    return_pc = context['trace'][-1] + 5

                    # attach a hook to the return_pc, as this is where we will perform concolic execution
                    @m.hook(return_pc)
                    def unconstrain_hook(state):
                        """
                        unconstrain_hook writes unconstrained symbolic data to the memory location of the output.
                        """
                        with m.locked_context() as context:

                            # output param is RDI, symbolicate RAX
                            context['return_addr'] = cpu.RAX
                            logging.debug(f"Writing unconstrained buffer to output memory location")

                            # initialize unconstrained symbolic input
                            return_buf = state.new_symbolic_buffer(consts.BUFFER_SIZE)

                            # apply charset constraints based on user input
                            for i in range(consts.BUFFER_SIZE):

                                if args.constraint == "alpha":
                                    state.constrain(operators.OR(
                                            operators.AND(ord('A') <= return_buf[i], return_buf[i] <= ord('Z')),
                                            operators.AND(ord('a') <= return_buf[i], return_buf[i] <= ord('z'))
                                    ))

                                elif args.constraint == "num":
                                    state.constrain(operators.AND(ord('0') <= return_buf[i], return_buf[i] <= ord('9')))

                                elif args.constraint == "alphanum":
                                    raise NotImplementedError("alphanum constraint set not yet implemented")

                                elif args.constraint == "ascii":
                                    state.constrain(operators.AND(ord(' ') <= return_buf[i], return_buf[i] <= ord('}')))

                            # write to address
                            state.cpu.write_bytes(context['return_addr'], return_buf)


        @m.hook(m.resolve(sym))
        def concolic_hook(state):
            """
            hook used in order to concretize the execution of a `call <sym>` instruction
            """
            cpu = state.cpu

            with m.locked_context() as context:

                # store `call sym` instruction and ret val instruction
                call_pc = context['trace'][-1]

                # we are currently in the function prologue of `sym`. Let's go back to `call sym`.
                state.cpu.PC = call_pc

                # use the fallback emulator to concretely execute call instruction.
                logging.debug(f"Concretely executing `call <{sym}>` at {hex(call_pc)}")
                state.cpu.decode_instruction(state.cpu.PC)
                emu = UnicornEmulator(state.cpu)
                emu.emulate(state.cpu.instruction)

                logging.debug("Continuing with Manticore symbolic execution")

    '''
    # TODO(alan): resolve ifunc (different archs use different optimized implementations)
    @m.hook(m.resolve(args.cmp_sym))
    def cmp_model(state):
        """
        used in order to invoke Manticore function model for strcmp and/or other comparison operation
        calls. While a developer can write a test case using a crypto library's built in
        constant-time comparison operation, it is preferable to use strcmp().
        """
        logging.debug("Invoking model for comparsion call")
        state.invoke_model(strcmp)
    '''

    @m.hook(m.resolve('abort'))
    def fail_state(state):
        """
        hook attached at fail state signified by abort call, which indicates that an edge case
        input is provided and the abort() call is made
        """

        logging.debug("Entering edge case path")

        # solve for the symbolic argv input
        with m.locked_context() as context:
            solution = state.solve_one(context['return_addr'], consts.BUFFER_SIZE)
            print(f"Solution found: {solution}")

            # write solution to individual test case to workspace
            rand_str = lambda n: ''.join([random.choice(string.ascii_lowercase) for i in range(n)])
            with open(m.workspace + '/' + 'sandshrew_' + rand_str(4), 'w') as fd:
                fd.write(str(solution))

        m.terminate()


    # run manticore
    m.run()
    print(f"Total instructions: {len(m.context['trace'])}\nLast instruction: {hex(m.context['trace'][-1])}")
    return 0


if __name__ == "__main__":
    main()
