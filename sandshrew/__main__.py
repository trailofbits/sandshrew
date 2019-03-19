#!/usr/bin/env python3
"""
sandshrew.py

    Unconstrained concolic execution tool for cryptographic verification

"""
import rand
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

    # initialize state by constraining symbolic argv
    @m.init
    def init(initial_state):

        logging.debug(f"Creating symbolic argument using '{args.constraint}' constraint")

        # determine argv[1] from state.input_symbols by label name
        argv1 = next(sym for sym in initial_state.input_symbols if sym.name == 'ARGV1')
        if argv1 is None:
            raise RuntimeException("ARGV was not provided and/or made symbolic")

        # apply constraint based on user input
        for i in range(consts.BUFFER_SIZE):

            if args.constraint == "alpha":
                initial_state.constrain(operators.OR(
                        operators.AND(ord('A') <= argv1[i], argv1[i] <= ord('Z')),
                        operators.AND(ord('a') <= argv1[i], argv1[i] <= ord('z'))
                ))

            elif args.constraint == "num":
                initial_state.constrain(operators.AND(ord('0') <= argv1[i], argv1[i] <= ord('9')))

            elif args.constraint == "alphanum":
                raise NotImplementedError("alphanum constraint set not yet implemented")

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


    for sym in m.context['syms']:

        # we do some initialization and symbolic input checking
        # at the wrapper call (SANDSHREW_*) and determine if further
        # concretization is necessary
        @m.hook(m.resolve("SANDSHREW_" + sym))
        def concrete_checker(state):
            """ checker hook that concretizes symbolic input """
            cpu = state.cpu

            with m.locked_context() as context:
                logging.debug(f"Entering target function SANDSHREW_{sym}")

                # check if RDI, the input arg, is symbolic, and
                # if so, set `exec_flag` before raising exception.
                data = cpu.read_int(cpu.RDI)
                if issymbolic(data):
                    logging.debug(f"Symbolic input arg detected")
                    context['exec_flag'] = True


        # actual hook for perform concretization when necessary, utilizing Unicorn
        # in order to execute single `call <sym>` instructions concretely
        @m.hook(m.resolve(sym))
        def concolic_hook(state):
            """ concretization hook """
            cpu = state.cpu

            with m.locked_context() as context:

                if context['exec_flag'] == True:

                    # store `call sym` instruction and the one after that
                    # by backtracking over trace counter
                    call_pc = context['trace'][-1]
                    next_pc = context['trace'][-1] + 5

                    # we are currently in the function prologue of `sym`.
                    # let's go back to `call sym`.
                    state.cpu.PC = call_pc

                    # use the fallback emulator to concretely execute call
                    # instruction.
                    logging.debug(f"Concretely executing `call <{sym}>`")
                    state.cpu.decode_instruction(state.cpu.PC)
                    emu = UnicornEmulator(state.cpu)
                    emu.emulate(state.cpu.instruction)

                    logging.debug("Continuing with Manticore symbolic execution")

                    # jump to instruction after `call` (just to make sure)
                    logging.debug(f"Jumping to next instruction {hex(next_pc)}")
                    state.cpu.PC = next_pc

                    # create new fresh unconstrained symbolic value
                    logging.debug("Writing fresh unconstrained buffer to return value")
                    context['unconstrained'] = state.new_symbolic_buffer(consts.BUFFER_SIZE)
                    state.cpu.write_bytes(state.cpu.RAX, context['unconstrained'])


                # if flag is not set, we do not concolically execute. No symbolic input is
                # present, so no path constraints will be collected
                else:
                    logging.debug("No symbolic input present, so skipping concolic testing.")


    # TODO(alan): resolve ifunc (different archs use different optimized implementations)
    # crypto comparisons should be done in strcmp. Since we are writing only test cases, we don't
    # need to rely on "constant-time comparison" implementations that may only lead to slower
    # SE runtimes.
    @m.hook(m.resolve('__strcmp_ssse3'))
    def cmp_model(state):
        """ when encountering strcmp(), just execute the function model """
        logging.debug("Invoking model for comparsion call")
        state.invoke_model(strcmp)


    # we finally attach a hook on the `abort` call, which must be called in the program
    # to abort from a fail/edge case path (i.e comparison b/w implementations failed), and
    # solve for the argv symbolic buffer
    @m.hook(m.resolve('abort'))
    def fail_state(state):
        """ the program must make a call to abort() in the edge case path. This way we can hook onto it
        with Manticore and solve for the input """

        logging.debug("Entering edge case path")

        # solve for the symbolic argv input
        with m.locked_context() as context:
            solution = state.solve_one(context['unconstrained'], consts.BUFFER_SIZE)
            print(f"\nEDGE CASE FOUND: {solution}")

            # write solution to individual test case to workspace
            rand_str = lambda n: ''.join([random.choice(string.ascii_lowercase) for i in xrange(n)])
            with open(m.workspace + '/' + 'sandshrew_' + rand_str, 'wb') as fd:
                fd.write(solution)

        m.terminate()


    # run manticore
    m.run()
    print(f"Total instructions: {len(m.context['trace'])}\nLast instruction: {hex(m.context['trace'][-1])}")
    return 0


if __name__ == "__main__":
    main()
