#!/usr/bin/env python3
"""
sandshrew.py

    Unconstrained concolic execution tool for cryptographic verification

"""
import argparse
import os.path
import logging

from elftools.elf.elffile import ELFFile

from manticore import issymbolic
from manticore.core.smtlib import operators
from manticore.core.plugin import Plugin
from manticore.native import Manticore
from manticore.native.models import strcmp
from manticore.native.cpu import abstractcpu
from manticore.utils.fallback_emulator import UnicornEmulator

import sandshrew.parse as parse
import sandshrew.consts as consts


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
    else:
        return False


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

    # check binary arch support for x86_64
    if not binary_arch(args.test):
        raise NotImplementedError("only supports x86_64 binary concretization")

    # initialize Manticore
    m = Manticore.linux(args.test, ['+' * consts.BUFFER_SIZE])
    m.verbosity(2)

    # initialize mcore context manager
    m.context['sym'] = args.symbol
    m.context['argv1'] = None
    m.context['funcs'] = parse.generate_parse_tree(m.workspace, args.test + ".c", args.symbol, args.exopts)
    m.context['exec_flag'] = False

    logging.debug(f"Generated callgraph for {m.context['sym']}: {m.context['funcs']}")

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


    # at target symbol, attach a hook that determines whether
    # Unicorn concretization is necessary
    @m.hook(m.resolve(m.context['sym']))
    def concrete_checker(state):
        """ checker hook that concretizes symbolic input """
        cpu = state.cpu

        with m.locked_context() as context:
            logging.debug(f"Entering target function {context['sym']}")

            # check if RDI, the input arg, is symbolic, and
            # if so, set `exec_flag` before raising exception.
            data = cpu.read_int(cpu.RDI)
            if issymbolic(data):
                logging.debug("Concretizing input arg RDI")
                context['exec_flag'] = True


    # for each helper function within those target symbols, add concrete_hook
    # which enables them to be executed concretely w/out the SE engine
    for sym in m.context['funcs']:

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
                    logging.debug(f"Concolically executing function {sym}")
                    cpu.decode_instruction(cpu.PC)
                    emu = UnicornEmulator(cpu)
                    emu.emulate(cpu.instruction)

                    # create new fresh unconstrained symbolic value
                    logging.debug("Writing fresh unconstrained buffer to RAX")
                    return_buf = state.new_symbolic_buffer(consts.BUFFER_SIZE)
                    state.cpu.write_bytes(state.cpu.RAX, return_buf)

                    # jump to instruction after `call` (just to make sure)
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
            context['solution'] = state.solve_one(context['argv1'], consts.BUFFER_SIZE)

        m.terminate()


    # run manticore
    m.run()

    # output results
    print(f"Total instructions: {len(m.context['trace'])}\nLast instruction: {hex(m.context['trace'][-1])}")
    if m.context['solution'] is not None:
        print(f"\nEDGE CASE FOUND: {m.context['solution']}")
    return 0


if __name__ == "__main__":
    main()
