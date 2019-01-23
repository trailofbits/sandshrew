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
import os.path
import argparse

import cffi
import pycparser

from pycparser import c_ast
from manticore import issymbolic
from manticore.core.smtlib import operators
from manticore.native import Manticore
from manticore.native.cpu import abstractcpu


class FuncGenAST(c_ast.NodeVisitor):
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
    """ generates a parse tree of all functions within
    a specified target function for later concretization """
    ast = pycparser.parse_file(filename, 
                               use_cpp=True, cpp_path='gcc',
                               cpp_args=['-Iinclude/monocypher', '-Iinclude/tweetnacl', 
                                         '-Iutils/fake_libc_include'])
    v = FuncGenAST(func)
    v.visit(ast)
    return v.parse_tree


def call_ffi(lib, funcname, args):
    """ safe wrapper to calling C through FFI """
    func = lib.__getattr__(funcname)
    lib.func(args)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--binary", dest="binary", required=True,
                        help="Target ELF binary for symbolic execution")
    parser.add_argument("-s", "--symbols", dest="symbols", required=True,
                        nargs='+', help="Target function symbols for equivalence analysis")
    parser.add_argument("-t", "--trace", action='store_true', required=False,
                        help="Set to execute instruction recording")
    parser.add_argument("-v", "--verbosity", dest="verbosity", required=False,
                        default=2, help="Set verbosity for Manticore")

    # parse or print help
    args = parser.parse_args()
    if args is None:
        parser.print_help()
    
    # initialize Manticore
    m = Manticore(args.binary)
    m.context['trace'] = []
    m.context['sym'] = ""
    m.context['funcs'] = {}
 
    # initialize FFI through shared object, assumes shared object in pwd
    ffi = cffi.FFI()
    obj = args.binary + ".so" 
    obj_path = os.path.dirname(os.path.abspath(__file__)) + os.path.sep + obj
    lib = ffi.dlopen(obj_path)


    with m.locked_context() as context:

        # generate parse tree for functions in source
        context['funcs'] = generate_parse_tree(args.binary + ".c", context['sym'])

        # save symbols and resolve them 
        context['sym'] = arg.symbols
        sym_addrs = [m.resolve(sym) for sym in context['sym']]

 
    # add record trace hook throughout execution if specified by user 
    if args.trace:
        @m.hook(None)
        def record(state):
            pc = state.cpu.PC
            print(f"{hex(pc)}")
            with m.locked_context() as context:
                context['trace'] += [pc]


    # at target symbols, assuming target was compiled for x86_64 
    # we immediately symbolicate the arguments. The calling convention
    # looks as so:
    # arg1: rdi, arg2: rsi, arg3: rdx
    for n, sym in enumerate(sym_addrs): 
        @m.hook(sym)
        def sym(state):
            """ create symbolic args with RSI and RDI
            to perform SE on function """

            print("Injecting symbolic buffer into args")

            # create symbolic buffers
            rdi_buf = state.new_symbolic_buffer(32)
            rsi_buf = state.new_symbolic_buffer(32)
            
            # apply constraints
            for i in range(32):
                state.constrain(operators.AND(ord(' ') <= rdi_buf[i], rdi_buf[i] <= ord('}')))
                state.constrain(operators.AND(ord(' ') <= rdi_buf[i], rdi_buf[i] <= ord('}')))
            
            with m.locked_context() as context:
                
                # load addresses into context
                #context[f'rdi_{n}'] = state.cpu.RDI
                context[f'rsi_{n}'] = state.cpu.RSI

                # write bytes
                #state.cpu.write_bytes(context[f'rdi_{n}'], rdi_buf)
                state.cpu.write_bytes(context[f'rsi_{n}'], rsi_buf)


    def concrete_hook(state):
        """ concrete hook for non-symbolic execution
        through FFI """
        cpu = state.cpu

        print("Concretely executing function")

        # check if args are symbolic, and concretize if so
        for arg in [cpu.RDI, cpu.RSI, cpu.RDX]:
            if issymbolic(arg):
                raise abstractcpu.ConcretizeRegister(arg)

        # execute C function natively through FFI
        call_ffi(lib, funcname, concrete_args)


    # attach hooks to parsed concrete functions
    with m.locked_context('funcs', dict) as funcs:
        for addr in funcs.keys():
            m.add_hook(m.resolve(addr), concrete_hook)


    # run manticore
    m.verbosity(args.verbosity)
    m.run()
    print(f"Total instructions: {len(m.context['trace'])}\nLast instruction: {hex(m.context['trace'][-1])}")


if __name__ == "__main__":
    main()
