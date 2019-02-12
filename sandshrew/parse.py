"""
parse.py

	sandshrew parsing module for C replay concrete model generation.
	Objects inherit the pycparser.c_ast base class in order to properly
	reason with C syntax, and is instantiated by the main module using
	generate_parse_tree()
"""
import subprocess
import pycparser
from pycparser import c_ast

import sandshrew.consts as consts

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


def generate_parse_tree(workspace, filename, funcs):
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
    with open(workspace + "_test.c", 'w+') as out:
        subprocess.call(['gcc', '-nostdinc', '-E', '-P', '-Iutils/fake_libc_include', filename],
                          stdout=out, stderr=subprocess.STDOUT)

    # use pycparser to generate an AST from the generated intermediate C file
    ast = pycparser.parse_file(workspace + "_test.c", use_cpp=False)

    # spawn off call graph visitor
    parent = FuncDefVisitor(funcs)
    parent.visit(ast)
    return parent.child.parse_tree
