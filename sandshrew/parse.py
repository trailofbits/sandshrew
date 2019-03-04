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
    child visitors.

    Due to nature of NodeVisitor base class,
    we have to use some awkward object inheritance to
    generate call graphs.
    """

    def __init__(self, func):
        """
        :param func: target symbol name
        """
        self.func = func
        super().__init__()


    def visit_FuncDef(self, node):
        """
        method called by visit() in base class that
        spawns off child visitors for target functions

        :param node: abstract syntax tree
        """

        # generate a callgraph for the target functions
        if node.decl.name == self.func:
            self.child = FuncCallVisitor()
            self.child.visit(node)


    @property
    def callgraph(self):
        return self.child.func_calls


class FuncCallVisitor(c_ast.NodeVisitor):

    def __init__(self):
        self.func_calls = []

    def visit_FuncCall(self, node):
        """
        method called by visit() in base class that
        generates and stores all function calls made

        :param node: abstract syntax tree
        """
        self.func_calls.append(node.name.name)


def generate_parse_tree(workspace, filename, func, ex_opts):
    """
    helper method that generates a parse tree of
    all functions within a target function

    :param workspace: Manticore workspace dir str
    :param filename: C file to generate AST
    :param func: function to extract call graph
    :param ex_opts: other user-supplied compilation flags.
    :rtype: dict
    """

    # path to store preprocessed code
    pre_path = workspace + "/" + consts.FUNC_FILE

    # annotated call for generating preprocessed C for parsing
    scall = [
        consts.COMPILER,                # default should be 'gcc'
        '-E',                           # preprocess only
        '-P',                           # no line directives
        '-Iutils/fake_libc_include',    # new libc path
        ex_opts,                        # extra user-supplied options
        filename,                       # name of C file
    ]

    # run scall to initialize a _test.c file with all function definitions from linked
    # libraries. pycparser can only reason if headers are preprocessed correctly.
    with open(pre_path, 'w+') as out:
        subprocess.call(scall, stdout=out, stderr=subprocess.STDOUT)

    # use pycparser to generate an AST from the generated intermediate C file
    ast = pycparser.parse_file(pre_path, use_cpp=True, cpp_args='-fpreprocessed')

    # spawn off call graph visitor
    parent = FuncDefVisitor(func)
    parent.visit(ast)
    return parent.callgraph
