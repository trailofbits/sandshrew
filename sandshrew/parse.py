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

    def __init__(self, func_names):
        """
        :param func_names: list of target symbols
        """
        self.func_names = func_names
        self.parse_tree = {}
        self.initial_callgraph = None
        super().__init__()


    def visit_FuncDef(self, node):
        """
        method called by visit() in base class that
        spawns off child visitors for target functions

        :param node: abstract syntax tree
        """

        # generate a callgraph for the target functions
        if node.decl.name in self.func_names:
            child = FuncCallVisitor()
            child.visit(node)
            self.initial_callgraph = child.func_calls

        # retrieve and parse parameters of all functions present
        args = []
        for param in node.decl.type.args.params:

            # check if param is pointer type
            if type(param.type) is c_ast.PtrDecl:

                # pointer to pointer type - awkward attributes result of
                # indirection
                if type(param.type.type) is c_ast.PtrDecl:
                    ptype = param.type.type.type.type.names
                    ptype += [" **"]

                # just one pointer lexicon
                else:
                    ptype = param.type.type.type.names
                    ptype += [" *"]

            # TODO: check if function pointer; also traverse??

            # check if type alias
            elif type(param.type.type) is c_ast.TypeDecl:
                ptype = param.type.type.type.names

            # else, a regular non-pointer type
            else:
                ptype = param.type.type.names

            args += [" ".join(ptype)]

        # retrieve return type of function.
        try:
            rettype = " ".join(node.decl.type.type.type.names)

        # thrown if rettype is pointer, since PtrDecl is an additional
        # type attribute
        except AttributeError:
            rettype = " ".join(node.decl.type.type.type.type.names)
            rettype += " *"

        # append to parse tree
        self.parse_tree[node.decl.name] = {
            "rettype": rettype,
            "args": args
        }


    @property
    def callgraph(self):
        """ bootstraps and returns a function callgraph """

        # check if a callgraph was generated by visit()
        if self.initial_callgraph is None:
            raise RuntimeError("Callgraph not generated. Does the function exist in the binary?")

        # re-initialize callgraph by comparing all parsed methods against original callgraph
        callgraph = {}
        for func, args in self.parse_tree.items():
            for name in self.initial_callgraph:
                if func == name:
                    callgraph[func] = args
        return callgraph


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


def generate_parse_tree(workspace, filename, funcs, ex_opts="-Iinclude"):
    """
    helper method that generates a parse tree of
    all functions within a target function

    :param workspace: Manticore workspace dir str
    :param filename: C file to generate AST
    :param funcs: list of functions to extract call graph
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
    parent = FuncDefVisitor(funcs)
    parent.visit(ast)
    return parent.callgraph


def generate_func_prototypes(parse_tree):
    """
    helper method that generates a string of
    C-style function prototypes from a NodeVisitor-based
    parse tree.

    :param parse_tree: dict of parse tree
    :rtype: str
    """

    func_prots = []
    for name, val in parse_tree.items():

        # init func prototype components
        rettype = val['rettype']
        args = val['args']
        last_len = len(args[:-1])

        # init return type and name
        prot = f"{rettype} {name}("

        # append func args expect for last
        for i, argtype in enumerate(args[:-1]):
            prot += f"{argtype} arg_{i}, "

        # close off prototype
        prot += f"{args[-1]} arg_{last_len});"

        func_prots.append(prot)

    return "\n".join(func_prots)
