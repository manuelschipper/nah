from argparser import HTTPieArgumentParser


def to_argparse(parser_type=HTTPieArgumentParser):
    concrete_parser = parser_type()
    return concrete_parser


parser = to_argparse()
