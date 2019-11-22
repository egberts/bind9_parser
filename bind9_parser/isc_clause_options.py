#!/usr/bin/env python3
"""
File: isc_clause_options.py

Clause: options

Title: Clause Statement for Options

Description:
"""

from pyparsing import Group, Keyword, ZeroOrMore, ParseFatalException, Word, alphas, alphanums
from bind9_parser.isc_utils import lbrack, rbrack, semicolon
from bind9_parser.isc_options import options_statements_set
from bind9_parser.isc_optview import optview_statements_set
from bind9_parser.isc_optviewzone import optviewzone_statements_set
from bind9_parser.isc_optviewserver import optviewserver_statements_set
from bind9_parser.isc_optviewzoneserver import optviewzoneserver_statements_set
from bind9_parser.isc_optzone import optzone_statements_set
from bind9_parser.isc_viewzone import viewzone_statements_set


class InvalidArgumentException(ParseFatalException):
    def __init__(self, s, loc, msg):
        print("InvalidArgumentException")
        super(InvalidArgumentException, self).__init__(
                s, loc, "invalid argument '%s'" % msg)


class InvalidFunctionException(ParseFatalException):
    def __init__(self, s, loc, msg):
        super(InvalidFunctionException, self).__init__(
                s, loc, "invalid function '%s'" % msg)


def error(exceptionClass):
    def raise_exception(s,l,t):
        raise exceptionClass(s,l,t[0])
    return Word(alphas,alphanums).setParseAction(raise_exception)

options_stmt_counter = 0
def counter_options(strg, loc, toks):
    global options_stmt_counter
    options_stmt_counter = options_stmt_counter + 1

options_all_statements_set = (
        options_statements_set
        | optview_statements_set
        | optviewserver_statements_set
        | optviewzone_statements_set
        | optviewzoneserver_statements_set
        | optzone_statements_set
)

options_all_statements_series = (
    ZeroOrMore(
        (
            options_all_statements_set
        )
    )('')
)('')

clause_stmt_options = (
    Keyword('options').setParseAction(counter_options).suppress()
    - Group(
        lbrack
        - options_all_statements_series
        + rbrack
    )('')
    + semicolon
)('options')
clause_stmt_options.setName('options { <options-statement>; ... };')
