#!/usr/bin/env python3.7
"""
File: isc_optviewserver.py

Clause: options

Title: Statements Used Only By options, view, And server Clauses.

Description: Provides 'options' and 'server'-related grammar in
             PyParsing engine for ISC-configuration style
"""
from pyparsing import ZeroOrMore, Keyword, Literal
from bind9_parser.isc_utils import semicolon, isc_boolean, number_type


#  edns-udp-size <number>;  # [ server ]
optviewserver_stmt_edns_udp_size = (
    Keyword('edns-udp-size')
    - number_type('edns_udp_size')  # valid range is 512-4096
    + semicolon
)

#  provide-ixfr ( yes | no) ; [ Opt, View, server ]
optviewserver_stmt_provide_ixfr = (
    Keyword('provide-ixfr')
    - isc_boolean('provide_ixfr')
    + semicolon
)

#  request-ixfr <boolean>;  # [ server ]  # v9.1.0+
optviewserver_stmt_request_ixfr = (
    Keyword('request-ixfr')
    + isc_boolean('request_ixfr')
    + semicolon
)

#  transfer-format ( 'one-answer' | 'many-answers' )  # [ server ]
optviewserver_stmt_transfer_format = (
    Keyword('transfer-format')
    + (
        Literal('one-answer')
        | Literal('many-answers')
    )('transfer_format')
    + semicolon
)

# Keywords are in dictionary-order, but with longest pattern as
# having been listed firstly
optviewserver_statements_set = (
    optviewserver_stmt_provide_ixfr
    | optviewserver_stmt_request_ixfr
    | optviewserver_stmt_transfer_format
    | optviewserver_stmt_edns_udp_size
)

optviewserver_statements_series = (
    ZeroOrMore(
        optviewserver_statements_set
    )
)
