#!/usr/bin/env python3
"""
File: isc_clause_server.py

Clause: server

Title: Clause Statement for Server Definitions

Description:
"""
from pyparsing import OneOrMore, Keyword, ZeroOrMore, Group
from bind9_parser.isc_utils import lbrack, rbrack, semicolon, parse_me
from bind9_parser.isc_inet import ip46_addr_or_prefix
from bind9_parser.isc_server import server_statement_set
from bind9_parser.isc_optviewserver import optviewserver_statements_set
from bind9_parser.isc_optviewzoneserver import optviewzoneserver_statements_set


# BUG: 'edns' and 'edns-udp-size' are reversed and needs unreversing
server_all_statements_set = (
    optviewserver_statements_set # make optviewserver_statements_set firstly due to 'edns-udp-size' pattern
    | optviewzoneserver_statements_set
    | server_statement_set  # make server_statement_set last due to 'edns' pattern
)

server_all_statements_series = (
    ZeroOrMore(
        server_all_statements_set
    )
)

clause_stmt_server_standalone = (
    Keyword('server').suppress()
    - Group(
        ip46_addr_or_prefix('addr')
        + lbrack
        + Group(
            server_all_statements_series
        )('configs')
        + rbrack
    )('')
    + semicolon
)('server')
clause_stmt_server_standalone.setName('server { ... };')

clause_stmt_server_series = (
    ZeroOrMore(
        clause_stmt_server_standalone
    )
)('server')
clause_stmt_server_series.setName('server { ... }; ...;')
