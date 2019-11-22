#!/usr/bin/env python3.7
"""
File: isc_dlz

Clause: dlz

Title: Clause statement for the DLZ

Description:
"""

from pyparsing import Group, CaselessKeyword, alphanums, Word, ZeroOrMore, OneOrMore
from bind9_parser.isc_utils import semicolon, name_type, isc_boolean, \
        lbrack, rbrack, dlz_name_type,\
        path_name


#  database <string>;
dlz_database_element = (
    CaselessKeyword('database').suppress()
    - path_name('db_args')
    + semicolon
)

#  search <boolean>;
dlz_search_element = (
    CaselessKeyword('search').suppress()
    - isc_boolean('search')
    + semicolon
)

# At the moment, orderings matter: 'database' first, then 'search'
dlz_element_group = (
    (
        dlz_search_element
        + dlz_database_element
    )
    | (
        dlz_database_element
        + dlz_search_element
    )
)

#  dlz <string> { database <string>; search <boolean>; };  [ DLZ ]
clause_stmt_dlz_standalone = (
    CaselessKeyword('dlz').suppress()
    - Group(
        dlz_name_type('dlz_name')
        - lbrack
        - OneOrMore(
                dlz_element_group('')
        )
        + rbrack
    )
    + semicolon
)('dlz')

clause_stmt_dlz_series = (
    ZeroOrMore(
        clause_stmt_dlz_standalone
    )
)('dlz')

#  See isc_viewzone.dlz for a simplified version of 'dlz <string>;' option
