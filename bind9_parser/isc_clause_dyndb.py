#!/usr/bin/env python3.7
"""
File: isc_clause_dyndb.py

Clause: dyndb

Title: Clause statement for Dynamic Database

Description:
"""
import unittest
from pyparsing import Group, Keyword, Word, ZeroOrMore, OneOrMore
from bind9_parser.isc_utils import lbrack, rbrack, semicolon, \
    isc_file_name, quoted_path_name, charset_filename_base

# TODO For dyndb_driver_content, haven't figured out how to allow curly braces inside quotes yet
dyndb_custom_driver_configuration = (
        lbrack
        + Word(charset_filename_base + ' \t\r\n/;"\"\'')('driver_parameters')  # no '{}' characters
        + rbrack
        # no semicolon here
)(None)

dyndb_database_name = (
    isc_file_name
)('db_name')

dyndb_dynamic_module_name = (
    quoted_path_name
)('module_filename')

clause_stmt_dyndb_standalone = (
    Keyword('dyndb').suppress()
    + Group(
        dyndb_database_name
        - dyndb_dynamic_module_name
        - dyndb_custom_driver_configuration
    )
    + semicolon
)('dyndb')

clause_stmt_dyndb_series = (
    OneOrMore(
        clause_stmt_dyndb_standalone
    )
)('dyndb')

if __name__ == '__main__':
    unittest.main()
