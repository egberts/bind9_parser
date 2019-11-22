#!/usr/bin/env python3.7
"""
File: isc_viewzone.py

Clause: view, zone

Title: Statements Used Only By view And zone Clauses

Description: isc_viewzone contains all parse elements pertaining
             to both options and zone (but not view)
"""
from pyparsing import Group, CaselessKeyword, OneOrMore, Keyword
from bind9_parser.isc_utils import semicolon, database_name_type
from bind9_parser.isc_clause_dlz import dlz_name_type


viewzone_stmt_database = (
    Keyword('database').suppress()
    - database_name_type('database')
    + semicolon
)

#  dlz <dlz_name>;  [ View Zone ]
#  See isc_dlz.clause_stmt_dlz_series for full DLZ-clause syntax in
#      which views/zones' DLZ references to.
viewzone_stmt_dlz = (
    CaselessKeyword('dlz').suppress()
    - dlz_name_type('dlz')
    + semicolon
)

# Keywords are in dictionary-order, but with longest pattern as
# having been listed firstly
#
# This statement set is to be used by either 'view' or 'zone' clause
viewzone_statements_set = (
    viewzone_stmt_database
    | viewzone_stmt_dlz
)

viewzone_statements_series = OneOrMore(viewzone_statements_set)
