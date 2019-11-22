#!/usr/bin/env python3.7
"""
File: isc_clause.py

Clause: top-level

Title: Clause Statement for all clauses

Description: Provides ALL clauses at the top-level of ISC
             configuration file (isc_clause_*.py)
"""
from pyparsing import ZeroOrMore, cppStyleComment, pythonStyleComment, Group
from isc_utils import parse_me
from isc_clause_acl import clause_stmt_acl_standalone
from isc_clause_controls import clause_stmt_control_standalone
from isc_clause_dlz import clause_stmt_dlz_standalone
from isc_clause_dyndb import clause_stmt_dyndb_standalone
from isc_clause_key import clause_stmt_key_standalone
from isc_clause_logging import clause_stmt_logging_standalone
from isc_clause_managed_keys import clause_stmt_managed_keys_standalone
from isc_clause_masters import clause_stmt_masters_standalone
from isc_clause_options import clause_stmt_options
from isc_clause_server import clause_stmt_server_standalone
from isc_clause_trusted_keys import clause_stmt_trusted_keys_standalone
from isc_clause_view import clause_stmt_view_standalone
from isc_clause_zone import clause_stmt_zone_standalone, clause_stmt_zone_series

#####################################################
#  Group of clauses (super-statements)
#####################################################
optional_clause_stmt_set = (
        clause_stmt_acl_standalone
        #    | (clause_catalog_zones + semicolon)
        | clause_stmt_control_standalone
        | clause_stmt_dlz_standalone
        | clause_stmt_dyndb_standalone
        | clause_stmt_key_standalone
        | clause_stmt_logging_standalone
        #    | (clause_lwres + semicolon)
        | clause_stmt_managed_keys_standalone
        | clause_stmt_masters_standalone
        | clause_stmt_server_standalone
        | clause_stmt_trusted_keys_standalone
        | clause_stmt_view_standalone
        | clause_stmt_zone_standalone
)

optional_clause_stmt_series = (
    ZeroOrMore(
        optional_clause_stmt_set
    )
)
#  Mandatory and Optional CLAUSE statements

# Exactly one 'options' clause
# options { a; };
mandatory_clause_stmts = clause_stmt_options

# Use the ZeroOrMore(optional) & mandatory & ZeroOrMore(optional) approach
clause_statements = (
        ZeroOrMore(optional_clause_stmt_set)
        - mandatory_clause_stmts
        + ZeroOrMore(optional_clause_stmt_set)
)
clause_statements.setName('(clauses-statements)')
clause_statements.ignore(cppStyleComment)
clause_statements.ignore(pythonStyleComment)