#!/usr/bin/env python3.7
"""
File: isc_view.py

Clause: view

Title: Statements Used Only By view Clause.

Description: Provides View-related grammar in PyParsing engine
             for ISC-configuration style.

             Covers the statements that are only found in View
             clause (and no other clauses).

             Does not test for view_name (that is in
             isc_util.py/test_util.py) nor test for
             clause_stmt_view_standalone (that is in clause_view.py/test_clause_view.py)
"""
from pyparsing import Group, Keyword, ZeroOrMore
from bind9_parser.isc_utils import semicolon, isc_boolean, lbrack, rbrack
from bind9_parser.isc_inet import ip46_addr_or_prefix
from bind9_parser.isc_aml import aml_nesting
from bind9_parser.isc_server import server_statement_series
from bind9_parser.isc_clause_trusted_keys import clause_stmt_trusted_keys_set


#   match-clients { aml; } ; [ View ]
view_stmt_match_clients = (
    Keyword('match-clients').suppress()
    - Group(
        aml_nesting('')
    )('match_clients')
)('')  # remove List label as 'match-clients' occurs exactly once

#  match-destinations { aml; } ; [ View ]
view_stmt_match_destinations = (
    Keyword('match-destinations').suppress()
    - Group(
        aml_nesting('')
    )('match_destinations')
)('')  # remove List label as 'match-destinations' occurs exactly once

#  match-recursive-only { boolean; } ; [ View ]
view_stmt_match_recursive_only = (
    Keyword('match-recursive-only').suppress()
    - isc_boolean('match_recursive_only')
    + semicolon
)('')

# re-include 'server' clause as a 'view' statement here
view_stmt_server = (
    Keyword('server').suppress()
    - Group(
        ip46_addr_or_prefix('ip_addr')
        + lbrack
        + Group(
            server_statement_series
        )('configs')
        + rbrack
    )('')
    + semicolon
)('server')
view_stmt_server.setName('server <netprefix> { ... };')


# Keywords are in dictionary-order, but with longest pattern as having been listed firstly
view_statements_set = (
    view_stmt_match_recursive_only
    | view_stmt_match_destinations
    | view_stmt_match_clients
    | view_stmt_server
    # Don't put clause_stmt_trusted_keys here, you'll get a circular dependency at Python-level
    # Insert the clause_stmt_trusted_keys into isc_clause_view.py instead
)

view_statements_series = ZeroOrMore(view_statements_set)
