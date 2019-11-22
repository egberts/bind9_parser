#!/usr/bin/env python3
"""
File: isc_clause_view.py

Clause: view

Title: Clause Statement for View Group

Description:
"""
from pyparsing import Keyword, Optional, ZeroOrMore, Group
from bind9_parser.isc_utils import lbrack, rbrack, semicolon, view_name
from bind9_parser.isc_rr import rr_class_set
from bind9_parser.isc_view import view_statements_set
from bind9_parser.isc_managed_keys import managed_keys_statement_standalone
from bind9_parser.isc_optview import optview_statements_set
from bind9_parser.isc_optviewserver import optviewserver_statements_set
from bind9_parser.isc_optviewzone import optviewzone_statements_set
from bind9_parser.isc_optviewzoneserver import optviewzoneserver_statements_set
from bind9_parser.isc_viewzone import viewzone_statements_set
from bind9_parser.isc_clause_zone import clause_stmt_zone_standalone
from bind9_parser.isc_clause_trusted_keys import clause_stmt_trusted_keys_standalone


view_all_statements_set = (
        view_statements_set
        | optview_statements_set
        | optviewserver_statements_set
        | optviewzone_statements_set
        | optviewzoneserver_statements_set
        | viewzone_statements_set
        | clause_stmt_zone_standalone
        | clause_stmt_trusted_keys_standalone
        | managed_keys_statement_standalone  # Amazing copy
)

view_all_statements_series = ZeroOrMore(view_all_statements_set)

clause_stmt_view_standalone = (
    Keyword('view').suppress()
    - Group(
        view_name('view_name')
        - Optional(rr_class_set('rr_class'))
        - Group(
            lbrack
            + view_all_statements_series
            + rbrack
        )('configs')
    )('')
    + semicolon
)('view')

clause_stmt_view_series = (
    ZeroOrMore(
            clause_stmt_view_standalone
    )
)('view')
