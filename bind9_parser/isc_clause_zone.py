#!/usr/bin/env python3
"""
File: isc_clause_zone.py

Clause: zone

Title: Clause Statement for Zone Group

Description:
"""
from pyparsing import Keyword, ZeroOrMore, Optional, Group, OneOrMore
from bind9_parser.isc_utils import lbrack, rbrack, semicolon
from bind9_parser.isc_rr import rr_domain_name
from bind9_parser.isc_zone import zone_statements_set, zone_name
from bind9_parser.isc_optviewzone import optviewzone_statements_set
from bind9_parser.isc_optviewzoneserver import optviewzoneserver_statements_set
from bind9_parser.isc_optzone import optzone_statements_set
from bind9_parser.isc_viewzone import viewzone_statements_set


# Note: There is no validation method applied here to ensure that
#       ordering of Keywords are in longest listed, firstly.
zone_all_stmts_set = (
     zone_statements_set
     | optzone_statements_set
     | optviewzone_statements_set
     | optviewzoneserver_statements_set
     | viewzone_statements_set
)

zone_all_stmts_series = (
    ZeroOrMore(
        zone_all_stmts_set
    )
)

clause_stmt_zone_standalone = (
    Keyword('zone').suppress()
    - Group(
        zone_name('zone_name')
        - Optional(rr_domain_name)
        - lbrack
        - (
            zone_all_stmts_series
        )('')
        + rbrack
    )('zone')
    + semicolon
)('')

clause_stmt_zone_series = (
    OneOrMore(
        Group(clause_stmt_zone_standalone)('')
    )('')
)('zones')
