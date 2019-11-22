#!/usr/bin/env python3.7
"""
File: isc_optzone.py

Clause: options, zone

Title: Statements Used Only By options And zone Clauses.

Description: isc_optzone contains all parse elements pertaining
             to both options and zone (but not view)
"""
from pyparsing import Group, Keyword, OneOrMore
from bind9_parser.isc_utils import isc_boolean, semicolon, parse_me


optzone_stmt_notify_to_soa = (
    Keyword('notify-to-soa')
    - isc_boolean('notify_to_soa')
    + semicolon
)

# Keywords are in dictionary-order, but with longest pattern as
# having been listed firstly
optzone_statements_set = (
    optzone_stmt_notify_to_soa
)

optzone_statements_series = (
    OneOrMore(optzone_statements_set)
)

