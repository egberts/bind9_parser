#!/usr/bin/env python3
"""
File: isc_clause_trusted_keys.py

Clause: trusted-keys

Title: Clause Statement for Trusted Keys

Description: Provides trusted-key-related grammar in
             PyParsing engine for ISC-configuration style
"""
from pyparsing import Word, alphanums, Group, Keyword, Literal, ZeroOrMore
from bind9_parser.isc_utils import semicolon, parse_me, lbrack, \
    rbrack, number_type,\
    squote, dquote, Combine
from bind9_parser.isc_domain import rr_domain_name_or_wildcard_type
from bind9_parser.isc_trusted_keys import trusted_keys_statements_set, \
        trusted_keys_statements_series


# key <key-name> { algorithm <string>; secret <key-secret>; };
clause_stmt_trusted_keys_standalone = (
    trusted_keys_statements_set
)('trusted_keys')

clause_stmt_trusted_keys_series = (
    ZeroOrMore(clause_stmt_trusted_keys_standalone)
)('trusted_keys')
