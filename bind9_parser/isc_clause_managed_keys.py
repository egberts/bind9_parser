#!/usr/bin/env python3
"""
File: isc_clause_managed_keys.py

Clause: managed-keys

Title: Clause statement for managed keys

Description: Provides managed-key-related grammar in
             PyParsing engine for ISC-configuration style
"""

from pyparsing import Optional, OneOrMore, ZeroOrMore
from bind9_parser.isc_managed_keys import managed_keys_statement_standalone


# Due to cyclic Python import, 'clause'-based managed-keys are
#    kept separate from 'view'-based managed-keys statement
#
# Fortunately, they are identical use of syntax so we merely assign its
#     managed-keys syntax to clause as well.

clause_stmt_managed_keys_standalone = managed_keys_statement_standalone

clause_stmt_managed_keys_series = (
    ZeroOrMore(
        managed_keys_statement_standalone
    )
)('managed_keys')

