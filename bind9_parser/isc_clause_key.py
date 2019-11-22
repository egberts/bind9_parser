#!/usr/bin/env python3
"""
File: isc_clause_key.py

Clause: keys

Title: Clause statement for key

Description: Provides key-related grammar in PyParsing engine
             for ISC-configuration style
"""
from pyparsing import Word, alphanums, Group, Keyword, ZeroOrMore
from bind9_parser.isc_utils import semicolon, lbrack, rbrack, key_id, key_secret

# NOTE: If any declaration here is to be used OUTSIDE of the 'keys' clause,
# it should instead be defined in isc_utils.py

key_algorithm_name = Word(alphanums + '-')('algorithm')
key_algorithm_name.setName('<key-algorithm>')

# algorithm <string>;
key_algorithm_element = (
        Keyword('algorithm').suppress()
        - key_algorithm_name('algorithm')
        + semicolon
)
key_algorithm_element.setName('algorithm <key-algorithm>;')

# secret <key_secret>;
key_secret_element = (
        Keyword('secret').suppress()
        - key_secret('secret')
        + semicolon
)
key_secret_element.setName('secret <key_secret>;')

# key <key-name> { algorithm <string>; secret <key-secret>; };
# key key_id {
#   algorithm algorithm_id;
#   secret secret_string;
# };
clause_stmt_key_standalone = (
    Keyword('key').suppress()
    - Group(
        key_id('key_id')
        + lbrack
        - key_algorithm_element
        - key_secret_element
        + rbrack
    )
    + semicolon
)('key')

# {0-*} statement
clause_stmt_key_series = (
    ZeroOrMore(
        clause_stmt_key_standalone
    )
)('key')
clause_stmt_key_series.setName('key <key-name> { algorithm <string>; secret <key-secret>; };')

