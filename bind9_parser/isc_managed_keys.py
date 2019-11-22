#!/usr/bin/env python3
"""
File: isc_managed_keys.py

Clause: managed-keys

Title: Clause statement for managed keys

Description: Provides managed-key-related grammar in
             PyParsing engine for ISC-configuration style
"""

from pyparsing import Word, alphanums, Group, Keyword, Literal, OneOrMore
from bind9_parser.isc_utils import semicolon, lbrack, rbrack, number_type,\
    squote, dquote, Combine, Char
from bind9_parser.isc_rr import rr_domain_name_or_root


managed_keyname_type = rr_domain_name_or_root
managed_keyname_type.setName('keyname_base')

managed_keyname_dquoted = Combine(
        Literal('"')
        - managed_keyname_type
        + Literal('"')
)
# keyname_dquoted.setName('keyname_dquoted')

managed_keyname_squoted = Combine(
        Literal("'")
        - managed_keyname_type
        + Literal("'")
)('key_id')
# keyname_dquoted.setName('keyname_squoted')

managed_key_domain_name = (
    managed_keyname_dquoted
    | managed_keyname_squoted
    | managed_keyname_type
)('rr_domain')

managed_key_type = Keyword('initial-key')  # Future will have multiple options

managed_key_flags_type = number_type('flags')
managed_key_flags_type.setName('<key-flags-id>')

managed_key_protocol_type = number_type('protocol_id')
managed_key_protocol_type.setName('<key-protocol-id>')

managed_key_algorithm_name = Word(alphanums + '-')('algorithm_type')
managed_key_algorithm_name.setName('<key-algorithm>')
managed_key_algorithm_type = number_type('algorithm_id')
managed_key_algorithm_type.setName('<key-algorithm-id>')


# Secret are in base64 encoding scheme with 2-char paddings (RFC 1421)
# Handles up to 16K encoding
charset_key_secret_base = ' \n\r\tABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
charset_key_secret_base_squote_allowed = charset_key_secret_base + "'"
charset_key_secret_base_dquote_allowed = charset_key_secret_base + '"'

managed_key_secret_type = (
        Combine(squote + Word(charset_key_secret_base_dquote_allowed) + squote)
        | Combine(dquote + Word(charset_key_secret_base_squote_allowed) + dquote)
        | Word(charset_key_secret_base)
)('key_secret')
managed_key_secret_type.setName('<key-secret>')

quoted_managed_key_secret_type = (
        Combine(squote + Word(charset_key_secret_base_dquote_allowed) + squote)
        | Combine(dquote + Word(charset_key_secret_base_squote_allowed) + dquote)
)('quoted_key_secret')

#  domain name, flags, protocol, algorithm, and the Base64 representation of the
#  key data.

managed_keys_set = (
    managed_key_domain_name
    + Keyword('initial-key').suppress()
    - managed_key_flags_type
    - managed_key_protocol_type
    - managed_key_algorithm_type
    - quoted_managed_key_secret_type('key_secret')
    + semicolon
)

managed_keys_series = (
    OneOrMore(managed_keys_set)('')
)

# key <key-name> { algorithm <string>; secret <key-secret>; };
managed_keys_statement_standalone = (
    Keyword('managed-keys').suppress()
    - Group(
        lbrack
        + managed_keys_series
        + rbrack
    )
    + semicolon
)('managed_keys')

