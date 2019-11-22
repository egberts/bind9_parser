#!/usr/bin/env python3
"""
File: isc_trusted_keys.py

Clause: trusted-keys

Title: Statement for Trusted Keys

Description: Provides trusted-key-related grammar in
             PyParsing engine for ISC-configuration style
"""
from pyparsing import Word, alphanums, Group, Keyword, Literal, ZeroOrMore
from bind9_parser.isc_utils import semicolon, parse_me, lbrack, rbrack, number_type,\
    squote, dquote, Combine, ungroup
from bind9_parser.isc_domain import rr_domain_name_or_wildcard_type

# From now on, all new installs of ISC Bind9 should use dnssec-validation auto; in place of trusted-keys.
# source: https://github.com/webmin/webmin/issues/617
trusted_keyname_type = (
    rr_domain_name_or_wildcard_type
    | Literal('.')
)('domain')
trusted_keyname_type.setName('<domain_name>')

trusted_keyname_dquoted = Combine(
        Literal('"').suppress()
        - trusted_keyname_type
        + Literal('"').suppress()
)
# keyname_dquoted.setName('keyname_dquoted')

trusted_keyname_squoted = Combine(
        Literal("'").suppress()
        - trusted_keyname_type
        + Literal("'").suppress()
)
# keyname_dquoted.setName('keyname_squoted')

trusted_key_domain_name = Group(
    trusted_keyname_dquoted
    | trusted_keyname_squoted
    | trusted_keyname_type
)

trusted_key_flags_type = number_type('flags')
trusted_key_flags_type.setName('<key-flags-id>')

trusted_key_protocol_type = number_type('protocol_id')
trusted_key_protocol_type.setName('<key-protocol-id>')

trusted_key_algorithm_name = Word(alphanums + '-')('algorithm')
trusted_key_algorithm_name.setName('<key-algorithm>')

trusted_key_algorithm_type = number_type('algorithm_id')
trusted_key_algorithm_type.setName('<key-algorithm-id>')


# Secret are in base64 encoding scheme with 2-char paddings (RFC 1421)
# Handles up to 16K encoding
charset_key_secret_base = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
charset_key_secret_base_squote_allowed = charset_key_secret_base + "'"
charset_key_secret_base_dquote_allowed = charset_key_secret_base + '"'

quoted_trusted_key_secret_type = (
    Combine(squote + Word(charset_key_secret_base_dquote_allowed) + squote)
    | Combine(dquote + Word(charset_key_secret_base_squote_allowed) + dquote)
)
quoted_trusted_key_secret_type.setName('<quoted-key-secret>')

#  domain name, flags, protocol, algorithm, and the Base64
#  representation of the key data.

trusted_keys_statements_set = (
    Keyword('trusted-keys').suppress()
    + lbrack
    + Group(
        ungroup(trusted_key_domain_name)('domain')
        + trusted_key_flags_type
        - trusted_key_protocol_type
        - trusted_key_algorithm_type
        - quoted_trusted_key_secret_type
        + semicolon
    )('')
    + rbrack
    + semicolon
)('trusted_keys')

trusted_keys_statements_series = (
    ZeroOrMore(
        trusted_keys_statements_set
    )
)('trusted_keys')
