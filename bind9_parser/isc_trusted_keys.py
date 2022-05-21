#!/usr/bin/env python3
"""
File: isc_trusted_keys.py

Statement: trusted_keys

Title: Statement statement for 'trusted-keys'

Description: 

  Used in 'view'-only clauses

  Statement Grammar:

    trusted-keys { 
        string ( 
            static-key |
            initial-key | 
            static-ds |
            initial-ds )
        integer integer integer
        quoted_string; 
        ... 
        };

References:

  * https://egbert.net/blog/articles/dns-rr-key.html

"""
from pyparsing import Word, alphanums, Group, Keyword, ZeroOrMore, OneOrMore, Optional, nums

from bind9_parser.isc_utils import semicolon, lbrack, rbrack, \
        iso8601_duration, quotable_name, fqdn_name, quoted_base64, \
        lbrack, rbrack, quoted_name, quoted_path_name, isc_boolean

# NOTE: If any declaration here is to be used OUTSIDE of 
# the 'trusted_keys' clause, it should instead be defined within isc_utils.py


#  integer - key id 
#    range: 0-65535
#      256 - zone-signed key
#      257 - key-signed key
#  command: dnssec-keygen -N
trusted_keys_stmt_key_id_integer = (
            Word(nums, min=1, max=5)
        )

#  integer - protocol_type
#    range: 0-255
#             0 = reserved
#             1 = TLS
#             2 = email
#             3 = DNSSEC
#             4 = IPSEC
#             255 = any
#  command: dnssec-keygen -p XXX
#
trusted_keys_protocol_type_integer = (
            Word(nums, min=1, max=3)
        )

#  integer -  algorithm id
#    range: 0-255
#       8 - RSA-SHA256
#       10 - RSA-SHA512
#       13 - ECDSA-P256-SHA256
#       14 - ECDSA-P384-SHA384
#       15 - ED25519
#       16 - ED448
#  command: dnssec--keygen -a XXX
trusted_keys_algorithm_id_integer = (
            Word(nums, min=1, max=3)
        )

#   trusted-keys { 
#       string ( 
#           static-key |
#           initial-key | 
#           static-ds |
#           initial-ds )
#       integer - key id (256=zone, 257=key)
#       integer - protocol type (3=DNS)
#       integer - algorithm (8,10,15)
#       quoted_string; 
#       ... 
#       };

trusted_keys_stmt_element = (
    (
        Group(
            fqdn_name('domain')
            + trusted_keys_stmt_key_id_integer('key_id')
            + trusted_keys_protocol_type_integer('protocol_type')
            + trusted_keys_algorithm_id_integer('algorithm_id')
            + quoted_base64('pubkey_base64')
        )
    )
    + semicolon
)

trusted_keys_stmt_element_series = (
                                        ZeroOrMore(
                                            trusted_keys_stmt_element(None)
                                        )
)

trusted_keys_stmt_standalone = (
    Keyword('trusted-keys').suppress()
    + lbrack
    + (
            Optional(trusted_keys_stmt_element_series)
    )('trusted_keys*')
    + rbrack
    + semicolon
)

trusted_keys_stmt_standalone.setName(\
    """trusted-keys { 
        string ( 
            static-key |
            initial-key | 
            static-ds |
            initial-ds )
        integer integer integer
        quoted_string; 
        ... };""")

trusted_keys_stmt_set = trusted_keys_stmt_standalone
trusted_keys_stmt_set.setName(\
    """trusted-keys { 
        string ( 
            static-key |
            initial-key | 
            static-ds |
            initial-ds )
        integer integer integer
        quoted_string; 
        ... };""")

# {0-*} statement
trusted_keys_stmt_series = (
    (
        ZeroOrMore( trusted_keys_stmt_set )
    )
)
trusted_keys_stmt_series.setName('trusted_keys <string> { ... }; ...')

