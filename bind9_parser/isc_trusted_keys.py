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
from pyparsing import Word, Group, Keyword, ZeroOrMore, OneOrMore, nums

from bind9_parser.isc_utils import semicolon, \
        fqdn_name, quoted_base64, \
        lbrack, rbrack
# NOTE: If any declaration here is to be used OUTSIDE
# the 'trusted_keys' clause, it should instead be defined within isc_utils.py


#  integer - key id 
#    range: 0-65535
#      256 - zone-signed key
#      257 - key-signed key
#  command: dnssec-keygen -N
trusted_keys_stmt_key_id_integer = (
    Word(nums, min=1, max=5)
        )
trusted_keys_stmt_key_id_integer.setName('<key_id_number>')


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
trusted_keys_protocol_type_integer.setName('<protocol_type_id>')

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
trusted_keys_algorithm_id_integer.setName('<algorithm_id_number>')

#       string (
#           static-key |
#           initial-key | 
#           static-ds |
#           initial-ds )
#       integer - key id (256=zone, 257=key)
#       integer - protocol type (3=DNS)
#       integer - algorithm (8,10,15)
#       quoted_string; 

trusted_keys_stmt_group_set = (
    (
        Group(
            fqdn_name('domain')
            - trusted_keys_stmt_key_id_integer('key_id')
            - trusted_keys_protocol_type_integer('protocol_type')
            - trusted_keys_algorithm_id_integer('algorithm_id')
            - quoted_base64('pubkey_base64')
        )
        ('trusted_keys*')
        # do use '*' in 'trusted_keys' to aggregate multiple 'trusted-keys' together in one list group
    )
    + semicolon
)

#  1:1+N for things inside the 'trusted-key' curly-brace '{}' group
trusted_keys_stmt_group_series = (
                                        OneOrMore(
                                            trusted_keys_stmt_group_set
                                        )
)
trusted_keys_stmt_group_series.setName('<domain> <integer> <integer> <integer> <base64_string>; ... ')

trusted_keys_stmt_standalone = (
    Keyword('trusted-keys').suppress()
    + lbrack
    - (
            trusted_keys_stmt_group_series
    )
    + rbrack
    + semicolon
)
trusted_keys_stmt_standalone.setName(
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
trusted_keys_stmt_set.setName(
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
        ZeroOrMore(trusted_keys_stmt_set)
    )  # do not insert ('trusted_keys') here; we want to capture all
    # subzones into same 'trusted_keys' defined earlier 'by group'
)
trusted_keys_stmt_series.setName('trusted_keys <string> { ... }; ...')
