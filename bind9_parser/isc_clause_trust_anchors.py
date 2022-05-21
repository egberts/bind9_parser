#!/usr/bin/env python3
"""
File: isc_clause_trust_anchors.py

Clause: trust_anchors

Title: Clause statement for 'trust-anchors'

Description: 

  Statement Grammar:

    trust-anchors { 
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
# the 'trust_anchors' clause, it should instead be defined within isc_utils.py


#       string ( 
#           static-key |
#           initial-key | 
#           static-ds |
#           initial-ds )
#
trust_anchors_stmt_key_type_keyword = (
            Keyword('static-key')
            | Keyword('initial-key')
            | Keyword('static-ds')
            | Keyword('initial-ds')
            )('key_type')

#  integer - key id 
#    range: 0-65535
#      256 - zone-signed key
#      257 - key-signed key
#  command: dnssec-keygen -N
trust_anchors_stmt_key_id_integer = (
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
trust_anchors_protocol_type_integer = (
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
trust_anchors_algorithm_id_integer = (
            Word(nums, min=1, max=3)
        )

#   trust-anchors { 
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

trust_anchors_stmt_element = (
    Group(
        fqdn_name('domain')
        + trust_anchors_stmt_key_type_keyword('key_type')
        + trust_anchors_stmt_key_id_integer('key_id')
        + trust_anchors_protocol_type_integer('protocol_type')
        + trust_anchors_algorithm_id_integer('algorithm_id')
        + quoted_base64('pubkey_base64')
        )('trust_anchors*')
    + semicolon
)

trust_anchors_stmt_element_series = (
                                        OneOrMore(
                                            trust_anchors_stmt_element
                                        )(None)
)

clause_stmt_trust_anchors_standalone = (
    Keyword('trust-anchors').suppress()
    + lbrack
    + (
        ZeroOrMore(
            trust_anchors_stmt_element_series
        )
    )
    + rbrack
    + semicolon
)
clause_stmt_trust_anchors_standalone.setName('trust_anchors <string> { ca-file <string>; cert-file <string>; ciphers <string>; dhparam-file <quoted_string>; prefer-server-ciphers <boolean>; protocols { <string>; ... }; remote-hostname <quoted_string>; session-tickets <boolean>; };')

clause_stmt_trust_anchors_set = clause_stmt_trust_anchors_standalone
clause_stmt_trust_anchors_set.setName(\
    """trust_anchors <string> { 
    ca-file <string>; 
    cert-file <string>; 
    ciphers <string>; 
    dhparam-file <quoted_string>; 
    prefer-server-ciphers <boolean>; 
    protocols { <string>; ... }; 
    remote-hostname <quoted_string>; 
    session-tickets <boolean>; 
};""")

# {0-*} statement
clause_stmt_trust_anchors_series = ZeroOrMore( clause_stmt_trust_anchors_set )
clause_stmt_trust_anchors_series.setName('trust_anchors <string> { ... }; ...')

