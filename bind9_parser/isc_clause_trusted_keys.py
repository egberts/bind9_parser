#!/usr/bin/env python3
"""
File: isc_clause_trusted_keys.py

Clause: trusted_keys

Title: Clause statement for 'trusted-keys'

Description: 

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

from bind9_parser.isc_trusted_keys import trusted_keys_stmt_set, \
        trusted_keys_stmt_series

clause_stmt_trusted_keys_standalone = trusted_keys_stmt_set

clause_stmt_trusted_keys_set = trusted_keys_stmt_set
clause_stmt_trusted_keys_set.setName(\
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
clause_stmt_trusted_keys_series = trusted_keys_stmt_series
clause_stmt_trusted_keys_series.setName(\
    """trusted-keys { 
        string ( 
            static-key |
            initial-key | 
            static-ds |
            initial-ds )
        integer integer integer
        quoted_string; 
        ... };""")
