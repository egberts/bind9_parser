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
from bind9_parser.isc_trusted_keys import trusted_keys_stmt_set, \
        trusted_keys_stmt_series

clause_stmt_trusted_keys_standalone = trusted_keys_stmt_set

clause_stmt_trusted_keys_set = trusted_keys_stmt_set
clause_stmt_trusted_keys_set.setName(
    """trusted-keys { 
        string ( 
            static-key |
            initial-key | 
            static-ds |
            initial-ds )
        <flags> <protocol_type> <algorithm_id>
        <quoted_base64_string>; 
        ... };""")

# {0-*} statement
clause_stmt_trusted_keys_series = trusted_keys_stmt_series
clause_stmt_trusted_keys_series.setName(
    """trusted-keys { ... }; [ trusted-keys { ... }; ... ]"""
    )
