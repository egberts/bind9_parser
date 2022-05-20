#!/usr/bin/env python3
"""
File: isc_clause_http.py

Clause: http

Title: Clause statement for HTTP of DNS-over-HTTP connections

Description: 

  Statement Grammar:

    http <string> {
      endpoints { <quoted_string>; ... };
      listener-clients <integer>;
      streams-per-connection <integer>;
      };
"""
from pyparsing import Word, alphanums, Group, Keyword, ZeroOrMore, OneOrMore, Optional, nums
from bind9_parser.isc_utils import semicolon, lbrack, rbrack, \
        iso8601_duration, quotable_name,\
        lbrack, rbrack, quoted_name

# NOTE: If any declaration here is to be used OUTSIDE of 
# the 'http' clause, it should instead be defined within isc_utils.py

http_endpoints_element = (
                Keyword('endpoints').suppress()
                + lbrack
                + OneOrMore (
                    Group(
                        quoted_name('endpoint_name')
                        + semicolon
                    )
                )
                + rbrack
                + semicolon
            )('endpoints')

http_listener_clients_element = (
                Keyword('listener-clients').suppress()
                + Word(nums, min=1, max=9)('listener_clients')
                + semicolon
            )

http_streams_per_conns_element = (
                Keyword('streams-per-connections').suppress()
                + Word(nums, min=1, max=9)('streams_per_connections')
                + semicolon
            )

clause_stmt_http_standalone = (
        Keyword('http').suppress()
        - Group(
            quotable_name('http_name')
            + lbrack
            + http_endpoints_element
            + http_listener_clients_element
            + http_streams_per_conns_element
            + rbrack
        )('http*')
        + semicolon
).setName('http <name> { endpoints { <quoted_string>; ... }; listener-clients <integer>; streams-per-connections <integer>; };')

clause_stmt_http_set = clause_stmt_http_standalone.setName('http <name> { endpoints { <quoted_string>; ... }; listener-clients <integer>; streams-per-connections <integer>; };')

# {0-*} statement
clause_stmt_http_series = ZeroOrMore( clause_stmt_http_set )
clause_stmt_http_series.setName('http <string> { ... }; ...')

