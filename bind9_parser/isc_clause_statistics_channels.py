#!/usr/bin/env python3
"""
File: isc_clause_statistics_channels.py

Clause: statistics_channels

Title: Clause statement for 'statistics-channels'

Description: 

  Statement Grammar:

    statistics-channels {
      inet ( ipv4_address | 
             ipv6_address |
             * ) 
           [ port ( integer | * ) ]
           [ allow { address_match_element; ...  } ];
    };
"""
from pyparsing import Group, Keyword, ZeroOrMore, OneOrMore, Optional
from bind9_parser.isc_utils import semicolon, \
    lbrack, rbrack
from bind9_parser.isc_inet import ip46_addr_or_wildcard, inet_ip_port_keyword_and_wildcard_element

# NOTE: If any declaration here is to be used OUTSIDE of 
# the 'statistics_channels' clause, it should instead be defined within isc_utils.py

clause_stmt_statistics_channels_standalone = (
        Keyword('statistics-channels').suppress()
        + lbrack
        + OneOrMore(
            Keyword('inet').suppress()
            + Group(
                Optional(ip46_addr_or_wildcard('ip_addr'))
                - Optional(inet_ip_port_keyword_and_wildcard_element('ip_port_w'))
                + OneOrMore(semicolon)
            )('statistics_channels*')
        )
        + rbrack
        + semicolon
)
clause_stmt_statistics_channels_standalone.setName(
    'statistics_channels <name> { endpoints { <quoted_string>; ... };'
    + 'listener-clients <integer>; streams-per-connections <integer>; };')

clause_stmt_statistics_channels_set = clause_stmt_statistics_channels_standalone

# {0-*} statement
clause_stmt_statistics_channels_series = ZeroOrMore(clause_stmt_statistics_channels_set)
clause_stmt_statistics_channels_series.setName('statistics_channels <string> { ... }; ...')
