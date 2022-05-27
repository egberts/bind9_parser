#!/usr/bin/env python3.7
"""
File: isc_clause_primaries.py

Clause: 'primaries'

Title: Clause Statement for Primary Servers

Description: Provides primary-related grammar in PyParsing engine
             for ISC-configuration style
"""
from pyparsing import OneOrMore, Group, Keyword, Optional, Word,\
    srange, Combine, ZeroOrMore, ungroup
from bind9_parser.isc_utils import lbrack, rbrack, semicolon, \
    dquote, squote, key_id_keyword_and_name_pair, \
    primary_id
from bind9_parser.isc_inet import ip4_addr, ip6_addr, ip46_addr,\
    inet_ip_port_keyword_and_number_element,\
    inet_dscp_port_keyword_and_number_element
from bind9_parser.isc_rr import rr_domain_name_or_root


# { ( primaries
#     | ipv4_address [ port integer ]
#     | ipv6_address [ port integer ]
#     | 'primaries'                      # New in 9.15.1???
#   )
#   [ key string ];
#   ...
# };
primaries_element_list = (
    (
        ip4_addr('ip4_addr')
        + Optional(inet_ip_port_keyword_and_number_element)
        + Optional(key_id_keyword_and_name_pair)
        + semicolon
    )
    | (
            ip6_addr('ip6_addr')
            + Optional(inet_ip_port_keyword_and_number_element)
            + Optional(key_id_keyword_and_name_pair)
            + semicolon
    )
    | (
            primary_id('primary_name')
            + Optional(key_id_keyword_and_name_pair)
            + semicolon
    )   # TODO investigate if a series of primary_id is supported in primaries clause
    | (
            primary_id('primary_name')
            + semicolon
    )
)

primaries_element_series = (
    OneOrMore(
        Group(    # Started indexing via list []
            primaries_element_list
        )
    )('primary_list')
)

# primaries string [ port integer ]
#                [ dscp integer ]
#                {
#                    ( primaries
#                      | ipv4_address [ port integer ]
#                      | ipv6_address [ port integer ]
#                    )
#                    [ key string ];
#                    ...
#                };

primary_keyword = (
        Keyword('primaries').suppress()
        ^ Keyword('masters').suppress()
        )
clause_stmt_primaries_standalone = (
    primary_keyword
    - Group(
        primary_id('primary_id')
        - Optional(inet_ip_port_keyword_and_number_element)
        - Optional(inet_dscp_port_keyword_and_number_element)
        - Group(
            lbrack
            + primaries_element_series('')
            + rbrack
        )('primary_list')
    )
    + semicolon
)('primaries')

# clause_stmt_primaries_series cannot be used within 'zone' clause, use clause_stmt_primaries_set instead
clause_stmt_primaries_series = (
    OneOrMore(
            clause_stmt_primaries_standalone
    )
)('primaries')
clause_stmt_primaries_series.setName('primaries <name> key <key_id>')

