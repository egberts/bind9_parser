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
    dquote, squote, key_id_keyword_and_name_pair
from bind9_parser.isc_inet import ip4_addr, ip6_addr, ip46_addr,\
    inet_ip_port_keyword_and_number_element,\
    inet_dscp_port_keyword_and_number_element
from bind9_parser.isc_rr import rr_domain_name_or_root


# Quoteable primary name
# Yes, ISC Bind9 supports period in primary_name_type
charset_primary_name = srange('[A-Za-z0-9]') + '_-.'
primary_name_type = Word(charset_primary_name)('primary_name_type')
primary_name_type.setName('<primary_name>')
primary_name_type_squotable = Word(charset_primary_name + '"')
primary_name_type_dquotable = Word(charset_primary_name + "'")

primary_name_type_with_squote = Combine(
    dquote
    - primary_name_type_dquotable
    + dquote
)

primary_name_type_with_dquote = Combine(
    squote
    - primary_name_type_squotable
    + squote
)

# the term primary_name used with the :
#   * primaries clause,
#   * primaries statement or
#   * also-notify statement of options/view/zone clauses.
primary_id = (
        primary_name_type_squotable
        | primary_name_type_dquotable
        | primary_name_type
)('primary_id')

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
        ip4_addr('addr')
        + Optional(inet_ip_port_keyword_and_number_element)
        + Optional(key_id_keyword_and_name_pair)
        + semicolon
    )
    | (
            ip6_addr('addr')
            + Optional(inet_ip_port_keyword_and_number_element)
            + Optional(key_id_keyword_and_name_pair)
            + semicolon
    )
    | (
            primary_id('addr')
            + Optional(key_id_keyword_and_name_pair)
            + semicolon
    )   # TODO investigate if a series of primary_id is supported in primaries clause
    | (
            primary_id('addr')
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
clause_stmt_primaries_standalone = (
    Keyword('primaries').suppress()
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

