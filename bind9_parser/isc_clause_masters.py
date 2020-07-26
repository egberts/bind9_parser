#!/usr/bin/env python3.7
"""
File: isc_clause_mains.py

Clause: mains

Title: Clause Statement for Main Servers

Description: Provides main-related grammar in PyParsing engine
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


# Quoteable mains name
# Yes, ISC Bind9 supports period in main_name_type
charset_main_name = srange('[A-Za-z0-9]') + '_-.'
main_name_type = Word(charset_main_name)('main_name_type')
main_name_type.setName('<main_name>')
main_name_type_squotable = Word(charset_main_name + '"')
main_name_type_dquotable = Word(charset_main_name + "'")

main_name_type_with_squote = Combine(
    dquote
    - main_name_type_dquotable
    + dquote
)

main_name_type_with_dquote = Combine(
    squote
    - main_name_type_squotable
    + squote
)

# the term mains_name used with the :
#   * mains clause,
#   * mains statement or
#   * also-notify statement of options/view/zone clauses.
main_id = (
        main_name_type_squotable
        | main_name_type_dquotable
        | main_name_type
)('main_id')

# { ( mains
#     | ipv4_address [ port integer ]
#     | ipv6_address [ port integer ]
#     | 'mains'                      # New in 9.15.1???
#   )
#   [ key string ];
#   ...
# };
mains_element_list = (
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
            main_id('addr')
            + Optional(key_id_keyword_and_name_pair)
            + semicolon
    )   # TODO investigate if a series of main_id is supported in mains clause
    | (
            main_id('addr')
            + semicolon
    )
)

mains_element_series = (
    OneOrMore(
        Group(    # Started indexing via list []
            mains_element_list
        )
    )('main_list')
)

# mains string [ port integer ]
#                [ dscp integer ]
#                {
#                    ( mains
#                      | ipv4_address [ port integer ]
#                      | ipv6_address [ port integer ]
#                    )
#                    [ key string ];
#                    ...
#                };
clause_stmt_mains_standalone = (
    Keyword('mains').suppress()
    - Group(
        main_id('main_id')
        - Optional(inet_ip_port_keyword_and_number_element)
        - Optional(inet_dscp_port_keyword_and_number_element)
        - Group(
            lbrack
            + mains_element_series('')
            + rbrack
        )('main_list')
    )
    + semicolon
)('mains')

# clause_stmt_mains_series cannot be used within 'zone' clause, use clause_stmt_mains_set instead
clause_stmt_mains_series = (
    OneOrMore(
            clause_stmt_mains_standalone
    )
)('mains')
clause_stmt_mains_series.setName('mains <name> key <key_id>')

