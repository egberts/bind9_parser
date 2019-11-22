#!/usr/bin/env python3.7
"""
File: isc_clause_masters.py

Clause: masters

Title: Clause Statement for Master Servers

Description: Provides master-related grammar in PyParsing engine
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


# Quoteable masters name
# Yes, ISC Bind9 supports period in master_name_type
charset_master_name = srange('[A-Za-z0-9]') + '_-.'
master_name_type = Word(charset_master_name)('master_name_type')
master_name_type.setName('<master_name>')
master_name_type_squotable = Word(charset_master_name + '"')
master_name_type_dquotable = Word(charset_master_name + "'")

master_name_type_with_squote = Combine(
    dquote
    - master_name_type_dquotable
    + dquote
)

master_name_type_with_dquote = Combine(
    squote
    - master_name_type_squotable
    + squote
)

# the term masters_name used with the :
#   * masters clause,
#   * masters statement or
#   * also-notify statement of options/view/zone clauses.
master_id = (
        master_name_type_squotable
        | master_name_type_dquotable
        | master_name_type
)('master_id')

# { ( masters
#     | ipv4_address [ port integer ]
#     | ipv6_address [ port integer ]
#     | 'masters'                      # New in 9.15.1???
#   )
#   [ key string ];
#   ...
# };
masters_element_list = (
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
            master_id('addr')
            + Optional(key_id_keyword_and_name_pair)
            + semicolon
    )   # TODO investigate if a series of master_id is supported in masters clause
    | (
            master_id('addr')
            + semicolon
    )
)

masters_element_series = (
    OneOrMore(
        Group(    # Started indexing via list []
            masters_element_list
        )
    )('master_list')
)

# masters string [ port integer ]
#                [ dscp integer ]
#                {
#                    ( masters
#                      | ipv4_address [ port integer ]
#                      | ipv6_address [ port integer ]
#                    )
#                    [ key string ];
#                    ...
#                };
clause_stmt_masters_standalone = (
    Keyword('masters').suppress()
    - Group(
        master_id('master_id')
        - Optional(inet_ip_port_keyword_and_number_element)
        - Optional(inet_dscp_port_keyword_and_number_element)
        - Group(
            lbrack
            + masters_element_series('')
            + rbrack
        )('master_list')
    )
    + semicolon
)('masters')

# clause_stmt_masters_series cannot be used within 'zone' clause, use clause_stmt_masters_set instead
clause_stmt_masters_series = (
    OneOrMore(
            clause_stmt_masters_standalone
    )
)('masters')
clause_stmt_masters_series.setName('masters <name> key <key_id>')

