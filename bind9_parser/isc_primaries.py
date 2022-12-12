#!/usr/bin/env python3
"""
File: isc_primaries.py

Statement: 'primaries'

Title: Primary Servers statement for Zone clauses

Description: Provides primary-related grammar in PyParsing engine
             for ISC-configuration style
"""
from pyparsing import OneOrMore, Group, Optional, ungroup, ZeroOrMore, Combine
from bind9_parser.isc_utils import lbrack, rbrack, semicolon, \
    key_id_keyword_and_name_pair, tls_id_keyword_and_name_pair, \
    primaries_id, primaries_keyword
from bind9_parser.isc_inet import ip4_addr, ip6_addr,\
    inet_ip_port_keyword_and_number_element,\
    inet_dscp_port_keyword_and_number_element


#         (
#             <remote-servers>
#             | <ipv4_address> [ port <integer> ]
#             | <ipv6_address> [ port <integer> ]
#         )

primaries_remoteserver_element = (
    (
        ip4_addr('ip4_addr')
        + Optional(inet_ip_port_keyword_and_number_element)
        + Optional(key_id_keyword_and_name_pair)
    )('').setName('<ip4-addr>')
    ^ (
            ip6_addr('ip6_addr')
            + Optional(inet_ip_port_keyword_and_number_element)
            + Optional(key_id_keyword_and_name_pair)
    )('').setName('<ip6-addr>')
    ^ (
            primaries_id('primaries_name')
            + Optional(key_id_keyword_and_name_pair)
    )('').setName('<primaries-name> [ key "ABCDEFGHIJKLMNO" ]')   # TODO investigate if a series of primary_id is supported in primaries clause
    ^ (
            primaries_id('primaries_name')
    )('').setName('<primaries-name>')
).setName('<remote-server>|<ip4-addr>|<ip6-addr>')

# one remote server (ends with a semicolon)
#
#         (
#             <remote-servers>
#             | <ipv4_address> [ port <integer> ]
#             | <ipv6_address> [ port <integer> ]
#         )
#         [ key <string> ]
#         [ tls <string> ];

primaries_remoteserver_set = (
    Group(
        primaries_remoteserver_element('')
        + Optional(key_id_keyword_and_name_pair)
        + Optional(tls_id_keyword_and_name_pair)
    )('remote_server')
    - semicolon
).setName('<remote-server>|<ip4-addr>|<ip6-addr> [ key <key-value> ] [ tls <tls-value> ];')

# a set of remote servers (ends with a right-brace)
primaries_remoteserver_element_series = (
    OneOrMore(
        Group(    # Started indexing via list []
            primaries_remoteserver_set
        )
    )('remote_servers')
).setName('<remote-server>|<ip4-addr>|<ip6-addr> [ key <key-value> ] [ tls <tls-value> ]; ...')

# zone <zone-name> {
#     primaries [ port <integer> ] [ dscp <integer> ]
#     {
#         (
#             <remote-servers>
#             | <ipv4_address> [ port <integer> ]
#             | <ipv6_address> [ port <integer> ]
#         )
#         [ key <string> ]
#         [ tls <string> ];
#       ...
#     };
# };

# Separation is required of primaries list fields to ensure non-circular regex
# between the 'clause' (clause_stmt_primaries_standalone)
# and 'statement' (zone_stmt_primaries_standalone) variants of 'primaries'.


# Used only as 'primaries' statement (ONCE) within 'zone' clause
zone_stmt_primaries_standalone = (
    Group(
        primaries_keyword
        - (
            (
                Optional(inet_ip_port_keyword_and_number_element)
                - Optional(inet_dscp_port_keyword_and_number_element)
            )
            ^ (
                Optional(inet_dscp_port_keyword_and_number_element)
                - Optional(inet_ip_port_keyword_and_number_element)
            )
        )
        - lbrack
        - ZeroOrMore(    # Started indexing via list []
            Group(
                primaries_remoteserver_set
            )('remote_servers*')
        )('')
        - rbrack
    )('primaries')
    + semicolon
).setName('primaries <remote-server-name> [ port <port-no> ] [ dscp <dscp-id> ] { <series-remote-servers> };')

