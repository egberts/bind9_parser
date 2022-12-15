#!/usr/bin/env python3
"""
File: isc_optviewserver.py

Clause: options

Title: Statements Used Only By options, view, And server Clauses.

Description: Provides 'options' and 'server'-related grammar in
             PyParsing engine for ISC-configuration style
"""
from pyparsing import ZeroOrMore, Keyword, Literal, Optional, Group
from bind9_parser.isc_utils import semicolon, isc_boolean, number_type
from bind9_parser.isc_inet import ip4_addr_or_wildcard, ip6_addr_or_wildcard, \
    inet_ip_port_keyword_and_wildcard_element, \
    inet_dscp_port_keyword_and_number_element


#  edns-udp-size <number>;  # [ server ]
optviewserver_stmt_edns_udp_size = (
    Keyword('edns-udp-size')
    - number_type('edns_udp_size')  # valid range is 512-4096
    + semicolon
)

#  provide-ixfr ( yes | no) ; [ Opt, View, server ]
optviewserver_stmt_provide_ixfr = (
    Keyword('provide-ixfr')
    - isc_boolean('provide_ixfr')
    + semicolon
)

#  query-source address 10.53.0.2;  [ Opt, View, Server ]
#
#  query-source (
#      ( [ address ] ( <ipv4_address> | * ) [ port ( <integer> | * ) ] )
#      | ( [ [ address ] ( <ipv4_address> | * ) ] port ( <integer> | * ) ) ) [ dscp <integer> ];
#
optviewserver_stmt_query_source = (
    Keyword('query-source').suppress()
    - Group(
        (
            (
                inet_ip_port_keyword_and_wildcard_element
            )
            | (
                Keyword('address').suppress()
                - ip4_addr_or_wildcard('ip4_addr_w')
                - Optional(inet_ip_port_keyword_and_wildcard_element)
            )
            | (
                ip4_addr_or_wildcard('ip4_addr_w')
                - Optional(inet_ip_port_keyword_and_wildcard_element)
            )
        )
        - Optional(
            inet_dscp_port_keyword_and_number_element
        )
    )('query_source')
    - semicolon
).setName("""query-source (
    ( [ address ] ( <ipv4_address> | * ) [ port ( <integer> | * ) ] )
    | ( [ [ address ] ( <ipv4_address> | * ) ] port ( <integer> | * ) ) ) [ dscp <integer> ];
""")

#  query-source-v6 (
#      ( [ address ] ( <ipv6_address> | * ) [ port ( <integer> | * ) ] )
#      | ( [ [ address ] ( <ipv6_address> | * ) ] port ( <integer> | * ) ) ) [ dscp <integer> ];
optviewserver_stmt_query_source_v6 = (
    Keyword('query-source-v6')
    - Group(
        (
            (
                inet_ip_port_keyword_and_wildcard_element
            )
            | (
                Keyword('address').suppress()
                - ip6_addr_or_wildcard('ip6_addr_w')
                - Optional(inet_ip_port_keyword_and_wildcard_element)
            )
            | (
                ip6_addr_or_wildcard('ip6_addr_w')
                - Optional(inet_ip_port_keyword_and_wildcard_element)
            )
        )
        - Optional(
            inet_dscp_port_keyword_and_number_element
        )
    )('query_source_v6')
    - semicolon
).setName("""query-source-v6 (
    ( [ address ] ( <ipv6_address> | * ) [ port ( <integer> | * ) ] )
    | ( [ [ address ] ( <ipv6_address> | * ) ] port ( <integer> | * ) ) ) [ dscp <integer> ];
"""
          )

#  request-ixfr <boolean>;  # [ server ]  # v9.1.0+
optviewserver_stmt_request_ixfr = (
    Keyword('request-ixfr')
    + isc_boolean('request_ixfr')
    + semicolon
)

#  send-cookie  <boolean>;  # [ server ]  # v9.1.0+
optviewserver_stmt_send_cookie = (
    Keyword('send-cookie')
    + isc_boolean('send_cookie')
    + semicolon
)

#  transfer-format ( 'one-answer' | 'many-answers' )  # [ server ]
optviewserver_stmt_transfer_format = (
    Keyword('transfer-format')
    + (
        Literal('one-answer')
        | Literal('many-answers')
    )('transfer_format')
    + semicolon
)

# Keywords are in dictionary-order, but with longest pattern as
# having been listed firstly
optviewserver_statements_set = (
    optviewserver_stmt_edns_udp_size
    ^ optviewserver_stmt_provide_ixfr
    ^ optviewserver_stmt_query_source
    ^ optviewserver_stmt_query_source_v6
    ^ optviewserver_stmt_request_ixfr
    ^ optviewserver_stmt_send_cookie
    ^ optviewserver_stmt_transfer_format
)

optviewserver_statements_series = (
    ZeroOrMore(
        optviewserver_statements_set
    )
)
