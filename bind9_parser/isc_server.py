#!/usr/bin/env python3.7
"""
File: isc_server.py

Clause: server

Title: Statements Used Only By server Clause.

Description: Provides server-related grammar in PyParsing engine
             for ISC-configuration style
"""
from pyparsing import Group, Keyword, Word, nums, Optional, Literal, ZeroOrMore
from bind9_parser.isc_utils import isc_boolean, semicolon, number_type, \
    key_id, byte_type
from bind9_parser.isc_inet import ip4_addr_or_wildcard, ip6_addr_or_wildcard,\
    inet_ip_port_keyword_and_wildcard_element,\
    inet_dscp_port_keyword_and_number_element

#  Be careful of deleting any statements here
#
#  Over times, 'server' clause is ALSO incorporating these
#  statements (which in turn gets included by 'view' clause)
#
#  In short, ISC architects are moving statements around.
#
#  Redundancy is necessary here.

#   bogus ( yes | no );  # [ server ]
server_stmt_bogus = (
    Keyword('bogus')
    - isc_boolean('bogus')
    + semicolon
)

#  edns ( yes | no);  # [ server ]
server_stmt_edns = (
    Keyword('edns')
    - isc_boolean('edns')
    + semicolon
)


#  edns-version <number>;  # [ server ]
server_stmt_edns_version = (
    Keyword('edns-version')
    - byte_type('edns_version')
    + semicolon
)

#  keys <server_key>;  # [ server ]
server_stmt_keys = (
    Keyword('keys')    # ATM, despite plural form of 'keys', only a single key_id is supported (v9.15.1)
    + key_id('keys')
    + semicolon
)

#  Max theoretical UDP packet size is 65,507.
max_udp_size = number_type

#  max-udp-size <number>;  # [ server ]
server_stmt_max_udp_size = (
    Keyword('max-udp-size')
    - max_udp_size('max_udp_size')
    + semicolon
)

#   notify-source ( ip4_addr | * )
#       [ port ( <ip_port> | * ) ]
#       [ dscp <dscp_port> ]
#       ;
server_stmt_notify_source = (
    Keyword('notify-source')
    + Group(
        ip4_addr_or_wildcard('addr')
        + Optional(inet_ip_port_keyword_and_wildcard_element)
        + Optional(inet_dscp_port_keyword_and_number_element)
    )('notify_source')
    + semicolon
)  # list label [] removed because exactly one statement per opt/zone/view

#   notify-source ( ip6_addr | * )
#       [ port ( <ip_port> | * ) ]
#       [ dscp <dscp_port> ]
#       ;
server_stmt_notify_source_v6 = (
    Keyword('notify-source-v6')
    + Group(
        ip6_addr_or_wildcard('addr')
        + Optional(inet_ip_port_keyword_and_wildcard_element)
        + Optional(inet_dscp_port_keyword_and_number_element)
    )('notify_source_v6')
    + semicolon
)

#   padding <number>;  # [ server ]
server_stmt_padding = (
    Keyword('padding')
    + number_type('padding')
    + semicolon
)

#   query-source (
#                  [ address ]    # 'address' keyword is optional here
#                  ( ip4_addr | * )
#                  [ ( port <ip_port> | * ) ]
#                  [ dscp <dscp_port> ]
#                )
#                ;
server_stmt_query_source = (
    Keyword('query-source')
    + Group(
        (  # match-first
            ip4_addr_or_wildcard('ip4_addr_w')
            - Optional(inet_ip_port_keyword_and_wildcard_element)
            - Optional(inet_dscp_port_keyword_and_number_element('dscp_port'))
            + semicolon
        )
        | (
            Keyword('address').suppress()  # match-first
            - ip4_addr_or_wildcard('ip4_addr_w')
            - Optional(inet_ip_port_keyword_and_wildcard_element)
            - Optional(inet_dscp_port_keyword_and_number_element('dscp_port'))
            + semicolon

        )('')
    )('query_source')
)('')

#  query-source-v6 (
#                    [ address ]    # 'address' keyword is optional here
#                    ( ip6_addr | * )
#                    [ ( port <ip_port> | * ) ]
#                    [ dscp <dscp_port> ]
#                  )
#                  ;
server_stmt_query_source_v6 = (
    Keyword('query-source-v6')
    + Group(
        (
            Keyword('address').suppress()  # match-first
            - ip6_addr_or_wildcard('ip6_addr_w')
            - Optional(inet_ip_port_keyword_and_wildcard_element)
            - Optional(inet_dscp_port_keyword_and_number_element('dscp_port'))
            + semicolon

        )
        | (  # match-first
            ip6_addr_or_wildcard('ip6_addr_w')
            - Optional(inet_ip_port_keyword_and_wildcard_element)
            - Optional(inet_dscp_port_keyword_and_number_element('dscp_port'))
            + semicolon
        )('')
    )('query_source_v6')
)('')

#  request-expire <boolean>;  # [ server ]
server_stmt_request_expire = (
    Keyword('request-expire')
    - isc_boolean('request_expire')
    + semicolon
)


#  request-nsid <boolean>;  # [ server ]
server_stmt_request_nsid = (
    Keyword('request-nsid')
    + isc_boolean('request_nsid')
    + semicolon
)

#  send-cookie <boolean>;  # [ server ]
server_stmt_send_cookie = (
    Keyword('send-cookie')
    + isc_boolean('send_cookie')
    + semicolon
)

#  tcp-keepalive <boolean>;  # [ server ]
server_stmt_tcp_keepalive = (
    Keyword('tcp-keepalive')
    + isc_boolean('tcp_keepalive')
    + semicolon
)

#  tcp-only <boolean>;  # [ server ]
server_stmt_tcp_only = (
    Keyword('tcp-only')
    + isc_boolean('tcp_only')
    + semicolon
)

#  transfer-source ( <ip4_addr> | * )
#                  [ 'port' <ip_port> ]
#                  [ 'dscp' <dscp_port> ]
#                  ;
server_stmt_transfer_source = (
    Keyword('transfer-source').suppress()
    - Group(
        ip4_addr_or_wildcard('ip4_addr_w')
        + Optional(inet_ip_port_keyword_and_wildcard_element)
        + Optional(inet_dscp_port_keyword_and_number_element)
    )('transfer_source')
    + semicolon
)('')

#  transfer-source-v6 ( <ip4_addr> | * )
#                     [ 'port' <ip_port> ]
#                     [ 'dscp' <dscp_port> ]
#                     ;
server_stmt_transfer_source_v6 = (
    Keyword('transfer-source-v6').suppress()
    - Group(
        ip6_addr_or_wildcard('ip6_addr_w')
        + Optional(inet_ip_port_keyword_and_wildcard_element)
        + Optional(inet_dscp_port_keyword_and_number_element)
    )('transfer_source_v6')
    + semicolon
)

#   transfers number ; [ server ]
server_stmt_transfers = (
    Keyword('transfers')
    - number_type('transfers')
    + semicolon
)

#############################################################
# Server clause
#############################################################

# Keywords are in dictionary-order, but with longest pattern as
# having been listed firstly
# We do match-first (via '|') here, instead of match-longest.
server_statement_set = (
        server_stmt_bogus
        ^ server_stmt_edns_version
        ^ server_stmt_edns
        ^ server_stmt_keys
        ^ server_stmt_max_udp_size
        ^ server_stmt_notify_source_v6
        ^ server_stmt_notify_source
        ^ server_stmt_padding
        ^ server_stmt_query_source_v6
        ^ server_stmt_query_source
        ^ server_stmt_request_expire
        ^ server_stmt_request_nsid
        ^ server_stmt_send_cookie
        ^ server_stmt_tcp_keepalive
        ^ server_stmt_tcp_only
        ^ server_stmt_transfer_source_v6
        ^ server_stmt_transfer_source
        ^ server_stmt_transfers
)

server_statement_series = (
    ZeroOrMore(server_statement_set)
)
