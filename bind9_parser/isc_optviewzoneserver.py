#!/usr/bin/env python3.7
"""
File: isc_optviewzoneserver.py

Clause: options, view, zone, server

Title:  Statements Used Only By options, view, zone, And server Clauses

Description: Provides statement support for ones found in all
             four clauses: options, view, zone, server
             PyParsing engine for ISC-configuration style
"""
from pyparsing import Group, Keyword, OneOrMore, ZeroOrMore, Optional, ungroup
from bind9_parser.isc_utils import semicolon, lbrack, rbrack, parse_me
from bind9_parser.isc_clause_key import key_id
from bind9_parser.isc_inet import ip46_addr, \
    inet_ip_port_keyword_and_number_element,\
    inet_dscp_port_keyword_and_number_element
from bind9_parser.isc_clause_masters import master_id


#  Note:  Be careful of deleting any options/view/zone/server
#         statements here because the ISC architects are
#         moving some server statements around.
#
#         So we want to ensure that such a statement is found in
#         exactly all four clauses (options, view, zone, and server).

# also-notify [port gp-num] [dscp gd-num] {
#     ( masters-list|IP-address )
#     [port p-num]
#     [dscp d-num]
#     [key key-name]
#     ;
#   [... ;]
# };
#  Note: no more 'masters-list' since 9.9+
optviewzoneserver_stmt_also_notify_element_set = (
        (
            (
                ip46_addr('addr')
                | master_id('addr')
            )
            + Optional(inet_ip_port_keyword_and_number_element)
            - Optional(inet_dscp_port_keyword_and_number_element)
        )
        + Optional(Keyword('key') + key_id)
        + semicolon
)
optviewzoneserver_also_notify_element_series = OneOrMore(
    Group(  # this is essential for multiple entries within a List {}
        optviewzoneserver_stmt_also_notify_element_set
    )
)

# also-notify [ port integer ]
#             [ dscp integer ]
#             {
#                 ( masters
#                   | ipv4_address [ port integer ]
#                   | ipv6_address [ port integer ]
#                 )
#                 [ key string ]
#                 ;
#                 ...
#             };
optviewzoneserver_stmt_also_notify = (
    Keyword('also-notify').suppress()
    - Optional(inet_ip_port_keyword_and_number_element)
    - Optional(inet_dscp_port_keyword_and_number_element)
    + lbrack
    - optviewzoneserver_also_notify_element_series
    + rbrack
    + semicolon
)('also_notify')

# Keywords are in dictionary-order, but with longest pattern as having been listed firstly
optviewzoneserver_statements_set = (
    # optviewzoneserver_stmt_also_notify has been removed from 'server' clause
    # but left that statement here for backward compatibility
    optviewzoneserver_stmt_also_notify
)

optviewzoneserver_statements_series = (
    OneOrMore(
        optviewzoneserver_statements_set
    )
)
