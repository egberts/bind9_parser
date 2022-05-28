#!/usr/bin/env python3.7
"""
File: isc_optviewzoneserver.py

Clause: options, view, zone, server

Title:  Statements Used Only By options, view, zone, And server Clauses

Description: Provides statement support for ones found in all
             four clauses: options, view, zone, server
             PyParsing engine for ISC-configuration style
"""
from pyparsing import Group, Keyword, OneOrMore, Optional, ungroup
from bind9_parser.isc_utils import semicolon, lbrack, rbrack, tls_algorithm_name,\
    primary_id, isc_boolean

from bind9_parser.isc_clause_key import key_id

from bind9_parser.isc_inet import \
    ip46_addr_and_port_list_set, \
    inet_ip_port_keyword_and_number_element, \
    inet_dscp_port_keyword_and_number_element


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
optviewzoneserver_also_notify_subgroup_subelement1 = (
    (
        Keyword('key')
        + key_id
        - Optional(
            Keyword('tls')
            + tls_algorithm_name
        )
    )
    ^ (
        Keyword('tls')
        + tls_algorithm_name
        + Optional(
            Keyword('key')
            + key_id
        )
    )
)
optviewzoneserver_also_notify_subgroup_subelement1.setName('[ key <key_id_name> ] [ tls <tls_algorithm_name> ]')

optviewzoneserver_also_notify_subgroup_element2 = (
        ip46_addr_and_port_list_set
        ^ primary_id('primary_name')
)
optviewzoneserver_also_notify_subgroup_element2.setName('[ ( <ip4>  <port> | <ip6>  <port> | <primary_name> ]')

optviewzoneserver_also_notify_subgroup_series = (
    OneOrMore(
        Group(
            optviewzoneserver_also_notify_subgroup_element2
            - Optional(optviewzoneserver_also_notify_subgroup_subelement1)
            + semicolon
        )('remote*')
    )
).setName('( [ ( <ip4>  <port> | <ip6>  <port> | <primary_name> ] ) [ key <key_id_name> ] [ tls <tls_algorithm_name> ]')
# also-notify
#             [ port integer ]
#             [ dscp integer ]  # added in v9.10
#             {
#                 (
#                   (
#                     ipv4_address [ port integer ]
#                     | ipv6_address [ port integer ]
#                     )
#                   [ port integer ]
#                   )
#                 [ key string ]  # added in v9.9
#                 [ tls string ]  # added in v9.18?
#              )
#              | (
#                 <primary_name>  # added in v9.9
#                 )
#             ;
#             };

optviewzoneserver_also_notify_group_element_set = (
    (
        ungroup(inet_ip_port_keyword_and_number_element)('port')
        - Optional(ungroup(inet_dscp_port_keyword_and_number_element)('dscp'))
    )
    ^ (
        ungroup(inet_dscp_port_keyword_and_number_element)('dscp')
        - Optional(ungroup(inet_ip_port_keyword_and_number_element)('port'))
    )
).setName('[ port <port> ] | [ dscp <dscp> ]')

optviewzoneserver_stmt_also_notify = (
    Keyword('also-notify').suppress()
    - Group(
        Optional(optviewzoneserver_also_notify_group_element_set)
        + lbrack
        - (
            optviewzoneserver_also_notify_subgroup_series
        )
    )('also-notify')
    + rbrack
    + semicolon
)
optviewzoneserver_stmt_also_notify.setName(
    'also-notify [ port <port> ] [ dscp <dscp> { ( <primary_name> | <ip4_addr> | <ip6_addr> ); };')

optviewzoneserver_stmt_request_expire = (
    Keyword('request-expire').suppress()
    - isc_boolean('request_expire')
    - semicolon
).setName('request-expire <boolean>;')

# Keywords are in dictionary-order, but with longest pattern as having been listed firstly
optviewzoneserver_statements_set = (
    # optviewzoneserver_stmt_also_notify has been removed from 'server' clause
    # but left that statement here for backward compatibility
    optviewzoneserver_stmt_also_notify
    ^ optviewzoneserver_stmt_request_expire
)

optviewzoneserver_statements_series = (
    OneOrMore(
        optviewzoneserver_statements_set
    )
)
