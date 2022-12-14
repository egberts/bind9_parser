#!/usr/bin/env python3.7
"""
File: isc_clause_primaries.py

Clause: 'primaries'

Title: Clause Statement for Primary Servers

Description: Provides primary-related grammar in PyParsing engine
             for ISC-configuration style

    Only for zone-type: secondary, mirror, stub, & redirect

Syntax:
      primaries <string> [ port <integer> ] [ dscp <integer> ]
      {
          ( <remote-servers>
            | <ipv4_address> [ port <integer> ]
            | <ipv6_address> [ port <integer> ]
          )
         [ key <string> ]
         [ tls <string> ];
         ...
      };
"""
import copy
from pyparsing import Group, ungroup, ZeroOrMore
from bind9_parser.isc_utils import Optional, lbrack, rbrack, semicolon, \
    primaries_keyword, primaries_id
from bind9_parser.isc_inet import \
    inet_ip_port_keyword_and_number_element, \
    inet_dscp_port_keyword_and_number_element
from bind9_parser.isc_primaries import primaries_remoteserver_set


clause_cloned_primaries_remoteserver_set = copy.deepcopy(primaries_remoteserver_set)

# Used only as top-level clause
clause_stmt_primaries_standalone = (
    Group(
        primaries_keyword
        - primaries_id('primaries_id')
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
                clause_cloned_primaries_remoteserver_set
            )('remote_servers*')
        )('')
        - rbrack
    )('primaries')
    + semicolon
)('').setName('primaries <remote-server-name> [ port <port-no> ] [ dscp <dscp-id> ] { <series-remote-servers> };')

# clause_stmt_primaries_series cannot be used within 'zone' clause, use clause_stmt_primaries_set instead
clause_stmt_primaries_series = (
    ZeroOrMore(
        Group(
            ungroup(clause_stmt_primaries_standalone(''))('')
        )('')
    )('')
)('primaries').setName("""primaries [ port <port> ] [ dscp <dscp> ] {
    ( <fqdn> | <ip4_addr> | <ip6_addr> ) [ key <key-value> ] [ tls <tls-value ]; ... };""")
clause_stmt_primaries_series.setName('primaries <name> key <key_id>')
