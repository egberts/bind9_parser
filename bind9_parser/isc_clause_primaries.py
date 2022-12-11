#!/usr/bin/env python3.7
"""
File: isc_clause_primaries.py

Clause: 'primaries'

Title: Clause Statement for Primary Servers

Description: Provides primary-related grammar in PyParsing engine
             for ISC-configuration style
             
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
from pyparsing import OneOrMore, Group
from bind9_parser.isc_utils import Optional, lbrack, rbrack, semicolon, \
    primaries_keyword, primaries_id
from bind9_parser.isc_inet import \
    inet_ip_port_keyword_and_number_element,\
    inet_dscp_port_keyword_and_number_element
from bind9_parser.isc_primaries import primaries_remoteserver_element_series


clause_cloned_primaries_remoteserver_element_series = copy.deepcopy(primaries_remoteserver_element_series)

# Used only as top-level clause
clause_stmt_primaries_standalone = (
        primaries_keyword
        - primaries_id
        - Optional(inet_ip_port_keyword_and_number_element)
        - Optional(inet_dscp_port_keyword_and_number_element)
        - lbrack
        + clause_cloned_primaries_remoteserver_element_series('')
        - rbrack
        + semicolon
)('primaries')

# clause_stmt_primaries_series cannot be used within 'zone' clause, use clause_stmt_primaries_set instead
clause_stmt_primaries_series = (
    OneOrMore(
            clause_stmt_primaries_standalone
    )
)('primaries')
clause_stmt_primaries_series.setName('primaries <name> key <key_id>')
