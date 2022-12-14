#!/usr/bin/env python3
"""
File: isc_clause_parental_agents.py

Clause: parental_agents

Title: Clause statement for 'parental-agents'

Description: 

  Only for zone-type: primary, secondary

  Statement Grammar:

    parental-agents <string> [ port <integer> ] [ dscp <integer> ] {
            (
                <remote-servers> |
                <ipv4_address> [ port <integer> ] |
                <ipv6_address> [ port <integer> ]
            )
            [ key <string> ]
            [ tls <string> ]; ...
    };

"""
import copy
from pyparsing import Group, Keyword, \
    ZeroOrMore, OneOrMore, Optional, ungroup
from bind9_parser.isc_utils import semicolon, \
    quotable_name, \
    lbrack, rbrack
from bind9_parser.isc_inet import \
    inet_ip_port_keyword_and_number_element, \
    inet_dscp_port_keyword_and_number_element
from bind9_parser.isc_primaries import primaries_remoteserver_set


clause_cloned_parental_agent_remoteserver_set = copy.deepcopy(primaries_remoteserver_set)


clause_stmt_parental_agents_standalone = (
    Group(
        Keyword('parental-agents').suppress()
        - quotable_name('parental_agent_name')
        + Optional(inet_ip_port_keyword_and_number_element)
        + Optional(inet_dscp_port_keyword_and_number_element)
        + lbrack
        + OneOrMore(
            Group(
                ungroup(clause_cloned_parental_agent_remoteserver_set(''))  # definitely leave this at ''
            )('remote_servers*')
        )('')
        + rbrack
    )('parental_agents*')
    + semicolon
)('')

clause_stmt_parental_agents_set = clause_stmt_parental_agents_standalone
clause_stmt_parental_agents_standalone.setName(
    'parental_agents <name> [ port <integer> ] [ dscp <integer> ] { [<remote-server>|' +
    '( <ipv4_address> [ port <integer> ) ' +
    ' | ( <ipv6_address> [ port <integer> ] ) [ key <string> ] [ tls <string> ]; ... };')

# {0-*} statement
clause_stmt_parental_agents_series = ZeroOrMore(clause_stmt_parental_agents_set(''))  # 0-*, may occur multiple times
clause_stmt_parental_agents_series.setName(
    'parental_agents <string> [ port <integer> ] [ dscp <integer> ] { ... }; ...')
