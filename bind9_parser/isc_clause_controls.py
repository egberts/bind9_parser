#!/usr/bin/env python3.7
"""
File: isc_clause_controls.py

Clause: controls

Title: Clause statement for the 'controls' connections.

Description
"""
from pyparsing import Keyword, Group, Optional, Literal, OneOrMore, ZeroOrMore
from bind9_parser.isc_utils import semicolon, lbrack, rbrack, \
    isc_boolean, quoted_path_name, number_type, \
    exclamation, key_id
from bind9_parser.isc_aml import aml_nesting, aml_choices
from bind9_parser.isc_inet import ip46_addr_or_wildcard, \
    inet_ip_port_keyword_and_wildcard_element

#  ( ip46_addr_or_prefix | * ) [ port ( ip_port | * ) ]
controls_inet_addr_and_port = (
        ip46_addr_or_wildcard('control_server_addr')
        + Optional(inet_ip_port_keyword_and_wildcard_element)
)

controls_inet_allow_element = Group(
    Keyword('allow').suppress()
    + lbrack
    + (
        ZeroOrMore(
            Group(
                (
                        exclamation('not')
                        + aml_nesting
                )
                | (
                        exclamation('not')
                        + aml_choices
                        + semicolon
                )
                | (
                    aml_nesting
                )
                | (
                        aml_choices
                        + semicolon
                )  # never set a ResultsLabel here, you get duplicate but un-nested 'addr'
            )  # never set a ResultsLabel here, you get no []
        )(None)
    )('aml')
    + rbrack
    # NOSEMICOLON HERE!
)('allow')

#  keys { key_id; [ ... ] };
controls_keys_element = (
        Keyword('keys').suppress()
        + lbrack
        + ZeroOrMore(
            Group(
                key_id(None)
                + semicolon
            )
        )
        + rbrack
        # NO SEMICOLON HERE!
)('keys')

#  read-only <boolean>
controls_inet_read_only_element = (
        Keyword('read-only').suppress()
        - isc_boolean('read-only')
        # NO SEMICOLON HERE!
)

#  inet
#      ( ip46_addr_or_prefix | * ) [ port ( ip_port | * ) ]
#      allow { <aml>; }
#      [ keys { key_id; [ ... ] } ]
#      [ read-only <boolean> ]
#      ;
controls_inet_set = Group(
    Keyword('inet').suppress()
    + controls_inet_addr_and_port(None)
    - controls_inet_allow_element(None)
    + Optional(controls_keys_element)
    + Optional(controls_inet_read_only_element)
    + semicolon
)('inet')

controls_unix_set = (
    Group(
        Keyword('unix').suppress()
        + (
                quoted_path_name('path_name')
                + Literal('perm').suppress()
                + number_type('perm')  # TODO Check if 'controls unix perm/owner/group is numeric-only or not
                + Literal('owner').suppress()
                + number_type('uid')
                + Literal('group').suppress()
                + number_type('gid')
                - Optional(controls_keys_element)
                - Optional(controls_inet_read_only_element)
                + semicolon
        )
    )('unix')
)

clause_stmt_control_standalone = (
        Keyword('controls').suppress()
        + lbrack
        + Group(
            OneOrMore(
                Group(controls_inet_set('inet'))
                | Group(controls_unix_set('unix'))
            )
        )('controls')  # ('controls')
        + rbrack
        + semicolon
)

clause_stmt_control_series = (
    ZeroOrMore(
        clause_stmt_control_standalone
    )
)
