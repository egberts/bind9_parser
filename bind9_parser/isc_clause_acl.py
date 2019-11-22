#!/usr/bin/env python3
"""
File: isc_clause_acl.py

Clause: acl

Title: Clause statement for the Access Control List

Description: Provides clause-specific aspect of ACL-related grammar
             in PyParsing engine for ISC-configuration style.

             Reason for separate file from isc_acl is to avoid the Python
             'import' circular dependency of 'isc_aml'.
"""
from pyparsing import Group, ZeroOrMore, Literal, Word, alphanums, Keyword
from bind9_parser.isc_utils import acl_name
from bind9_parser.isc_aml import aml_nesting


#############################################################
# ACL clause
#  The following ACL names are built-in:
#
#  * any - Matches all hosts.
#  * none - Matches no hosts.
#  * localhost - Matches the IPv4 and IPv6 addresses of all
#                network interfaces on the system. When
#                addresses are added or removed, the
#                localhost ACL element is updated to reflect
#                the changes.
#  * localnets - Matches any host on an IPv4 or IPv6 network
#                for which the system has an interface. When
#                addresses are added or removed, the
#                localnets ACL element is updated to reflect
#                the changes. Some systems do not provide a
#                way to determine the prefix lengths of
#                local IPv6 addresses. In such a case,
#                localnets only matches the local IPv6
#                addresses, just like localhost
#############################################################
# acl acl-name {
#    [ address_match_nosemicolon | any | all ];
# };

clause_stmt_acl_standalone = (
        Keyword('acl').suppress()
        - Group(   # Best thing I've ever done.
            acl_name  #(Word(alphanums + '_-'))('acl_name')
            - (
                ZeroOrMore(
                    Group(

                        aml_nesting('')  # peel away testing label here
                    )('')  # ('aml_series3')
                )('')
            )('aml_series')
        )('')
)('acl')

# Syntax:
#         acl a { b; };  acl c { d; e; f; }; acl g { ! h; ! { i; }; };
#
clause_stmt_acl_series = ZeroOrMore(
    (
        clause_stmt_acl_standalone
    )
)('acl')
