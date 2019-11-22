#!/usr/bin/env python3
"""
File: isc_aml.py

Clause: controls, options, view, zone

Element: aml

Title: AML For controls, options, view, And zone Clauses

Description: Provides Address Match List (AML)-related grammar in
             PyParsing engine for ISC-configuration style
"""
from pyparsing import ZeroOrMore, Forward, Group, CaselessLiteral
from bind9_parser.isc_utils import semicolon, lbrack, rbrack, \
        exclamation, acl_name
from bind9_parser.isc_inet import ip4_addr, ip6_addr, ip4s_prefix

# Address_Match_List (AML)
# This AML combo is ordered very carefully so that longest pattern
# are tried firstly
#
# EBNF detailed at http://www.zytrax.com/books/dns/ch7/address_match_list.html
#
# EBNF reiterated here:
#
#    address_match_nosemicolon = element ; [ element; ... ]
#
#    element = [!] ( ip [/prefix]
#                    | key key-name
#                    | "acl_name_base"
#                    | { address_match_nosemicolon } )
#
literal_localhost = CaselessLiteral('localhost')('').setName('"localhost"')

literal_any = CaselessLiteral('any')('')
literal_any.setName('"any"')

literal_none = CaselessLiteral('none')('')
literal_none.setName('"none"')

literal_localnets = CaselessLiteral('localnets')('')
literal_localnets.setName('"localnets"')

aml_choices_key_id = CaselessLiteral('key').suppress() + acl_name('')  # key_id('')
aml_choices_key_id.setName('"key" <key_id>')

aml_choices_acl_name = acl_name('')

aml_choices = (
        (aml_choices_key_id('key_id'))
        | (ip4s_prefix('addr'))
        | (ip4_addr('addr'))
        | (ip6_addr('addr'))
        | (literal_any('addr'))
        | (literal_none('addr'))
        | (literal_localhost('addr'))
        | (literal_localnets('addr'))
        | (aml_choices_acl_name('acl_name'))
)

aml_nesting = Forward()
aml_nesting << (
        lbrack
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
        ) ('aml')
        + rbrack
        + semicolon
)(None)  # ResultsLabel here didn't force a list, one before here did.
