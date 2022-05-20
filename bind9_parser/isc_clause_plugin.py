#!/usr/bin/env python3
"""
File: isc_clause_plugin.py

Clause: plugin

Title: Clause statement for 'plugin'

Description: 

  Statement Grammar:

    plugin ( query ) string 
        [ { unspecified-text } ]
        ;
"""
from pyparsing import Word, alphanums, Group, Keyword, ZeroOrMore, OneOrMore, Optional, nums
from bind9_parser.isc_utils import semicolon, lbrack, rbrack, \
        iso8601_duration, quotable_name,\
        lbrack, rbrack, quoted_name, quoted_path_name, config_base

# NOTE: If any declaration here is to be used OUTSIDE of 
# the 'plugin' clause, it should instead be defined within isc_utils.py

plugin_config_line_element = (
                                 config_base
                                 + OneOrMore(semicolon)
)

plugin_config_element = (
        lbrack
        + OneOrMore(plugin_config_line_element)('config*')
        + rbrack
)

clause_stmt_plugin_standalone = (
        Keyword('plugin').suppress()
        + Optional(Keyword('query')('flag'))
        + quoted_path_name
        + plugin_config_element
        + semicolon
).setName('plugin [ query ] <quoted_string> { text ; ... };')

clause_stmt_plugin_set = clause_stmt_plugin_standalone.setName('plugin [ query ] <quoted_string> { text ; ... };')

# {0-*} statement
clause_stmt_plugin_series = ZeroOrMore( clause_stmt_plugin_set )
clause_stmt_plugin_series.setName('plugin [ query ] <string> { ... }; ...')

