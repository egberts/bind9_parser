#!/usr/bin/env python3
"""
File: test_clause_plugin

Description:
  Performs unit test on the 'plugin' clause 
  in isc_clause_plugin.py source file.
    
  Statement Grammar:

    plugin ( query ) string [ { 
        unspecified-text
    } ];

"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue
from bind9_parser.isc_clause_plugin import \
    plugin_config_element, \
    clause_stmt_plugin_standalone, \
    clause_stmt_plugin_set, clause_stmt_plugin_series


class TestClauseHttp(unittest.TestCase):
    """ Test Clause 'plugin' """

    def test_plugin_config_passing(self):
        """ Test Clause 'plugin'; 'config' element; passing """
        test_string = '{ a; }'  # do not include semicolon, that is done elsewhere
        expected_result = {'config': [['a']]}
        assertParserResultDictTrue(
            plugin_config_element,
            test_string,
            expected_result)

    def test_plugin_config_two_passing(self):
        """ Test Clause 'plugin'; 'config' x2 element'; passing """
        test_string = '{ a; d e f; }'  # do not include semicolon, that is done elsewhere
        expected_result = {'config': [['a', 'd e f']]}
        assertParserResultDictTrue(
            plugin_config_element,
            test_string,
            expected_result)

    def test_plugin_config_multiple_passing(self):
        """ Test Clause 'plugin'; 'config' multiple elements'; passing """
        test_string = '{ b c; d e f; b c; a;}'  # do not include semicolon
        expected_result = {'config': [['b c', 'd e f', 'b c', 'a']]}
        assertParserResultDictTrue(
            plugin_config_element,
            test_string,
            expected_result)

    def test_plugin_config_complex_passing(self):
        """ Test Clause 'plugin'; 'config' complex elements; passing """
        test_string = '{ a; b c; d e f; g h  i; ; j  k; l; m;  n; }'
        expected_result = { 'config': [ [ 'a',
                'b c',
                'd e f',
                'g h  i',
                'j  k',
                'l',
                'm',
                'n']]}
        assertParserResultDictTrue(
            plugin_config_element,
            test_string,
            expected_result)

    def test_stmt_clause_plugin_standalone_passing(self):
        """ Test Clause 'plugin'; standalone; passing """
        test_string = 'plugin query "../../../plugins/.libs/filter-aaaa.so" { filter-a-on-v4 yes; };'
        expected_result = { 'config': [['filter-a-on-v4 yes']],
  'flag': 'query',
  'quoted_path_name': '"../../../plugins/.libs/filter-aaaa.so"'}
        assertParserResultDictTrue(
            clause_stmt_plugin_standalone,
            test_string,
            expected_result)

    def test_stmt_clause_plugin_set_passing(self):
        """ Test Clause 'plugin'; set; passing """
        test_string = 'plugin "../../../filter-aaaa.so" { filter-aaaa yes; };'
        expected_result = { 'config': [['filter-aaaa yes']],
  'quoted_path_name': '"../../../filter-aaaa.so"'}
        assertParserResultDictTrue(
            clause_stmt_plugin_set,
            test_string,
            expected_result)

    def test_stmt_clause_plugin_set_query_passing(self):
        """ Test Clause 'plugin'; set with 'query'; passing """
        test_string = 'plugin query "../../../filter-a.so" { filter-aaaa yes; };'
        expected_result = { 'config': [['filter-aaaa yes']],
  'flag': 'query',
  'quoted_path_name': '"../../../filter-a.so"'}
        assertParserResultDictTrue(
            clause_stmt_plugin_set,
            test_string,
            expected_result)

    def test_clause_stmt_plugin_series_passing(self):
        """ Test Clause 'plugin'; series; passing """
        test_string = """
plugin "../../../filter-a.so" { filter-a yes; };
plugin query "../../../filter-aaaa.so" { filter-aaaa yes; };"""
        expected_result = { 'config': [['filter-a yes'], ['filter-aaaa yes']],
  'flag': 'query',
  'quoted_path_name': '"../../../filter-aaaa.so"'}
        assertParserResultDictTrue(
            clause_stmt_plugin_series,
            test_string,
            expected_result)


if __name__ == '__main__':
    unittest.main()

