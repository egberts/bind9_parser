#!/usr/bin/env python3
"""
File: test_clause_options.py

Description:  Performs unit test on the isc_options.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictFalse, assertParserResultDictTrue
from bind9_parser.isc_options import options_statements_set, options_statements_series,\
    options_stmt_avoid_v4_udp_ports

from bind9_parser.isc_clause_options import clause_stmt_options, options_all_statements_set,\
    options_all_statements_series

class TestClauseOptions(unittest.TestCase):
    """ Clause options """

    def test_isc_options_all_statement_set_passing(self):
        """ Clause options; Statement Set All; passing mode """
        test_data = [
            'version 5;',
            'version 5;',
            ]
        result = options_all_statements_set.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_options_all_statements_set_failing(self):
        """ Clause options; Statement Set All; failing mode """
        test_data = [
            'also-notify localhost;',
        ]
        result = options_all_statements_set.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_options_all_statement_series_passing(self):
        """ Clause options; Statement Series All; passing mode """
        test_data = [
            'version 5; port 53;',
            'version 5; coresize unlimited; pid-file "/var/run/named.pid";',
            ]
        result = options_all_statements_series.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            options_all_statements_series,
            'version 5; port 53;',
            {'ip_port': 53, 'version_string': '5'}
        )
        assertParserResultDictTrue(
            options_all_statements_series,
            'version 5; coresize unlimited; pid-file "/var/run/named.pid";',
            {'coresize': ['unlimited'],
             'pid_file_path_name': '"/var/run/named.pid"',
             'version_string': '5'}
        )
        assertParserResultDictTrue(
            options_all_statements_series,
            'version 5; port 53;',
            {'ip_port': 53, 'version_string': '5'}
        )

    def test_isc_options_all_statements_series_failing(self):
        """ Clause options; Statement Series All; failing mode """
        test_data = [
            'version 5; moresize unlimited; pid-file "/var/run/named.pid";',
        ]
        result = options_all_statements_series.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_clause_stmt_option_passing(self):
        """ Clause options; passing mode """
        test_data = [
            'options { version 5; coresize unlimited; pid-file "/var/run/named.pid"; };',
            ]
        result = clause_stmt_options.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_clause_stmt_options_failing(self):
        """ Clause options; failing mode """
        test_data = [
            'country us',
        ]
        result = clause_stmt_options.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()

