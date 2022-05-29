#!/usr/bin/env python3
"""
File: test_view.py

Description:  Performs unit test on the isc_view.py source file.
"""

import unittest
from bind9_parser.isc_utils import assert_parser_result_dict_false, assert_parser_result_dict_true
from bind9_parser.isc_view import view_stmt_match_clients,\
    view_stmt_match_destinations, view_stmt_match_recursive_only,\
    view_statements_series, view_statements_set


class TestView(unittest.TestCase):
    """ Clause view """

    def test_isc_view_stmt_match_client_passing(self):
        """ Clause view; Statement match-client; passing mode"""
        test_string = [
            'match-clients { 129.0.0.1; };',
        ]
        result = view_stmt_match_clients.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            view_stmt_match_clients,
            'match-clients { 8.8.8.8; };',
            {'match_clients': {'aml': [{'ip4_addr': '8.8.8.8'}]}}
        )

    def test_isc_view_stmt_match_client_failing(self):
        """ Clause view; Statement match-client; failing mode"""
        test_string = [
            'match-clients 129.0.0.1;',  # must be bracketed {}
        ]
        result = view_stmt_match_clients.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_view_stmt_match_destination_passing(self):
        """ Clause view; Statement match-destinations; passing mode"""
        test_string = [
            'match-destinations { 129.0.0.1; };',
            'match-destinations { 129.0.0.1/24; };',
            'match-destinations { fe0a::1; };',
            'match-destinations { acl_master_nameservers; };',
            'match-destinations { any; };',
            'match-destinations { none; };',
            'match-destinations { localhost; };',
            'match-destinations { localnets; };',
            'match-destinations { ! localnets; };',
        ]
        result = view_stmt_match_destinations.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            view_stmt_match_destinations,
            'match-destinations { 8.8.8.8; };',
            {'match_destinations': {'aml': [{'ip4_addr': '8.8.8.8'}]}}
        )

    def test_isc_view_stmt_match_destination_failing(self):
        """ Clause view; Statement match-destinations; failing mode"""
        test_string = [
            'match-destination 129.0.0.1;',  # must be bracketed {}
            'match-destinations ! 130.0.0.5;',  # exclamation must be inside first curly braces
        ]
        result = view_stmt_match_destinations.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_view_stmt_match_recursive_only_passing(self):
        """ Clause view; Statement match-recursive-only; passing mode """
        test_string = [
            'match-recursive-only yes;',
            'match-recursive-only 0;',
            'match-recursive-only TRUE;',
        ]
        result = view_stmt_match_recursive_only.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            view_stmt_match_recursive_only,
            'match-recursive-only yes;',
            {'match_recursive_only': 'yes'}
        )

    def test_isc_view_stmt_match_recursive_only_failing(self):
        """ Clause view; Statement match-recursive-only; failing mode """
        test_string = [
            'match-recursive-only { yes; };',  # extraneous pair of braces
            'match-recursive-only 131.0.0.7;',   # supposed to be yes/no
        ]
        result = view_stmt_match_recursive_only.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    # Cannot test 'zone' statement from inside 'view' clause within this source file
    #    due to cyclic nesting of Python 'import' statements
    # to test 'zone' statement, we do that in test_clause_view.py


if __name__ == '__main__':
    unittest.main()
