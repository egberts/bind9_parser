#!/usr/bin/env python3
"""
File: test_clause_http

Description:
    Performs unit test on the 'http' clause 
    in isc_clause_http.py source file.
    
    Statement Grammar:
    http <string> {
      endpoints { <quoted_string>; ... };
      listener-clients <integer>;
      streams-per-connection <integer>;
      };
"""

import unittest
from bind9_parser.isc_utils import assert_parser_result_dict_true
from bind9_parser.isc_clause_http import \
    http_endpoints_element, http_listener_clients_element, \
    http_streams_per_conns_element, \
    clause_stmt_http_set, clause_stmt_http_series


class TestClauseHttp(unittest.TestCase):
    """ Test Clause HTTP """

    def test_http_endpoints_passing(self):
        """ Test Clause HTTP; 'endpoints'; passing """
        test_string = 'endpoints { "str1"; };'
        expected_result = {'endpoints': [{'endpoint_name': '"str1"'}]}
        assert_parser_result_dict_true(
            http_endpoints_element,
            test_string,
            expected_result)

    def test_http_endpoints_two_passing(self):
        """ Test Clause HTTP; 'endpoints x2'; passing """
        test_string = 'endpoints { "str2"; "str3"; };'
        expected_result = { 'endpoints': [ {'endpoint_name': '"str2"'},
                 {'endpoint_name': '"str3"'}]}
        assert_parser_result_dict_true(
            http_endpoints_element,
            test_string,
            expected_result)

    def test_http_listener_clients_passing(self):
        """ Test Clause HTTP; 'listener-clients'; passing """
        test_string = 'listener-clients 3600;'
        expected_result = {'listener_clients': '3600'}
        assert_parser_result_dict_true(
            http_listener_clients_element,
            test_string,
            expected_result)

    def test_http_streams_per_connections_passing(self):
        """ Test Clause HTTP; 'streams-per-connections'; passing """
        test_string = 'streams-per-connections 3000;'
        expected_result = {'streams_per_connections': '3000'}
        assert_parser_result_dict_true(
            http_streams_per_conns_element,
            test_string,
            expected_result)

    def test_stmt_clause_http_set_passing(self):
        """ Test Clause HTTP; set; passing """
        test_string = """
http private {
    endpoints { "endpoint1"; };
    listener-clients 15;
    streams-per-connections 300;
    };"""
        expected_result = { 'http': [ { 'endpoints': [{'endpoint_name': '"endpoint1"'}],
              'http_name': 'private',
              'listener_clients': '15',
              'streams_per_connections': '300'}]}
        assert_parser_result_dict_true(
            clause_stmt_http_set,
            test_string,
            expected_result)

    def test_clause_stmt_http_series_passing(self):
        """ Test Clause HTTP; series; passing """
        test_string = """
http private {
    endpoints { "endpoint1"; };
    listener-clients 15;
    streams-per-connections 300;
    };
http public {
    endpoints { "endpoint1"; };
    listener-clients 15;
    streams-per-connections 300;
    };
http furtive {
    endpoints { "endpoint1"; };
    listener-clients 15;
    streams-per-connections 300;
    };"""
        expected_result = { 'http': [ { 'endpoints': [{'endpoint_name': '"endpoint1"'}],
              'http_name': 'private',
              'listener_clients': '15',
              'streams_per_connections': '300'},
            { 'endpoints': [{'endpoint_name': '"endpoint1"'}],
              'http_name': 'public',
              'listener_clients': '15',
              'streams_per_connections': '300'},
            { 'endpoints': [{'endpoint_name': '"endpoint1"'}],
              'http_name': 'furtive',
              'listener_clients': '15',
              'streams_per_connections': '300'}]}
        assert_parser_result_dict_true(
            clause_stmt_http_series,
            test_string,
            expected_result)


if __name__ == '__main__':
    unittest.main()
