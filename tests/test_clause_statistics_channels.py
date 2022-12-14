#!/usr/bin/env python3
"""
File: test_clause_statistics_channels

Description:
  Performs unit test on the 'statistics-channels' clause 
  in isc_clause_statistics_channels.py source file.
    
  Statement Grammar:
    statistics-channels {
      inet ( ipv4_address | 
             ipv6_address |
             * ) 
           [ port ( integer | * ) ] 
           [ allow { 
                 address_match_element; ...
               } ]
            ;
     };
"""

import unittest
from bind9_parser.isc_utils import assert_parser_result_dict_true
from bind9_parser.isc_clause_statistics_channels import \
    clause_stmt_statistics_channels_set, clause_stmt_statistics_channels_series


class TestClauseHttp(unittest.TestCase):
    """ Test Clause 'statistics-channels' """

    def test_stmt_clause_statistics_channels_set_passing(self):
        """ Test Clause 'statistics-channels'; set; passing """
        test_string = """statistics-channels { inet 127.0.0.1; };"""
        expected_result = {'statistics_channels': [{'ip_addr': '127.0.0.1'}]}
        assert_parser_result_dict_true(
            clause_stmt_statistics_channels_set,
            test_string,
            expected_result)

    def test_stmt_clause_statistics_channels_set_port_passing(self):
        """ Test Clause 'statistics-channels'; set port; passing """
        test_string = """statistics-channels { inet 127.0.0.1 port 854; };"""
        expected_result = {
            'statistics_channels': [
                {
                    'ip_addr': '127.0.0.1',
                    'ip_port_w': ['854']}]}
        assert_parser_result_dict_true(
            clause_stmt_statistics_channels_set,
            test_string,
            expected_result)

    def test_stmt_clause_statistics_channels_set_two_elements_passing(self):
        """ Test Clause 'statistics-channels'; set, 2 elements; passing """
        test_string = """statistics-channels { inet 127.0.0.2; inet 127.0.0.3 port 853; };"""
        expected_result = {'statistics_channels': [{'ip_addr': '127.0.0.2'},
                                                   {'ip_addr': '127.0.0.3',
                                                    'ip_port_w': ['853']}]}
        assert_parser_result_dict_true(
            clause_stmt_statistics_channels_set,
            test_string,
            expected_result)

    def test_clause_stmt_statistics_channels_series_passing(self):
        """ Test Clause 'statistics-channels'; series; passing """
        test_string = """
statistics-channels { inet 127.0.0.2; inet 127.0.0.3 port 853; };
statistics-channels { inet 127.0.0.4; inet 127.0.0.5 port 854; };
statistics-channels { inet 127.0.0.6; inet 127.0.0.7 port 855; };
statistics-channels { inet 127.0.0.8; inet 127.0.0.9 port 856; };
"""
        assert_parser_result_dict_true(
            clause_stmt_statistics_channels_series,
            test_string,
            {'statistics_channels': [{'ip_addr': '127.0.0.2'},
                                     {'ip_addr': '127.0.0.3',
                                      'ip_port_w': ['853']},
                                     {'ip_addr': '127.0.0.4'},
                                     {'ip_addr': '127.0.0.5',
                                      'ip_port_w': ['854']},
                                     {'ip_addr': '127.0.0.6'},
                                     {'ip_addr': '127.0.0.7',
                                      'ip_port_w': ['855']},
                                     {'ip_addr': '127.0.0.8'},
                                     {'ip_addr': '127.0.0.9',
                                      'ip_port_w': ['856']}]}

        )


if __name__ == '__main__':
    unittest.main()
