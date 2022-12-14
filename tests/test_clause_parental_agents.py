#!/usr/bin/env python3
"""
File: test_clause_parental_agents

Description:
  Performs unit test on the 'parental_agents' clause 
  in isc_clause_parental_agents.py source file.
    
  Statement Grammar:
    parental-agents <string> [ port <integer> ] [ dscp <integer> ] {
            ( <remote-servers> |
              <ipv4_address> [ port <integer> ] |
              <ipv6_address> [ port <integer> ] )
            [ key <string> ]
            [ tls <string> ]; ... 
        };
"""

import unittest
from bind9_parser.isc_utils import assert_parser_result_dict_true
from bind9_parser.isc_clause_parental_agents import \
    clause_stmt_parental_agents_standalone, \
    clause_stmt_parental_agents_set, clause_stmt_parental_agents_series


class TestClauseParentalAgents(unittest.TestCase):
    """ Test Clause 'parental-agents' """

    def test_clause_stmt_parental_agents_standalone(self):
        """ Test Clause 'parental-agents'; standalone; passing """
        test_string = """
parental-agents tunneled_office port 853 dscp 5 {
    127.0.0.1 port 853 key "asdfasdfasdf" tls "asdfasdfasdf"; };"""
        assert_parser_result_dict_true(
            clause_stmt_parental_agents_standalone,
            test_string,
            {'parental_agents': [{'dscp_port': 5,
                                  'ip_port': '853',
                                  'parental_agent_name': 'tunneled_office',
                                  'remote_servers': [{'ip4_addr': '127.0.0.1',
                                                      'ip_port': '853',
                                                      'key_id': 'asdfasdfasdf',
                                                      'tls_id': 'asdfasdfasdf'}]}]}
        )

    def test_clause_stmt_parental_agents_set_passing(self):
        """ Test Clause 'parental-agents'; set; passing """
        test_string = """
        parental-agents tunneled_office port 853 dscp 5 {
            127.0.0.1 port 853 key "asdfasdfasdf" tls "asdfasdfasdf";
        };"""
        assert_parser_result_dict_true(
            clause_stmt_parental_agents_set,
            test_string,
            {'parental_agents': [{'dscp_port': 5,
                                  'ip_port': '853',
                                  'parental_agent_name': 'tunneled_office',
                                  'remote_servers': [{'ip4_addr': '127.0.0.1',
                                                      'ip_port': '853',
                                                      'key_id': 'asdfasdfasdf',
                                                      'tls_id': 'asdfasdfasdf'}]}]}
        )

    def test_clause_stmt_parental_agents_set_two_elements_passing(self):
        """ Test Clause 'parental-agents'; set, two elements; passing """
        test_string = """
parental-agents tunneled_office port 853 dscp 5 {
    192.168.1.1;
    172.16.1.1;
};"""
        assert_parser_result_dict_true(
            clause_stmt_parental_agents_set,
            test_string,
            {'parental_agents': [{'dscp_port': 5,
                                  'ip_port': '853',
                                  'parental_agent_name': 'tunneled_office',
                                  'remote_servers': [{'ip4_addr': '192.168.1.1'},
                                                     {'ip4_addr': '172.16.1.1'}]}]}
        )

    def test_clause_stmt_parental_agents_set_multiple_element_passing(self):
        """ Test Clause 'parental-agents'; set, multiple element; passing """
        test_string = """
parental-agents tunneled_office port 853 dscp 5 {
    127.0.0.1 port 853 key "asdfasdfasdf" tls "asdfasdfasdf";
    192.168.1.1;
    172.16.1.1 port 853;
    172.16.1.2 key "third_key";
    172.16.1.3 tls "third_tls";
    172.16.1.4 port 853 tls "fourth_tls";
    172.16.1.4 port 853 key "fourth_key";
    };"""
        assert_parser_result_dict_true(
            clause_stmt_parental_agents_set,
            test_string,
            {'parental_agents': [{'dscp_port': 5,
                                  'ip_port': '853',
                                  'parental_agent_name': 'tunneled_office',
                                  'remote_servers': [{'ip4_addr': '127.0.0.1',
                                                      'ip_port': '853',
                                                      'key_id': 'asdfasdfasdf',
                                                      'tls_id': 'asdfasdfasdf'},
                                                     {'ip4_addr': '192.168.1.1'},
                                                     {'ip4_addr': '172.16.1.1',
                                                      'ip_port': '853'},
                                                     {'ip4_addr': '172.16.1.2',
                                                      'key_id': 'third_key'},
                                                     {'ip4_addr': '172.16.1.3',
                                                      'tls_id': 'third_tls'},
                                                     {'ip4_addr': '172.16.1.4',
                                                      'ip_port': '853',
                                                      'tls_id': 'fourth_tls'},
                                                     {'ip4_addr': '172.16.1.4',
                                                      'ip_port': '853',
                                                      'key_id': 'fourth_key'}]}]}
        )

    def test_clause_stmt_parental_agents_series(self):
        """ Test Clause 'parental-agents'; series; passing """
        test_string = """
parental-agents tunneled_office port 853 dscp 5 {
    127.0.0.1 port 853 key "asdfasdfasdf" tls "asdfasdfasdf";
    };
parental-agents tunneled_office port 854 dscp 6 {
    127.0.0.2 port 857 key "zxcvzxcvzxcv" tls "zxcvzxccvzxcv";
    };
"""
        assert_parser_result_dict_true(
            clause_stmt_parental_agents_series,
            test_string,
            {'parental_agents': [{'dscp_port': 5,
                                  'ip_port': '853',
                                  'parental_agent_name': 'tunneled_office',
                                  'remote_servers': [{'ip4_addr': '127.0.0.1',
                                                      'ip_port': '853',
                                                      'key_id': 'asdfasdfasdf',
                                                      'tls_id': 'asdfasdfasdf'}]},
                                 {'dscp_port': 6,
                                  'ip_port': '854',
                                  'parental_agent_name': 'tunneled_office',
                                  'remote_servers': [{'ip4_addr': '127.0.0.2',
                                                      'ip_port': '857',
                                                      'key_id': 'zxcvzxcvzxcv',
                                                      'tls_id': 'zxcvzxccvzxcv'}]}]}
        )


if __name__ == '__main__':
    unittest.main()
