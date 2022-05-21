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
from bind9_parser.isc_utils import assertParserResultDictTrue
from bind9_parser.isc_clause_parental_agents import \
    parental_agents_server_address_element, parental_agents_key_element, \
    parental_agents_tls_element, clause_stmt_parental_agents_standalone, \
    clause_stmt_parental_agents_set, clause_stmt_parental_agents_series


class TestClauseParentalAgents(unittest.TestCase):
    """ Test Clause 'parental-agents' """

    def test_parental_agents_server_address_ipv4_passing(self):
        """ Test Clause 'parental-agents'; server address element IPv4; passing """
        test_string = '1.2.3.4'
        expected_result = {'addr': '1.2.3.4'}
        assertParserResultDictTrue(
            parental_agents_server_address_element,
            test_string,
            expected_result)

    def test_parental_agents_server_address_ipv6_passing(self):
        """ Test Clause 'parental-agents'; server address element IPv6; passing """
        test_string = 'fe00::1'
        expected_result = {'addr': 'fe00::1'}
        assertParserResultDictTrue(
            parental_agents_server_address_element,
            test_string,
            expected_result)

    def test_parental_agents_server_address_fqdn_passing(self):
        """ Test Clause 'parental-agents'; server address element FQDN; passing """
        test_string = 'example.com'
        expected_result = {'fqdn': 'example.com'}
        assertParserResultDictTrue(
            parental_agents_server_address_element,
            test_string,
            expected_result)

    def test_parental_agents_key_element(self):
        """ Test Clause 'parental-agents'; key element; passing """
        test_string = 'key my_key_name'
        expected_result = {'key_id': 'my_key_name'}
        assertParserResultDictTrue(
            parental_agents_key_element,
            test_string,
            expected_result)


    def test_parental_agents_tls_element(self):
        """ Test Clause 'parental-agents'; tls element; passing """
        test_string = 'tls my_tls_name'
        expected_result = {'tls_name': 'my_tls_name'}
        assertParserResultDictTrue(
            parental_agents_tls_element,
            test_string,
            expected_result)


    def test_clause_stmt_parental_agents_standalone(self):
        """ Test Clause 'parental-agents'; standalone; passing """
        test_string = """parental-agents tunneled_office port 853 dscp 5 { 127.0.0.1 port 853 key "asdfasdfasdf" tls "asdfasdfasdf"; };"""
        expected_result = { 'parental_agents': [ { 'dscp_port': 5,
                         'ip_port': '853',
                         'parental_agents_name': 'tunneled_office',
                         'parental_agents_servers': [ { 'addr': '127.0.0.1',
                                                        'ip_port': '853',
                                                        'key_id': '"asdfasdfasdf"',
                                                        'tls_name': '"asdfasdfasdf"'}]}]}
        assertParserResultDictTrue(
            clause_stmt_parental_agents_standalone,
            test_string,
            expected_result)


    def test_clause_stmt_parental_agents_set_passing(self):
        """ Test Clause 'parental-agents'; set; passing """
        test_string = """
        parental-agents tunneled_office port 853 dscp 5 {
            127.0.0.1 port 853 key "asdfasdfasdf" tls "asdfasdfasdf";
        };"""
        expected_result = { 'parental_agents': [ { 'dscp_port': 5,
                         'ip_port': '853',
                         'parental_agents_name': 'tunneled_office',
                         'parental_agents_servers': [ { 'addr': '127.0.0.1',
                                                        'ip_port': '853',
                                                        'key_id': '"asdfasdfasdf"',
                                                        'tls_name': '"asdfasdfasdf"'}]}]}
        assertParserResultDictTrue(
            clause_stmt_parental_agents_set,
            test_string,
            expected_result)

    def test_clause_stmt_parental_agents_set_two_elements_passing(self):
        """ Test Clause 'parental-agents'; set, two elements; passing """
        test_string = """
parental-agents tunneled_office port 853 dscp 5 {
    192.168.1.1;
    172.16.1.1;
};"""
        expected_result = { 'parental_agents': [ { 'dscp_port': 5,
                         'ip_port': '853',
                         'parental_agents_name': 'tunneled_office',
                         'parental_agents_servers': [ { 'addr': '192.168.1.1'},
                                                      { 'addr': '172.16.1.1'}]}]}
        assertParserResultDictTrue(
            clause_stmt_parental_agents_set,
            test_string,
            expected_result)

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
        expected_result = { 'parental_agents': [ { 'dscp_port': 5,
                         'ip_port': '853',
                         'parental_agents_name': 'tunneled_office',
                         'parental_agents_servers': [ { 'addr': '127.0.0.1',
                                                        'ip_port': '853',
                                                        'key_id': '"asdfasdfasdf"',
                                                        'tls_name': '"asdfasdfasdf"'},
                                                      { 'addr': '192.168.1.1'},
                                                      { 'addr': '172.16.1.1',
                                                        'ip_port': '853'},
                                                      { 'addr': '172.16.1.2',
                                                        'key_id': '"third_key"'},
                                                      { 'addr': '172.16.1.3',
                                                        'tls_name': '"third_tls"'},
                                                      { 'addr': '172.16.1.4',
                                                        'ip_port': '853',
                                                        'tls_name': '"fourth_tls"'},
                                                      { 'addr': '172.16.1.4',
                                                        'ip_port': '853',
                                                        'key_id': '"fourth_key"'}]}]}
        assertParserResultDictTrue(
        clause_stmt_parental_agents_set,
        test_string,
        expected_result)


    def test_clause_stmt_parental_agents_series(self):
        """ Test Clause 'parental-agents'; series; passing """
        test_string = """
parental-agents tunneled_office port 853 dscp 5 {
    127.0.0.1 port 853 key "asdfasdfasdf" tls "asdfasdfasdf";
    };
parental-agents tunneled_office port 853 dscp 5 {
    127.0.0.1 port 853 key "asdfasdfasdf" tls "asdfasdfasdf";
    };
"""
        expected_result = { 'parental_agents': [ { 'dscp_port': 5,
                         'ip_port': '853',
                         'parental_agents_name': 'tunneled_office',
                         'parental_agents_servers': [ { 'addr': '127.0.0.1',
                                                        'ip_port': '853',
                                                        'key_id': '"asdfasdfasdf"',
                                                        'tls_name': '"asdfasdfasdf"'}]},
                       { 'dscp_port': 5,
                         'ip_port': '853',
                         'parental_agents_name': 'tunneled_office',
                         'parental_agents_servers': [ { 'addr': '127.0.0.1',
                                                        'ip_port': '853',
                                                        'key_id': '"asdfasdfasdf"',
                                                        'tls_name': '"asdfasdfasdf"'}]}]}
        assertParserResultDictTrue(
            clause_stmt_parental_agents_series,
            test_string,
            expected_result)


if __name__ == '__main__':
    unittest.main()
