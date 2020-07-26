#!/usr/bin/env python3
"""
File: test_clause_mains.py

Description:  Performs unit test on the isc_clause_mains.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue, assertParserResultDictFalse
from bind9_parser.isc_clause_mains import \
    main_id, \
    mains_element_series,\
    clause_stmt_mains_standalone, clause_stmt_mains_series


class TestClauseMains(unittest.TestCase):
    """ Clause mains """

    def test_isc_mains_name_passing(self):
        """ Clause mains; Series Main Name; passing mode """
        expected_result = {'main_id': 'primary_nameservers'}
        assertParserResultDictTrue(main_id, 'primary_nameservers', expected_result)
        expected_result = {'main_id': 'secondary-subordinates'}
        assertParserResultDictTrue(main_id, 'secondary-subordinates', expected_result)
        expected_result = {'main_id': 'demilitarized_zone_servers'}
        assertParserResultDictTrue(main_id, 'demilitarized_zone_servers', expected_result)

    def test_isc_mains_name_failing(self):
        """ Clause mains; Series Main Name; failing mode """
        test_data = [
            'route,net;',
            'bad host',
            'no such;',
        ]
        expected_result = {'main_id': '2.2.2.2'}
        assertParserResultDictFalse(main_id, 'route.net;', expected_result)
        assertParserResultDictFalse(main_id, 'bad host', expected_result)
        assertParserResultDictFalse(main_id, 'no such;', expected_result)

    def test_isc_main_name_passing(self):
        """Mains clause, Main Name type, passing mode"""
        test_string = 'main_bastion_host'
        expected_result = {'main_id': 'main_bastion_host'}
        assertParserResultDictTrue(main_id, test_string, expected_result)
        test_string = '\'secondary_firewall_host\''
        expected_result = {'main_id': '\'secondary_firewall_host\''}
        assertParserResultDictTrue(main_id, test_string, expected_result)
        test_string = '"hidden_primary"'
        expected_result = {'main_id': '"hidden_primary"'}
        assertParserResultDictTrue(main_id, test_string, expected_result)
        test_string = 'asdf"asdf"'
        expected_result = {'main_id': 'asdf"asdf"'}
        assertParserResultDictTrue(main_id, test_string, expected_result)

    def test_isc_main_name_failing(self):
        """Mains clause, Main Name type, purposely failing mode"""
        test_string = 'netspeed 150000000'
        expected_result = {'main_id': 'netspeed'}
        assertParserResultDictFalse(main_id, test_string, expected_result)

    def test_isc_mains_element_series_passing(self):
        """Mains clause, Main Element series, passing mode"""
        test_string = 'primary_subdomain key "main_key_maker";'
        expected_result = {
            'main_list': [
                {
                    'addr': 'primary_subdomain',
                    'key_id': '"main_key_maker"'}]}
        assertParserResultDictTrue(mains_element_series, test_string, expected_result)
        test_string = 'main_recon_border_gateway key "My_Secret_Company_Key";'
        expected_result = {
            'main_list': [
                {
                    'addr': 'main_recon_border_gateway',
                    'key_id': '"My_Secret_Company_Key"'}]}
        assertParserResultDictTrue(mains_element_series, test_string, expected_result)

    def test_isc_mains_element_series_failing(self):
        """Mains clause, Main Element series, purposely failing mode"""
        test_string = 'netspeed 150000000'
        expected_result = {
            'main_list': [
                {'addr': 'main_recon_border_gateway', 'key_id': '"My_Secret_Company_Key"'}
            ]
        }
        assertParserResultDictFalse(mains_element_series, test_string, expected_result)

    def test_isc_clause_stmt_mains_standalone_passing(self):
        """Mains clause, passing mode"""
        test_string = 'mains ns1 { 127.0.0.1; };'
        expected_result = {
            'mains': [
                {
                    'main_id': 'ns1',
                    'main_list': [
                        {'addr': '127.0.0.1'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_mains_standalone, test_string, expected_result)

# mains example.com { mains; my_secondaries; };
    def test_isc_clause_stmt_mains_ACLname_passing(self):
        """ Main clause, ACL usages; passing mode"""
        test_string = 'mains example.com { mains; my_secondaries; };'
        expected_result = {
            'mains': [
                {
                    'main_id': 'example.com',
                    'main_list': [
                        {'addr': 'mains'},
                        {'addr': 'my_secondaries'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_mains_standalone, test_string, expected_result)

    def test_isc_clause_stmt_mains_multielement_passing(self):
        """Mains clause, passing mode"""
        test_string = 'mains ns1 { 127.0.0.1; 192.168.1.1; 192.168.6.1; };'
        expected_result = { 'mains': [ { 'main_id': 'ns1',
                                           'main_list': [ {'addr': '127.0.0.1'},
                                                            {'addr': '192.168.1.1'},
                                                            {'addr': '192.168.6.1'}]}]}
        assertParserResultDictTrue(clause_stmt_mains_standalone, test_string, expected_result)
        test_string = 'mains ns1 { another_bastion_hosts1; hidden_bastion2; };'
        expected_result = { 'mains': [ { 'main_id': 'ns1',
                 'main_list': [ { 'addr': 'another_bastion_hosts1'},
                                  {'addr': 'hidden_bastion2'}]}]}
        assertParserResultDictTrue(clause_stmt_mains_standalone, test_string, expected_result)

    def test_isc_clause_stmt_mains_series_passing(self):
        test_string = 'mains another_bastion_host3 { another_bastion_hosts22; }; mains third_bastion { hidden_bastion; };'
        expected_result = {
            'mains': [
                {
                    'main_id': 'another_bastion_host3',
                    'main_list': [
                        {'addr': 'another_bastion_hosts22'}
                    ]
                },
                {
                    'main_id': 'third_bastion',
                    'main_list': [
                        {'addr': 'hidden_bastion'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_mains_series, test_string, expected_result)

    def test_isc_clause_stmt_mains_standalone3_passing(self):
        test_string = 'mains example.com { mains; };'
        expected_result = {
            'mains': [
                {
                    'main_id': 'example.com',
                    'main_list': [
                        {'addr': 'mains'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_mains_standalone, test_string, expected_result)

    def test_isc_clause_stmt_mains_standalone4_passing(self):
        test_string = 'mains ns2 { 127.0.0.1; localhost; localnets; };'
        expected_result = {
            'mains': [
                {
                    'main_id': 'ns2',
                    'main_list': [
                        {'addr': '127.0.0.1'},
                        {'addr': 'localhost'},
                        {'addr': 'localnets'}
                    ]
                }
                ]
        }
        assertParserResultDictTrue(clause_stmt_mains_standalone, test_string, expected_result)

    def test_isc_clause_stmt_mains_standalone5_passing(self):
        test_string = 'mains example.com port 53 { mains; };'
        expected_result = {
            'mains': [
                {
                    'ip_port': 53,
                    'main_id': 'example.com',
                    'main_list': [
                        {'addr': 'mains'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(
            clause_stmt_mains_standalone,
            test_string,
            expected_result
        )

    def isc_test_clause_stmt_mains_standalone6_passing(self):
        test_string = 'mains example.com dscp 7 { mains; };'
        expected_result = {
            'mains': [
                {
                    'dscp_port': 7,
                    'main_id': 'example.com',
                    'main_list': [
                        {'addr': 'mains'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_mains_standalone, test_string, expected_result)

    def isc_clause_stmt_mains_standalone7_passing(self):
        test_string = 'mains example.com port 53 dscp 7 { big.com key partner_secret_key; };'
        expected_result = {
            'mains': [
                {
                    'dscp_port': 7,
                    'ip_port': 53,
                    'main_id': 'example.com',
                    'main_list': [
                        {
                            'addr': 'big.com',
                            'key_id': 'partner_secret_key'
                        }
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_mains_standalone, test_string, expected_result)

    def test_isc_clause_stmt_mains_series2_passing(self):
        """Mains clause, Main statement series; passing mode"""
        test_string = 'mains A { B; C; }; mains D { E; F; };'
        expected_result = {
            'mains': [
                {
                    'main_id': 'A',
                    'main_list': [
                        {'addr': 'B'},
                        {'addr': 'C'}
                    ]
                },
                {
                    'main_id': 'D',
                    'main_list': [
                        {'addr': 'E'},
                        {'addr': 'F'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_mains_series, test_string, expected_result)


if __name__ == '__main__':
    unittest.main()
