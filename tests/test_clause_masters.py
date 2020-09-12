#!/usr/bin/env python3
"""
File: test_clause_masters.py

Description:  Performs unit test on the isc_clause_masters.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue, assertParserResultDictFalse
from bind9_parser.isc_clause_masters import \
    master_id, \
    masters_element_series,\
    clause_stmt_masters_standalone, clause_stmt_masters_series


class TestClauseMasters(unittest.TestCase):
    """ Clause masters """

    def test_isc_masters_name_passing(self):
        """ Clause masters; Series Master Name; passing mode """
        expected_result = {'master_id': 'primary_nameservers'}
        assertParserResultDictTrue(master_id, 'primary_nameservers', expected_result)
        expected_result = {'master_id': 'secondary-slaves'}
        assertParserResultDictTrue(master_id, 'secondary-slaves', expected_result)
        expected_result = {'master_id': 'demilitarized_zone_servers'}
        assertParserResultDictTrue(master_id, 'demilitarized_zone_servers', expected_result)

    def test_isc_masters_name_failing(self):
        """ Clause masters; Series Master Name; failing mode """
        test_data = [
            'route,net;',
            'bad host',
            'no such;',
        ]
        expected_result = {'master_id': '2.2.2.2'}
        assertParserResultDictFalse(master_id, 'route.net;', expected_result)
        assertParserResultDictFalse(master_id, 'bad host', expected_result)
        assertParserResultDictFalse(master_id, 'no such;', expected_result)

    def test_isc_master_name_passing(self):
        """Masters clause, Master Name type, passing mode"""
        test_string = 'master_bastion_host'
        expected_result = {'master_id': 'master_bastion_host'}
        assertParserResultDictTrue(master_id, test_string, expected_result)
        test_string = '\'secondary_firewall_host\''
        expected_result = {'master_id': '\'secondary_firewall_host\''}
        assertParserResultDictTrue(master_id, test_string, expected_result)
        test_string = '"hidden_primary"'
        expected_result = {'master_id': '"hidden_primary"'}
        assertParserResultDictTrue(master_id, test_string, expected_result)
        test_string = 'asdf"asdf"'
        expected_result = {'master_id': 'asdf"asdf"'}
        assertParserResultDictTrue(master_id, test_string, expected_result)

    def test_isc_master_name_failing(self):
        """Masters clause, Master Name type, purposely failing mode"""
        test_string = 'netspeed 150000000'
        expected_result = {'master_id': 'netspeed'}
        assertParserResultDictFalse(master_id, test_string, expected_result)

    def test_isc_masters_element_series_passing(self):
        """Masters clause, Master Element series, passing mode"""
        test_string = 'primary_subdomain key "master_key_maker";'
        expected_result = {
            'master_list': [
                {
                    'addr': 'primary_subdomain',
                    'key_id': '"master_key_maker"'}]}
        assertParserResultDictTrue(masters_element_series, test_string, expected_result)
        test_string = 'master_recon_border_gateway key "My_Secret_Company_Key";'
        expected_result = {
            'master_list': [
                {
                    'addr': 'master_recon_border_gateway',
                    'key_id': '"My_Secret_Company_Key"'}]}
        assertParserResultDictTrue(masters_element_series, test_string, expected_result)

    def test_isc_masters_element_series_failing(self):
        """Masters clause, Master Element series, purposely failing mode"""
        test_string = 'netspeed 150000000'
        expected_result = {
            'master_list': [
                {'addr': 'master_recon_border_gateway', 'key_id': '"My_Secret_Company_Key"'}
            ]
        }
        assertParserResultDictFalse(masters_element_series, test_string, expected_result)

    def test_isc_clause_stmt_masters_standalone_passing(self):
        """Masters clause, passing mode"""
        test_string = 'masters ns1 { 127.0.0.1; };'
        expected_result = {
            'masters': [
                {
                    'master_id': 'ns1',
                    'master_list': [
                        {'addr': '127.0.0.1'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_masters_standalone, test_string, expected_result)

# masters example.com { masters; my_secondaries; };
    def test_isc_clause_stmt_masters_ACLname_passing(self):
        """ Master clause, ACL usages; passing mode"""
        test_string = 'masters example.com { masters; my_secondaries; };'
        expected_result = {
            'masters': [
                {
                    'master_id': 'example.com',
                    'master_list': [
                        {'addr': 'masters'},
                        {'addr': 'my_secondaries'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_masters_standalone, test_string, expected_result)

    def test_isc_clause_stmt_masters_multielement_passing(self):
        """Masters clause, passing mode"""
        test_string = 'masters ns1 { 127.0.0.1; 192.168.1.1; 192.168.6.1; };'
        expected_result = { 'masters': [ { 'master_id': 'ns1',
                                           'master_list': [ {'addr': '127.0.0.1'},
                                                            {'addr': '192.168.1.1'},
                                                            {'addr': '192.168.6.1'}]}]}
        assertParserResultDictTrue(clause_stmt_masters_standalone, test_string, expected_result)
        test_string = 'masters ns1 { another_bastion_hosts1; hidden_bastion2; };'
        expected_result = { 'masters': [ { 'master_id': 'ns1',
                 'master_list': [ { 'addr': 'another_bastion_hosts1'},
                                  {'addr': 'hidden_bastion2'}]}]}
        assertParserResultDictTrue(clause_stmt_masters_standalone, test_string, expected_result)

    def test_isc_clause_stmt_masters_series_passing(self):
        test_string = 'masters another_bastion_host3 { another_bastion_hosts22; }; masters third_bastion { hidden_bastion; };'
        expected_result = {
            'masters': [
                {
                    'master_id': 'another_bastion_host3',
                    'master_list': [
                        {'addr': 'another_bastion_hosts22'}
                    ]
                },
                {
                    'master_id': 'third_bastion',
                    'master_list': [
                        {'addr': 'hidden_bastion'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_masters_series, test_string, expected_result)

    def test_isc_clause_stmt_masters_standalone3_passing(self):
        test_string = 'masters example.com { masters; };'
        expected_result = {
            'masters': [
                {
                    'master_id': 'example.com',
                    'master_list': [
                        {'addr': 'masters'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_masters_standalone, test_string, expected_result)

    def test_isc_clause_stmt_masters_standalone4_passing(self):
        test_string = 'masters ns2 { 127.0.0.1; localhost; localnets; };'
        expected_result = {
            'masters': [
                {
                    'master_id': 'ns2',
                    'master_list': [
                        {'addr': '127.0.0.1'},
                        {'addr': 'localhost'},
                        {'addr': 'localnets'}
                    ]
                }
                ]
        }
        assertParserResultDictTrue(clause_stmt_masters_standalone, test_string, expected_result)

    def test_isc_clause_stmt_masters_standalone5_passing(self):
        test_string = 'masters example.com port 53 { masters; };'
        expected_result = {
            'masters': [
                {
                    'ip_port': '53',
                    'master_id': 'example.com',
                    'master_list': [
                        {'addr': 'masters'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(
            clause_stmt_masters_standalone,
            test_string,
            expected_result
        )

    def isc_test_clause_stmt_masters_standalone6_passing(self):
        test_string = 'masters example.com dscp 7 { masters; };'
        expected_result = {
            'masters': [
                {
                    'dscp_port': 7,
                    'master_id': 'example.com',
                    'master_list': [
                        {'addr': 'masters'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_masters_standalone, test_string, expected_result)

    def isc_clause_stmt_masters_standalone7_passing(self):
        test_string = 'masters example.com port 53 dscp 7 { big.com key partner_secret_key; };'
        expected_result = {
            'masters': [
                {
                    'dscp_port': '7',
                    'ip_port': '53',
                    'master_id': 'example.com',
                    'master_list': [
                        {
                            'addr': 'big.com',
                            'key_id': 'partner_secret_key'
                        }
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_masters_standalone, test_string, expected_result)

    def test_isc_clause_stmt_masters_series2_passing(self):
        """Masters clause, Master statement series; passing mode"""
        test_string = 'masters A { B; C; }; masters D { E; F; };'
        expected_result = {
            'masters': [
                {
                    'master_id': 'A',
                    'master_list': [
                        {'addr': 'B'},
                        {'addr': 'C'}
                    ]
                },
                {
                    'master_id': 'D',
                    'master_list': [
                        {'addr': 'E'},
                        {'addr': 'F'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_masters_series, test_string, expected_result)


if __name__ == '__main__':
    unittest.main()
