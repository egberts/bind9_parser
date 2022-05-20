#!/usr/bin/env python3
"""
File: test_clause_primaries.py

Description:  Performs unit test on the 'primaries' clause in isc_clause_primaries.py.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue, assertParserResultDictFalse
from bind9_parser.isc_clause_primaries import \
    primary_id, \
    primaries_element_series,\
    clause_stmt_primaries_standalone, clause_stmt_primaries_series


class TestClausePrimaries(unittest.TestCase):
    """ Clause primaries """

    def test_isc_primaries_name_passing(self):
        """ Clause primaries; Series Primary Name; passing mode """
        expected_result = {'primary_id': 'primary_nameservers'}
        assertParserResultDictTrue(primary_id, 'primary_nameservers', expected_result)
        expected_result = {'primary_id': 'secondary-slaves'}
        assertParserResultDictTrue(primary_id, 'secondary-slaves', expected_result)
        expected_result = {'primary_id': 'demilitarized_zone_servers'}
        assertParserResultDictTrue(primary_id, 'demilitarized_zone_servers', expected_result)

    def test_isc_primaries_name_failing(self):
        """ Clause primaries; Series Primary Name; failing mode """
        test_data = [
            'route,net;',
            'bad host',
            'no such;',
        ]
        expected_result = {'primary_id': '2.2.2.2'}
        assertParserResultDictFalse(primary_id, 'route.net;', expected_result)
        assertParserResultDictFalse(primary_id, 'bad host', expected_result)
        assertParserResultDictFalse(primary_id, 'no such;', expected_result)

    def test_isc_primary_name_passing(self):
        """Primaries clause, Primary Name type, passing mode"""
        test_string = 'primary_bastion_host'
        expected_result = {'primary_id': 'primary_bastion_host'}
        assertParserResultDictTrue(primary_id, test_string, expected_result)
        test_string = '\'secondary_firewall_host\''
        expected_result = {'primary_id': '\'secondary_firewall_host\''}
        assertParserResultDictTrue(primary_id, test_string, expected_result)
        test_string = '"hidden_primary"'
        expected_result = {'primary_id': '"hidden_primary"'}
        assertParserResultDictTrue(primary_id, test_string, expected_result)
        test_string = 'asdf"asdf"'
        expected_result = {'primary_id': 'asdf"asdf"'}
        assertParserResultDictTrue(primary_id, test_string, expected_result)

    def test_isc_primary_name_failing(self):
        """Primaries clause, Primary Name type, purposely failing mode"""
        test_string = 'netspeed 150000000'
        expected_result = {'primary_id': 'netspeed'}
        assertParserResultDictFalse(primary_id, test_string, expected_result)

    def test_isc_primaries_element_series_passing(self):
        """Primaries clause, Primary Element series, passing mode"""
        test_string = 'primary_subdomain key "primary_key_maker";'
        expected_result = {
            'primary_list': [
                {
                    'addr': 'primary_subdomain',
                    'key_id': '"primary_key_maker"'}]}
        assertParserResultDictTrue(primaries_element_series, test_string, expected_result)
        test_string = 'primary_recon_border_gateway key "My_Secret_Company_Key";'
        expected_result = {
            'primary_list': [
                {
                    'addr': 'primary_recon_border_gateway',
                    'key_id': '"My_Secret_Company_Key"'}]}
        assertParserResultDictTrue(primaries_element_series, test_string, expected_result)

    def test_isc_primaries_element_series_failing(self):
        """Primaries clause, Primary Element series, purposely failing mode"""
        test_string = 'netspeed 150000000'
        expected_result = {
            'primary_list': [
                {'addr': 'primary_recon_border_gateway', 'key_id': '"My_Secret_Company_Key"'}
            ]
        }
        assertParserResultDictFalse(primaries_element_series, test_string, expected_result)

    def test_isc_clause_stmt_primaries_standalone_passing(self):
        """Primaries clause, passing mode"""
        test_string = 'primaries ns1 { 127.0.0.1; };'
        expected_result = {
            'primaries': [
                {
                    'primary_id': 'ns1',
                    'primary_list': [
                        {'addr': '127.0.0.1'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_primaries_standalone, test_string, expected_result)

# primaries example.com { primaries; my_secondaries; };
    def test_isc_clause_stmt_primaries_ACLname_passing(self):
        """ Primaries clause, ACL usages; passing mode"""
        test_string = 'primaries example.com { primaries; my_secondaries; };'
        expected_result = {
            'primaries': [
                {
                    'primary_id': 'example.com',
                    'primary_list': [
                        {'addr': 'primaries'},
                        {'addr': 'my_secondaries'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_primaries_standalone, test_string, expected_result)

    def test_isc_clause_stmt_primaries_multielement_passing(self):
        """Primaries clause, passing mode"""
        test_string = 'primaries ns1 { 127.0.0.1; 192.168.1.1; 192.168.6.1; };'
        expected_result = { 'primaries': [ { 'primary_id': 'ns1',
                                           'primary_list': [ {'addr': '127.0.0.1'},
                                                            {'addr': '192.168.1.1'},
                                                            {'addr': '192.168.6.1'}]}]}
        assertParserResultDictTrue(clause_stmt_primaries_standalone, test_string, expected_result)
        test_string = 'primaries ns1 { another_bastion_hosts1; hidden_bastion2; };'
        expected_result = { 'primaries': [ { 'primary_id': 'ns1',
                 'primary_list': [ { 'addr': 'another_bastion_hosts1'},
                                  {'addr': 'hidden_bastion2'}]}]}
        assertParserResultDictTrue(clause_stmt_primaries_standalone, test_string, expected_result)

    def test_isc_clause_stmt_primaries_series_passing(self):
        test_string = 'primaries another_bastion_host3 { another_bastion_hosts22; }; primaries third_bastion { hidden_bastion; };'
        expected_result = {
            'primaries': [
                {
                    'primary_id': 'another_bastion_host3',
                    'primary_list': [
                        {'addr': 'another_bastion_hosts22'}
                    ]
                },
                {
                    'primary_id': 'third_bastion',
                    'primary_list': [
                        {'addr': 'hidden_bastion'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_primaries_series, test_string, expected_result)

    def test_isc_clause_stmt_primaries_standalone3_passing(self):
        test_string = 'primaries example.com { primaries; };'
        expected_result = {
            'primaries': [
                {
                    'primary_id': 'example.com',
                    'primary_list': [
                        {'addr': 'primaries'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_primaries_standalone, test_string, expected_result)

    def test_isc_clause_stmt_primaries_standalone4_passing(self):
        test_string = 'primaries ns2 { 127.0.0.1; localhost; localnets; };'
        expected_result = {
            'primaries': [
                {
                    'primary_id': 'ns2',
                    'primary_list': [
                        {'addr': '127.0.0.1'},
                        {'addr': 'localhost'},
                        {'addr': 'localnets'}
                    ]
                }
                ]
        }
        assertParserResultDictTrue(clause_stmt_primaries_standalone, test_string, expected_result)

    def test_isc_clause_stmt_primaries_standalone5_passing(self):
        test_string = 'primaries example.com port 53 { primaries; };'
        expected_result = {
            'primaries': [
                {
                    'ip_port': '53',
                    'primary_id': 'example.com',
                    'primary_list': [
                        {'addr': 'primaries'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(
            clause_stmt_primaries_standalone,
            test_string,
            expected_result
        )

    def isc_test_clause_stmt_primaries_standalone6_passing(self):
        test_string = 'primaries example.com dscp 7 { primaries; };'
        expected_result = {
            'primaries': [
                {
                    'dscp_port': 7,
                    'primary_id': 'example.com',
                    'primary_list': [
                        {'addr': 'primaries'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_primaries_standalone, test_string, expected_result)

    def isc_clause_stmt_primaries_standalone7_passing(self):
        test_string = 'primaries example.com port 53 dscp 7 { big.com key partner_secret_key; };'
        expected_result = {
            'primaries': [
                {
                    'dscp_port': '7',
                    'ip_port': '53',
                    'primary_id': 'example.com',
                    'primary_list': [
                        {
                            'addr': 'big.com',
                            'key_id': 'partner_secret_key'
                        }
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_primaries_standalone, test_string, expected_result)

    def test_isc_clause_stmt_primaries_series2_passing(self):
        """Primaries clause, Primary statement series; passing mode"""
        test_string = 'primaries A { B; C; }; primaries D { E; F; };'
        expected_result = {
            'primaries': [
                {
                    'primary_id': 'A',
                    'primary_list': [
                        {'addr': 'B'},
                        {'addr': 'C'}
                    ]
                },
                {
                    'primary_id': 'D',
                    'primary_list': [
                        {'addr': 'E'},
                        {'addr': 'F'}
                    ]
                }
            ]
        }
        assertParserResultDictTrue(clause_stmt_primaries_series, test_string, expected_result)


if __name__ == '__main__':
    unittest.main()
