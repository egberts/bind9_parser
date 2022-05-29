#!/usr/bin/env python3
"""
File: test_clause_primaries.py

Description:  Performs unit test on the 'primaries' clause in isc_clause_primaries.py.py source file.
"""

import unittest
from bind9_parser.isc_utils import assert_parser_result_dict_true, assert_parser_result_dict_false
from bind9_parser.isc_clause_primaries import \
    primary_id, \
    primaries_element_series,\
    clause_stmt_primaries_standalone, clause_stmt_primaries_series


class TestClausePrimaries(unittest.TestCase):
    """ Clause primaries """

    def test_isc_primaries_name_passing(self):
        """ Clause primaries; Series Primary Name; passing mode """
        expected_result = {'primary_id': 'primary_nameservers'}
        assert_parser_result_dict_true(primary_id, 'primary_nameservers', expected_result)
        expected_result = {'primary_id': 'secondary-slaves'}
        assert_parser_result_dict_true(primary_id, 'secondary-slaves', expected_result)
        expected_result = {'primary_id': 'demilitarized_zone_servers'}
        assert_parser_result_dict_true(primary_id, 'demilitarized_zone_servers', expected_result)

    def test_isc_primaries_name_failing(self):
        """ Clause primaries; Series Primary Name; failing mode """
        test_data = [
            'route,net;',
            'bad host',
            'no such;',
        ]
        expected_result = {'primary_id': '2.2.2.2'}
        assert_parser_result_dict_false(primary_id, 'route.net;', expected_result)
        assert_parser_result_dict_false(primary_id, 'bad host', expected_result)
        assert_parser_result_dict_false(primary_id, 'no such;', expected_result)

    def test_isc_primary_name_passing(self):
        """Primaries clause, Primary Name type, passing mode"""
        test_string = 'primary_bastion_host'
        expected_result = {'primary_id': 'primary_bastion_host'}
        assert_parser_result_dict_true(primary_id, test_string, expected_result)
        test_string = '\'secondary_firewall_host\''
        expected_result = {'primary_id': '\'secondary_firewall_host\''}
        assert_parser_result_dict_true(primary_id, test_string, expected_result)
        test_string = '"hidden_primary"'
        expected_result = {'primary_id': '"hidden_primary"'}
        assert_parser_result_dict_true(primary_id, test_string, expected_result)
        test_string = 'asdf"asdf"'
        expected_result = {'primary_id': 'asdf"asdf"'}
        assert_parser_result_dict_true(primary_id, test_string, expected_result)

    def test_isc_primary_name_failing(self):
        """Primaries clause, Primary Name type, purposely failing mode"""
        test_string = 'netspeed 150000000'
        expected_result = {'primary_id': 'netspeed'}
        assert_parser_result_dict_false(primary_id, test_string, expected_result)

    def test_isc_primaries_element_series_passing(self):
        """Primaries clause, Primary Element series, passing mode"""
        assert_parser_result_dict_true(
            primaries_element_series,
            'primary_subdomain key "primary_key_maker";',
            {'primary_list': [{'key_id': '"primary_key_maker"',
                               'primary_name': 'primary_subdomain'}]}
        )

    def test_isc_primaries_element_series_2_passing(self):
        """Primaries clause, Primary Element series, passing mode"""
        assert_parser_result_dict_true(
            primaries_element_series,
            'primary_recon_border_gateway key "My_Secret_Company_Key";',
            {'primary_list': [{'key_id': '"My_Secret_Company_Key"',
                               'primary_name': 'primary_recon_border_gateway'}]}
        )

    def test_isc_primaries_element_series_failing(self):
        """Primaries clause, Primary Element series, purposely failing mode"""
        test_string = 'netspeed 150000000'
        expected_result = {
            'primary_list': [
                {'ip_addr': 'primary_recon_border_gateway', 'key_id': '"My_Secret_Company_Key"'}
            ]
        }
        assert_parser_result_dict_false(primaries_element_series, test_string, expected_result)

    def test_isc_clause_stmt_primaries_standalone_passing(self):
        """Primaries clause, passing mode"""
        assert_parser_result_dict_true(
            clause_stmt_primaries_standalone,
            'primaries ns1 { 127.0.0.1; };',
            {'primaries': [{'primary_id': 'ns1',
                            'primary_list': [{'ip4_addr': '127.0.0.1'}]}]}
        )

# primaries example.com { primaries; my_secondaries; };
    def test_isc_clause_stmt_primaries_ACLname_passing(self):
        """ Primaries clause, ACL usages; passing mode"""
        test_string = 'primaries 127.0.0.1 { 172.16.0.1; 10.0.0.1; };'
        expected_result = {
            'primaries': [
                {
                    'primary_id': '127.0.0.1',
                    'primary_list': [
                        {'ip4_addr': '172.16.0.1'},
                        {'ip4_addr': '10.0.0.1'}
                    ]
                }
            ]
        }
        assert_parser_result_dict_true(clause_stmt_primaries_standalone, test_string, expected_result)

    def test_isc_clause_stmt_primaries_multielement_passing(self):
        """Primaries clause, passing mode"""
        test_string = 'primaries ns1 { 127.0.0.1; 192.168.1.1; 192.168.6.1; };'
        assert_parser_result_dict_true(
            clause_stmt_primaries_standalone,
            test_string,
            {'primaries': [{'primary_id': 'ns1',
                            'primary_list': [{'ip4_addr': '127.0.0.1'},
                                             {'ip4_addr': '192.168.1.1'},
                                             {'ip4_addr': '192.168.6.1'}]}]}
        )

    def test_isc_clause_stmt_primaries_multielement_2_passing(self):
        """Primaries clause 2, passing mode"""
        assert_parser_result_dict_true(
            clause_stmt_primaries_standalone,
            'primaries ns1 { another_bastion_hosts1; hidden_bastion2; };',
            {'primaries': [{'primary_id': 'ns1',
                            'primary_list': [{'primary_name': 'another_bastion_hosts1'},
                                             {'primary_name': 'hidden_bastion2'}]}]}
        )

    def test_isc_clause_stmt_primaries_series_passing(self):
        assert_parser_result_dict_true(
            clause_stmt_primaries_series,
            'primaries another_bastion_host3 { another_bastion_hosts22; }; primaries third_bastion { hidden_bastion; };',
            {'primaries': [{'primary_id': 'another_bastion_host3',
                            'primary_list': [{'primary_name': 'another_bastion_hosts22'}]},
                           {'primary_id': 'third_bastion',
                            'primary_list': [{'primary_name': 'hidden_bastion'}]}]}
        )

    def test_isc_clause_stmt_primaries_standalone3_passing(self):
        assert_parser_result_dict_true(
            clause_stmt_primaries_standalone,
            'primaries example.com { primaries; };',
            {'primaries': [{'primary_id': 'example.com',
                            'primary_list': [{'primary_name': 'primaries'}]}]}
        )

    def test_isc_clause_stmt_primaries_standalone4_passing(self):
        assert_parser_result_dict_true(
            clause_stmt_primaries_standalone,
            'primaries ns2 { 127.0.0.1; localhost; localnets; };',
            {'primaries': [{'primary_id': 'ns2',
                            'primary_list': [{'ip4_addr': '127.0.0.1'},
                                             {'primary_name': 'localhost'},
                                             {'primary_name': 'localnets'}]}]}
        )

    def test_isc_clause_stmt_primaries_standalone5_passing(self):
        assert_parser_result_dict_true(
            clause_stmt_primaries_standalone,
            'primaries example.com port 53 { primaries; };',
            {'primaries': [{'ip_port': '53',
                            'primary_id': 'example.com',
                            'primary_list': [{'primary_name': 'primaries'}]}]}
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
        assert_parser_result_dict_true(clause_stmt_primaries_standalone, test_string, expected_result)

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
        assert_parser_result_dict_true(clause_stmt_primaries_standalone, test_string, expected_result)

    def test_isc_clause_stmt_primaries_series2_passing(self):
        """Primaries clause, Primary statement series; passing mode"""
        assert_parser_result_dict_true(
            clause_stmt_primaries_series,
            'primaries A { B; C; }; primaries D { E; F; };',
            {'primaries': [{'primary_id': 'A',
                            'primary_list': [{'primary_name': 'B'},
                                             {'primary_name': 'C'}]},
                           {'primary_id': 'D',
                            'primary_list': [{'primary_name': 'E'},
                                             {'primary_name': 'F'}]}]}
        )


if __name__ == '__main__':
    unittest.main()
