#!/usr/bin/env python3
"""
File: test_clause_acl.py

Clause: acl

Description:  Performs unit test on the isc_clause_acl.py source file.
"""

import unittest
from bind9_parser.isc_utils import assert_parser_result_dict_true
from bind9_parser.isc_clause_acl import clause_stmt_acl_series, clause_stmt_acl_standalone


class TestClauseACL(unittest.TestCase):
    """ Clause ACL """

    def setUp(self):
        pass

    def test_isc_clause_acl_standalone_passing(self):
        """ Clause  ACL, standalone; passing mode"""
        test_data = [
            'acl a { }; ',
            'acl a { b; };',
            'acl unquoted-key_id { 127.0.0.1; };',
            'acl master-nameservers { 8.8.8.8; 9.9.9.9; };',
            'acl master_nameservers { any; };',
            'acl master_nameservers { none; };',
            'acl master_nameservers { localhost; };',
            'acl master_nameservers { localnets; };',
            'acl master_nameservers { 1.1.1.1; };',
            ]
        #            'acl "dquoted-key_id" { 128.1.1.2; };',          # TODO double-quote fails here
        #            'acl \'squoted-key_id\' { 129.2.2.3; };',        # TODO single-quote fails here
        result = clause_stmt_acl_series.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_clause_acl_standalone_failing(self):
        """ Clause ACL, standalone; failing mode """
        test_data = [
            'acl a { b };',  # missing inside semicolon
            'acl a { b; }',  # missing outside semicolon
            'acl FunkY/name { }; ',
            'acl weird_aml { all }; ',  # 'all' works, but it is missing a semicolon
            'acl master-nameservers {{8.8.8.8; 9.9.9.9; };',
            'acl master-nameservers 8.8.8.8; 9.9.9.9; };',
            'acl master-nameservers { 8.8.8,8; 9.9.9.9; };',  # comma, not period
            'acl master-nameservers { 8.8.8.8: 9.9.9.9; };',  # colon, not semicolon
        ]
        result = clause_stmt_acl_series.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_clause_acl_list_simple(self):
        """ Clause ACL; clause_stmt_acl_series; List, simple; passing """
        test_string = 'acl e { f; };'
        expected_result = {
            'acl': [
                {
                    'acl_name': 'e',
                    'aml_series': [
                        {
                            'aml': [
                                {'acl_name': 'f'}
                            ]
                        }
                    ]
                }
            ]
        }
        assert_parser_result_dict_true(
                clause_stmt_acl_standalone,
                test_string,
                expected_result)

    def test_isc_clause_acl_clause_stmt_acl_clause_series(self):
        """ Clause ACL; caluse_stmt_acl; Clause Series; passing """
        test_data = 'acl a { b; }; acl c { d; };'
        expected_result = {
            'acl': [
                {
                    'acl_name': 'a',
                    'aml_series': [
                        {
                            'aml': [
                                {'acl_name': 'b'},
                            ]}
                    ]},
                {
                    'acl_name': 'c',
                    'aml_series': [
                        {
                            'aml': [
                                {'acl_name': 'd'},
                            ]}
                    ]}

            ]}
        assert_parser_result_dict_true(clause_stmt_acl_series, test_data, expected_result)

    def test_isc_clause_stmt_acl_public(self):
        """ Clause ACL; clause_stmt_acl_series; Public; passing """
        test_data = """
        acl xfer_acl { none; };
        acl external_bastion_ip_acl { 99.99.99.99; };
        acl trusted_cablesupport_acl { 192.168.0.0/24; 192.168.1.1/24; };
        acl trusted_real_dmz_acl { 192.168.2.0/24; };
        acl trusted_residential_network_dmz_acl { 192.168.4.0/24; };
        acl trusted_residential_network_blue_acl { 192.168.5.0/24; };
        acl trusted_residential_gateway_acl { 192.168.6.1; };
        acl trusted_residential_network_green_acl { 192.168.7.0/24; };
        acl trusted_residential_network_white_acl { 192.168.8.0/24; };
        acl trusted_residential_network_vmnet_acl { 192.168.32.0/24; };
        acl trusted_remote_vpn_acl { 192.168.64.0/16; };
        acl trusted_residential_network_acl {
            trusted_residential_network_dmz_acl;
            trusted_residential_network_blue_acl;
            trusted_residential_network_green_acl;
            trusted_residential_network_white_acl;
            trusted_residential_network_vmnet_acl; };
        acl trusted_all_acl {
            trusted_real_dmz_acl;
            trusted_residential_network_dmz_acl;
            trusted_residential_network_blue_acl;
            trusted_residential_network_green_acl;
            trusted_residential_network_white_acl;
            trusted_residential_network_vmnet_acl;
            trusted_cablesupport_acl;
            localnet_acl; }; """
        my_csa = clause_stmt_acl_series.setWhitespaceChars(' \t\n')
        assert_parser_result_dict_true(
            my_csa,
            test_data,
            {'acl': [{'acl_name': 'xfer_acl',
                      'aml_series': [{'aml': [{'keyword': 'none'}]}]},
                     {'acl_name': 'external_bastion_ip_acl',
                      'aml_series': [{'aml': [{'ip4_addr': '99.99.99.99'}]}]},
                     {'acl_name': 'trusted_cablesupport_acl',
                      'aml_series': [{'aml': [{'ip4_addr': '192.168.0.0',
                                               'prefix': '24'},
                                              {'ip4_addr': '192.168.1.1',
                                               'prefix': '24'}]}]},
                     {'acl_name': 'trusted_real_dmz_acl',
                      'aml_series': [{'aml': [{'ip4_addr': '192.168.2.0',
                                               'prefix': '24'}]}]},
                     {'acl_name': 'trusted_residential_network_dmz_acl',
                      'aml_series': [{'aml': [{'ip4_addr': '192.168.4.0',
                                               'prefix': '24'}]}]},
                     {'acl_name': 'trusted_residential_network_blue_acl',
                      'aml_series': [{'aml': [{'ip4_addr': '192.168.5.0',
                                               'prefix': '24'}]}]},
                     {'acl_name': 'trusted_residential_gateway_acl',
                      'aml_series': [{'aml': [{'ip4_addr': '192.168.6.1'}]}]},
                     {'acl_name': 'trusted_residential_network_green_acl',
                      'aml_series': [{'aml': [{'ip4_addr': '192.168.7.0',
                                               'prefix': '24'}]}]},
                     {'acl_name': 'trusted_residential_network_white_acl',
                      'aml_series': [{'aml': [{'ip4_addr': '192.168.8.0',
                                               'prefix': '24'}]}]},
                     {'acl_name': 'trusted_residential_network_vmnet_acl',
                      'aml_series': [{'aml': [{'ip4_addr': '192.168.32.0',
                                               'prefix': '24'}]}]},
                     {'acl_name': 'trusted_remote_vpn_acl',
                      'aml_series': [{'aml': [{'ip4_addr': '192.168.64.0',
                                               'prefix': '16'}]}]},
                     {'acl_name': 'trusted_residential_network_acl',
                      'aml_series': [{'aml': [{'acl_name': 'trusted_residential_network_dmz_acl'},
                                              {'acl_name': 'trusted_residential_network_blue_acl'},
                                              {'acl_name': 'trusted_residential_network_green_acl'},
                                              {'acl_name': 'trusted_residential_network_white_acl'},
                                              {'acl_name': 'trusted_residential_network_vmnet_acl'}]}]},
                     {'acl_name': 'trusted_all_acl',
                      'aml_series': [{'aml': [{'acl_name': 'trusted_real_dmz_acl'},
                                              {'acl_name': 'trusted_residential_network_dmz_acl'},
                                              {'acl_name': 'trusted_residential_network_blue_acl'},
                                              {'acl_name': 'trusted_residential_network_green_acl'},
                                              {'acl_name': 'trusted_residential_network_white_acl'},
                                              {'acl_name': 'trusted_residential_network_vmnet_acl'},
                                              {'acl_name': 'trusted_cablesupport_acl'},
                                              {'acl_name': 'localnet_acl'}]}]}]}
        )

    def test_isc_clause_stmt_acl_public(self):
        """ Clause ACL; clause_stmt_acl_series; Public; passing """
        test_data = """
        acl "a3internet" { 10.1.12.25; 10.1.12.26; };
        acl "my" { 127.0.0.1; };
        """
        my_csa = clause_stmt_acl_series.setWhitespaceChars(' \t\n')
        assert_parser_result_dict_true(
            my_csa,
            test_data,
            {
                'acl': [
                    {
                        'acl_name': '"a3internet"',
                        'aml_series': [
                            {
                                'aml': [
                                    {'ip4_addr': '10.1.12.25'},
                                    {'ip4_addr': '10.1.12.26'}
                                ]
                            }
                        ]
                    },
                    {
                        'acl_name': '"my"',
                        'aml_series': [
                            {
                                'aml': [
                                    {'ip4_addr': '127.0.0.1'}
                                ]
                            }
                        ]
                    }
                ]
            }
        )


if __name__ == '__main__':
    unittest.main()
