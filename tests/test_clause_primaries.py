#!/usr/bin/env python3
"""
File: test_clause_primaries.py

Description:  Performs unit test on the 'primaries' clause in isc_clause_primaries.py.py source file.
"""

import unittest
from bind9_parser.isc_utils import assert_parser_result_dict_true
from bind9_parser.isc_clause_primaries import \
    clause_stmt_primaries_standalone, \
    clause_stmt_primaries_series


class TestClausePrimaries(unittest.TestCase):
    """ Clause primaries """

    def test_isc_clause_primary_standalone_bare_passing(self):
        """Primaries clause, Primary Standalone bare; passing mode"""
        assert_parser_result_dict_true(
            clause_stmt_primaries_standalone,
            'primaries oldmaster {  };',
            {'primaries': {'primaries_id': 'oldmaster'}}
        )

    def test_isc_clause_primary_standalone_port_passing(self):
        """Primaries clause, Primary Standalone port; passing mode"""
        assert_parser_result_dict_true(
            clause_stmt_primaries_standalone,
            'primaries oldmaster port 5353  {  };',
            {
                'primaries': {
                    'ip_port': '5353',
                    'primaries_id': 'oldmaster'
                }
            }
        )

    def test_isc_clause_primary_standalone_dscp_passing(self):
        """Primaries clause, Primary Standalone dscp; passing mode"""
        assert_parser_result_dict_true(
            clause_stmt_primaries_standalone,
            'primaries my_primary dscp 12 {  };',
            {
                'primaries': {
                    'dscp_port': 12,
                    'primaries_id': 'my_primary'
                }
            }
        )

    def test_isc_clause_primary_standalone_port_dscp_passing(self):
        """Primaries clause, Primary Standalone port/dscp; passing mode"""
        assert_parser_result_dict_true(
            clause_stmt_primaries_standalone,
            'primaries red_zone port 5454 dscp 13 {  };',
            {
                'primaries': {
                    'dscp_port': 13,
                    'ip_port': '5454',
                    'primaries_id': 'red_zone'
                }
            }
        )

    def test_isc_clause_primary_standalone_port_dscp_reversed_passing(self):
        """Primaries clause, Primary Standalone reversed port/dscp; passing mode"""
        assert_parser_result_dict_true(
            clause_stmt_primaries_standalone,
            'primaries demilitarized_zone dscp 14 port 5555 {  };',
            {
                'primaries': {
                    'dscp_port': 14,
                    'ip_port': '5555',
                    'primaries_id': 'demilitarized_zone'
                }
            }
        )

    def test_isc_clause_primary_standalone_acl_passing(self):
        """Primaries clause, Primary Standalone ACL; passing mode"""
        assert_parser_result_dict_true(
            clause_stmt_primaries_standalone,
            'primaries corp_zone { eng_zone; };',
            {'primaries': {'primaries_id': 'corp_zone',
                           'remote_servers': [{'remote_server': {'primaries_name': 'eng_zone'}}]}},
        )

    def test_isc_clause_primary_standalone_acls_passing(self):
        """Primaries clause, Primary Standalone ACLs; passing mode"""
        assert_parser_result_dict_true(
            clause_stmt_primaries_standalone,
            'primaries corp_zone { abc.example.tld; 2.3.4.5; 2.3.4.5 key "2345" tls "qwer"; 2e:fe::1; };',
            {'primaries': {'primaries_id': 'corp_zone',
                           'remote_servers': [{'remote_server': {'primaries_name': 'abc.example.tld'}},
                                              {'remote_server': {'ip4_addr': '2.3.4.5'}},
                                              {'remote_server': {'ip4_addr': '2.3.4.5',
                                                                 'key_id': '2345',
                                                                 'tls_id': 'qwer'}},
                                              {'remote_server': {'ip6_addr': '2e:fe::1'}}]}}
        )

    def test_isc_clause_primary_standalone_full_passing(self):
        """Primaries clause, Primary Standalone full; passing mode"""
        assert_parser_result_dict_true(
            clause_stmt_primaries_standalone,
            """
    primaries corp_zone port 5252 dscp 8 {
        remote-server-name; 
        4.5.6.7 key "zxcv" tls "sdfg";
        6.6.7.8; 
        2e:fe::2; 
        };""",
            {'primaries': {'dscp_port': 8,
                           'ip_port': '5252',
                           'primaries_id': 'corp_zone',
                           'remote_servers': [{'remote_server': {'primaries_name': 'remote-server-name'}},
                                              {'remote_server': {'ip4_addr': '4.5.6.7',
                                                                 'key_id': 'zxcv',
                                                                 'tls_id': 'sdfg'}},
                                              {'remote_server': {'ip4_addr': '6.6.7.8'}},
                                              {'remote_server': {'ip6_addr': '2e:fe::2'}}]}}
        )

    def test_isc_clause_primary_series_passing(self):
        """Primaries clause, general; passing mode"""
        assert_parser_result_dict_true(
            clause_stmt_primaries_series,
            """primaries oldmaster { remote-server-name; 1.2.3.4; 2e:fe::1; 2.3.4.5 key "123" tls "asdd"; };
    primaries newmaster port 5353 { new-master-name; 2.3.4.5; 4.5.6.7 key "123"; };""",
            {'primaries': [{'primaries_id': 'oldmaster',
                            'remote_servers': [{'remote_server': {'primaries_name': 'remote-server-name'}},
                                               {'remote_server': {'ip4_addr': '1.2.3.4'}},
                                               {'remote_server': {'ip6_addr': '2e:fe::1'}},
                                               {'remote_server': {'ip4_addr': '2.3.4.5',
                                                                  'key_id': '123',
                                                                  'tls_id': 'asdd'}}]},
                           {'ip_port': '5353',
                            'primaries_id': 'newmaster',
                            'remote_servers': [{'remote_server': {'primaries_name': 'new-master-name'}},
                                               {'remote_server': {'ip4_addr': '2.3.4.5'}},
                                               {'remote_server': {'ip4_addr': '4.5.6.7',
                                                                  'key_id': '123'}}]}]}
        )

    def test_isc_clause_primary_series_2_passing(self):
        """Primaries clause, general; passing mode"""
        assert_parser_result_dict_true(
            clause_stmt_primaries_series,
            """
    primaries oldmaster {  };
    primaries my_primary dscp 12 {  };
    primaries oldmaster port 5353  {  };
    primaries red_zone port 5454 dscp 13 {  };
    primaries demilitarized_zone dscp 14 port 5555 {  };
    primaries corp_zone port 5252 dscp 8 {
        remote-server-name; 
        4.5.6.7 key "zxcv" tls "sdfg";
        6.6.7.8; 
        2e:fe::2; 
        };
    primaries corp_zone { eng_zone; };
    primaries corp2_zone { 6.7.8.10; };
    primaries corp3_zone { 2e:fd::10; };
    primaries corp4_zone { abc.example.tld; 2.3.4.5; 2.3.4.5 key "2345" tls "qwer"; 2e:fe::1; };
""",
            {'primaries': [{'primaries_id': 'oldmaster'},
                           {'dscp_port': 12, 'primaries_id': 'my_primary'},
                           {'ip_port': '5353', 'primaries_id': 'oldmaster'},
                           {'dscp_port': 13,
                            'ip_port': '5454',
                            'primaries_id': 'red_zone'},
                           {'dscp_port': 14,
                            'ip_port': '5555',
                            'primaries_id': 'demilitarized_zone'},
                           {'dscp_port': 8,
                            'ip_port': '5252',
                            'primaries_id': 'corp_zone',
                            'remote_servers': [{'remote_server': {'primaries_name': 'remote-server-name'}},
                                               {'remote_server': {'ip4_addr': '4.5.6.7',
                                                                  'key_id': 'zxcv',
                                                                  'tls_id': 'sdfg'}},
                                               {'remote_server': {'ip4_addr': '6.6.7.8'}},
                                               {'remote_server': {'ip6_addr': '2e:fe::2'}}]},
                           {'primaries_id': 'corp_zone',
                            'remote_servers': [{'remote_server': {'primaries_name': 'eng_zone'}}]},
                           {'primaries_id': 'corp2_zone',
                            'remote_servers': [{'remote_server': {'ip4_addr': '6.7.8.10'}}]},
                           {'primaries_id': 'corp3_zone',
                            'remote_servers': [{'remote_server': {'ip6_addr': '2e:fd::10'}}]},
                           {'primaries_id': 'corp4_zone',
                            'remote_servers': [{'remote_server': {'primaries_name': 'abc.example.tld'}},
                                               {'remote_server': {'ip4_addr': '2.3.4.5'}},
                                               {'remote_server': {'ip4_addr': '2.3.4.5',
                                                                  'key_id': '2345',
                                                                  'tls_id': 'qwer'}},
                                               {'remote_server': {'ip6_addr': '2e:fe::1'}}]}]}

        )


if __name__ == '__main__':
    unittest.main()
