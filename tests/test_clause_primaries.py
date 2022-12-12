#!/usr/bin/env python3
"""
File: test_clause_primaries.py

Description:  Performs unit test on the 'primaries' clause in isc_clause_primaries.py.py source file.
"""

import unittest
from bind9_parser.isc_utils import primaries_id,\
    assert_parser_result_dict_true, assert_parser_result_dict_false
from bind9_parser.isc_clause_primaries import \
    clause_cloned_primaries_remoteserver_set, \
    clause_stmt_primaries_standalone, \
    clause_stmt_primaries_series


class TestClausePrimaries(unittest.TestCase):
    """ Clause primaries """

    def test_isc_clause_primary_standalone_passing(self):
        """Primaries clause, Primary Standalone general; passing mode"""
        assert_parser_result_dict_true(
            clause_stmt_primaries_standalone,
            'primaries oldmaster { remote-server-name; 1.2.3.4; 2e:fe::1; 2.3.4.5 key "123" tls "asdd"; };',
            {'primaries': {'primaries_id': 'oldmaster',
                           'remote_servers': [{'remote_server': {'primaries_name': 'remote-server-name'}},
                                              {'remote_server': {'ip4_addr': '1.2.3.4'}},
                                              {'remote_server': {'ip6_addr': '2e:fe::1'}},
                                              {'remote_server': {'ip4_addr': '2.3.4.5',
                                                                 'key_id': '123',
                                                                 'tls_id': 'asdd'}}]}}
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
            """primaries oldmaster { remote-server-name; 1.2.3.4; 2e:fe::1; 2.3.4.5 key "123" tls "asdd"; };
    primaries newmaster port 5353 { new-master-name; 2.3.4.5; 4.5.6.7 key "123"; };
    primaries next_master dscp 10 { };""",
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
                                                                  'key_id': '123'}}]},
                           {'dscp_port': 10,
                            'primaries_id': 'next_master'}]}
        )


if __name__ == '__main__':
    unittest.main()
