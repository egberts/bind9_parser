#!/usr/bin/env python3
"""
File: test_primaries.py

Description:  Performs unit test on the 'primaries' statements (inside zone clause)
              in isc_primaries.py.py source file.
"""

import unittest
from bind9_parser.isc_utils import assert_parser_result_dict_true,\
    assert_parser_result_dict_false
from bind9_parser.isc_primaries import \
    primaries_remoteserver_element, \
    primaries_remoteserver_set, \
    primaries_remoteserver_element_series, \
    zone_stmt_primaries_standalone


class TestClausePrimaries(unittest.TestCase):
    """ Clause primaries """

    #         (
    #             <remote-servers>
    #             | <ipv4_address> [ port <integer> ]
    #             | <ipv6_address> [ port <integer> ]
    #         )
    def test_isc_primaries_remoteserver_name_passing(self):
        """ Primaries element; Element Servers by name; passing mode """
        assert_parser_result_dict_true(
            primaries_remoteserver_element,
            'primary-remote-server',
            {'primaries_name': 'primary-remote-server'}
        )

    def test_isc_primaries_remoteserver_ip4addr_passing(self):
        """ Primaries element; Element Servers by IPv4 address; passing mode """
        assert_parser_result_dict_true(
            primaries_remoteserver_element,
            '127.0.0.1',
            {'ip4_addr': '127.0.0.1'}
        )

    def test_isc_primaries_remoteserver_ip4addr_port_passing(self):
        """ Primaries element; Element Servers by IPv4 address and port number; passing mode """
        assert_parser_result_dict_true(
            primaries_remoteserver_element,
            '127.0.0.1 port 123',
            {'ip4_addr': '127.0.0.1', 'ip_port': '123'}
        )

    def test_isc_primaries_remoteserver_ip4addr_port_failing(self):
        """ Primaries element; Element Servers by IPv4 address and port number; failing mode """
        assert_parser_result_dict_false(
            primaries_remoteserver_element,
            'port 123',
            {'ip_port': '123'}
        )

    def test_isc_primaries_remoteserver_ip6addr_passing(self):
        """ Primaries element; Element Servers by IPv6 address; passing mode """
        assert_parser_result_dict_true(
            primaries_remoteserver_element,
            'fe:2c::1',
            {'ip6_addr': 'fe:2c::1'}
        )

    def test_isc_primaries_remoteserver_ip6addr_port_passing(self):
        """ Primaries element; Element Servers by IPv6 address and port number; passing mode """
        assert_parser_result_dict_true(
            primaries_remoteserver_element,
            'fe:2c::1 port 234',
            {'ip6_addr': 'fe:2c::1', 'ip_port': '234'}
        )

    # one remote server (ends with a semicolon)
    #
    #         (
    #             <remote-servers>
    #             | <ipv4_address> [ port <integer> ]
    #             | <ipv6_address> [ port <integer> ]
    #         )
    #         [ key <string> ]
    #         [ tls <string> ];
    def test_isc_primary_name_set_passing(self):
        """Primaries set, Primary Name set, passing mode"""
        assert_parser_result_dict_true(
            primaries_remoteserver_set,
            '1.2.3.4;',
            {'remote_server': {'ip4_addr': '1.2.3.4'}}
        )

    def test_isc_primary_name_set_key_passing(self):
        """Primaries set, Primary Name set with 'key' keyword, passing mode"""
        assert_parser_result_dict_true(
            primaries_remoteserver_set,
            'a.b.example.tld key "ABCDEFGHIJKL";',
            {'remote_server': {'key_id': 'ABCDEFGHIJKL',
                               'primaries_name': 'a.b.example.tld'}}
        )

    def test_isc_primary_ipv4_set_key_passing(self):
        """Primaries set, Primary IPv4 set with 'key' keyword, passing mode"""
        assert_parser_result_dict_true(
            primaries_remoteserver_set,
            '1.2.3.4 key "ABCDEFGHIJKL";',
            {'remote_server': {'ip4_addr': '1.2.3.4',
                               'key_id': 'ABCDEFGHIJKL'}}
        )

    def test_isc_primary_ipv4_set_tls_passing(self):
        """Primaries set, Primary IPv4 address set with 'tls' keyword, passing mode"""
        assert_parser_result_dict_true(
            primaries_remoteserver_set,
            '1.2.3.4 tls "ABCDEFGHIJKL";',
            {'remote_server': {'ip4_addr': '1.2.3.4',
                               'tls_id': 'ABCDEFGHIJKL'}}
        )

    def test_isc_primary_name_series_passing(self):
        """Primaries element, primary name; passing mode"""
        assert_parser_result_dict_true(
            primaries_remoteserver_element_series,
            'my-remote-server-name;',
            {
                'remote_servers': [
                    {
                        'remote_server': {'primaries_name': 'my-remote-server-name'}
                    }
                ]
            }
        )

    def test_isc_primary_name_series_2_passing(self):
        """Primaries element, primary name 2; passing mode"""
        assert_parser_result_dict_true(
            primaries_remoteserver_element_series,
            'remote-server-name; 1.2.3.4; 2e:fe::1; 2.3.4.5 key "123" tls "asdd";',
            {'remote_servers': [{'remote_server': {'primaries_name': 'remote-server-name'}},
                                {'remote_server': {'ip4_addr': '1.2.3.4'}},
                                {'remote_server': {'ip6_addr': '2e:fe::1'}},
                                {'remote_server': {'ip4_addr': '2.3.4.5',
                                                   'key_id': '123',
                                                   'tls_id': 'asdd'}}]}
        )

    def test_isc_primary_standalone_name_standalone_port_passing(self):
        """Primaries set, Primary Standalone with 'port' keyword, passing mode"""
        assert_parser_result_dict_true(
            zone_stmt_primaries_standalone,
            'primaries port 5353 { localhost; };',
            {'primaries': {'ip_port': '5353',
                           'remote_servers': [{'remote_server': {'primaries_name': 'localhost'}}]}}
        )

    def test_isc_primary_standalone_name_standalone_dscp_passing(self):
        """Primaries set, Primary Standalone with 'dscp' keyword, passing mode"""
        assert_parser_result_dict_true(
            zone_stmt_primaries_standalone,
            'primaries dscp 11 { localhost; };',
            {'primaries': {'dscp_port': 11,
                           'remote_servers': [{'remote_server': {'primaries_name': 'localhost'}}]}}
        )

    def test_isc_primary_standalone_name_standalone_port_dscp_passing(self):
        """Primaries set, Primary Standalone with 'port' & 'dscp' keywords; passing mode"""
        assert_parser_result_dict_true(
            zone_stmt_primaries_standalone,
            'primaries port 5354 dscp 11 { localhost; };',
            {'primaries': {'dscp_port': 11,
                           'ip_port': '5354',
                           'remote_servers': [{'remote_server': {'primaries_name': 'localhost'}}]}}
        )

    def test_isc_primary_standalone_name_standalone_dscp_port_passing(self):
        """Primaries set, Primary Standalone with 'port' & 'dscp' keywords reversed; passing mode"""
        assert_parser_result_dict_true(
            zone_stmt_primaries_standalone,
            'primaries dscp 11 port 5355 { localhost; };',
            {'primaries': {'dscp_port': 11,
                           'ip_port': '5355',
                           'remote_servers': [{'remote_server': {'primaries_name': 'localhost'}}]}}
        )

    def test_isc_primary_standalone_name_set_key_passing(self):
        """Primaries set, Primary Standalone set with 'key' keyword, passing mode"""
        assert_parser_result_dict_true(
            zone_stmt_primaries_standalone,
            'primaries { localhost key "ABCDEFGHIJKL"; };',
            {'primaries': {'remote_servers': [{'remote_server': {'key_id': 'ABCDEFGHIJKL',
                                                                 'primaries_name': 'localhost'}}]}}
        )

    def test_isc_primary_standalone_ipv4_set_key_passing(self):
        """Primaries set, Primary Standalone IPv4 set with 'key' keyword, passing mode"""
        assert_parser_result_dict_true(
            zone_stmt_primaries_standalone,
            'primaries { 1.2.3.4 key "ABCDEFGHIJKL"; };',
            {'primaries': {'remote_servers': [{'remote_server': {'ip4_addr': '1.2.3.4',
                                                                 'key_id': 'ABCDEFGHIJKL'}}]}}
        )

    def test_isc_primary_standalone_ipv4_set_tls_passing(self):
        """Primaries set, Primary Standalone IPv4 address set with 'tls' keyword, passing mode"""
        assert_parser_result_dict_true(
            zone_stmt_primaries_standalone,
            'primaries { 1.2.3.4 tls "ABCDEFGHIJKL"; };',
            {'primaries': {'remote_servers': [{'remote_server': {'ip4_addr': '1.2.3.4',
                                                                 'tls_id': 'ABCDEFGHIJKL'}}]}}
        )

    def test_isc_primary_standalone_name_series_passing(self):
        """Primaries element, Primary Standalone; passing mode"""
        assert_parser_result_dict_true(
            zone_stmt_primaries_standalone,
            'primaries {};',
            {'primaries': []}
        )

    def test_isc_primary_standalone_name_port_series_passing(self):
        """Primaries element, Primary Standalone; Port element; passing mode"""
        assert_parser_result_dict_true(
            zone_stmt_primaries_standalone,
            'primaries port 5353 {};',
            {'primaries': {'ip_port': '5353'}}
        )

    def test_isc_primary_name_standalone_passing(self):
        """Primaries statement, primary standalone ; passing mode"""
        assert_parser_result_dict_true(
            zone_stmt_primaries_standalone,
            'primaries port 123 dscp 11 { remote-server-name; 1.2.3.4; 2e:fe::1; 2.3.4.5 key "123" tls "asdd"; };',
            {'primaries': {'dscp_port': 11,
                           'ip_port': '123',
                           'remote_servers': [{'remote_server': {'primaries_name': 'remote-server-name'}},
                                              {'remote_server': {'ip4_addr': '1.2.3.4'}},
                                              {'remote_server': {'ip6_addr': '2e:fe::1'}},
                                              {'remote_server': {'ip4_addr': '2.3.4.5',
                                                                 'key_id': '123',
                                                                 'tls_id': 'asdd'}}]}}
        )

    def test_isc_primary_name_standalone_2elements_passing(self):
        """Primaries statement, primary standalone 2; passing mode"""
        assert_parser_result_dict_true(
            zone_stmt_primaries_standalone,
            """
    primaries port 123 dscp 11 {
        remote-server-name; 
        1.2.3.4; 
        2e:fe::1; 
        2.3.4.5 key "123" tls "asdd";
        };""",
            {'primaries': {'dscp_port': 11,
                           'ip_port': '123',
                           'remote_servers': [{'remote_server': {'primaries_name': 'remote-server-name'}},
                                              {'remote_server': {'ip4_addr': '1.2.3.4'}},
                                              {'remote_server': {'ip6_addr': '2e:fe::1'}},
                                              {'remote_server': {'ip4_addr': '2.3.4.5',
                                                                 'key_id': '123',
                                                                 'tls_id': 'asdd'}}]}}
        )


if __name__ == '__main__':
    unittest.main()
