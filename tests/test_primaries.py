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
            {'ip4_addr': '1.2.3.4'}
        )

    def test_isc_primary_name_set_key_passing(self):
        """Primaries set, Primary Name set with 'key' keyword, passing mode"""
        assert_parser_result_dict_true(
            primaries_remoteserver_set,
            'a.b.example.tld key "ABCDEFGHIJKL";',
            {
                'key_id': 'ABCDEFGHIJKL',
                'primaries_name': 'a.b.example.tld',
            }
        )

    def test_isc_primary_ipv4_set_key_passing(self):
        """Primaries set, Primary IPv4 set with 'key' keyword, passing mode"""
        assert_parser_result_dict_true(
            primaries_remoteserver_set,
            '1.2.3.4 key "ABCDEFGHIJKL";',
            {'ip4_addr': '1.2.3.4', 'key_id': 'ABCDEFGHIJKL'}
        )

    def test_isc_primary_ipv4_set_tls_passing(self):
        """Primaries set, Primary IPv4 address set with 'tls' keyword, passing mode"""
        assert_parser_result_dict_true(
            primaries_remoteserver_set,
            '1.2.3.4 tls "ABCDEFGHIJKL";',
            {'ip4_addr': '1.2.3.4', 'tls_id': 'ABCDEFGHIJKL'}
        )

    def test_isc_primary_name_series_passing(self):
        """Primaries element, primary name; passing mode"""
        assert_parser_result_dict_true(
            primaries_remoteserver_element_series,
            'remote-server-name;',
            {'primaries_list': [{'primaries_name': 'remote-server-name'}]}
        )

    def test_isc_primary_name_series_2_passing(self):
        """Primaries element, primary name 2; passing mode"""
        assert_parser_result_dict_true(
            primaries_remoteserver_element_series,
            'remote-server-name; 1.2.3.4; 2e:fe::1; 2.3.4.5 key "123" tls "asdd";',
            {
                'primaries_list': [
                    {'primaries_name': 'remote-server-name'},
                    {'ip4_addr': '1.2.3.4'},
                    {'ip6_addr': '2e:fe::1'},
                    {'ip4_addr': '2.3.4.5',
                     'key_id': '123',
                     'tls_id': 'asdd'}
                ]
            }
        )

    def test_isc_primary_name_standalone_passing(self):
        """Primaries statement, primary name 2; passing mode"""
        assert_parser_result_dict_true(
            zone_stmt_primaries_standalone,
            'primaries port 123 dscp 11 { remote-server-name; 1.2.3.4; 2e:fe::1; 2.3.4.5 key "123" tls "asdd"; };',
            {
                'dscp_port': 11,
                'ip_port': '123',
                'primaries_list': [
                    {'primaries_name': 'remote-server-name'},
                    {'ip4_addr': '1.2.3.4'},
                    {'ip6_addr': '2e:fe::1'},
                    {'ip4_addr': '2.3.4.5', 'key_id': '123', 'tls_id': 'asdd'}
                ]
            }
        )
if __name__ == '__main__':
    unittest.main()
