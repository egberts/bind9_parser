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
        """ Clause primaries; Element Servers by name; passing mode """
        assert_parser_result_dict_true(
            primaries_remoteserver_element,
            'primary-remote-server',
            {'primaries_name': 'primary-remote-server'}
        )

    def test_isc_primaries_remoteserver_ip4addr_passing(self):
        """ Clause primaries; Element Servers by IPv4 address; passing mode """
        assert_parser_result_dict_true(
            primaries_remoteserver_element,
            '127.0.0.1',
            {'ip4_addr': '127.0.0.1'}
        )

    def test_isc_primaries_remoteserver_ip4addr_port_passing(self):
        """ Clause primaries; Element Servers by IPv4 address and port number; passing mode """
        assert_parser_result_dict_true(
            primaries_remoteserver_element,
            '127.0.0.1 port 123',
            {'ip4_addr': '127.0.0.1', 'ip_port': '123'}
        )

    def test_isc_primaries_remoteserver_ip4addr_port_failing(self):
        """ Clause primaries; Element Servers by IPv4 address and port number; failing mode """
        assert_parser_result_dict_false(
            primaries_remoteserver_element,
            'port 123',
            {'ip_port': '123'}
        )

    def test_isc_primaries_remoteserver_ip6addr_passing(self):
        """ Clause primaries; Element Servers by IPv6 address; passing mode """
        assert_parser_result_dict_true(
            primaries_remoteserver_element,
            'fe:2c::1',
            {'ip6_addr': 'fe:2c::1'}
        )

    def test_isc_primaries_remoteserver_ip6addr_port_passing(self):
        """ Clause primaries; Element Servers by IPv6 address and port number; passing mode """
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
        """Primaries clause, Primary Name set, passing mode"""
        assert_parser_result_dict_true(
            primaries_remoteserver_set,
            '1.2.3.4;',
            {'ip4_addr': '1.2.3.4'}
        )

    def test_isc_primary_name_set_key_passing(self):
        """Primaries clause, Primary Name set with 'key' keyword, passing mode"""
        assert_parser_result_dict_true(
            primaries_remoteserver_set,
            '1.2.3.4 key "ABCDEFGHIJKL";',
            {'ip4_addr': '1.2.3.4', 'key_id': 'ABCDEFGHIJKL'}
        )

    def test_isc_primary_name_set_tls_passing(self):
        """Primaries clause, Primary Name set with 'tls' keyword, passing mode"""
        assert_parser_result_dict_true(
            primaries_remoteserver_set,
            '1.2.3.4 tls "ABCDEFGHIJKL";',
            {'ip4_addr': '1.2.3.4', 'tls_id': 'ABCDEFGHIJKL'}
        )


if __name__ == '__main__':
    unittest.main()
