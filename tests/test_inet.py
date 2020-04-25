#!/usr/bin/env python3
"""
File: test_inet.py

Description:  Performs unit test on the isc_inet.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictFalse, assertParserResultDictTrue
from bind9_parser.isc_inet import \
    ip4_addr, \
    ip4_addr_list, \
    ip4_addr_list_series, \
    ip4s_prefix, \
    ip4s_prefix_list_series, \
    ip6_addr, \
    ip6_addr_list_series, \
    ip46_addr, \
    ip46_addr_or_prefix, \
    ip46_addr_and_port_list, \
    ip46_addr_or_wildcard, \
    ip46_addr_prefix_or_wildcard, \
    ip46_addr_list_series, \
    ip_addr_semicolon_series, \
    ip4s_subnet, \
    ip_port, dscp_port

class TestINET(unittest.TestCase):
    """ Element INET """

    def setUp(self):
        pass

    def test_isc_inet_ip4_addr_passing(self):
        """INET clause, ip4_addr element, passing mode"""
        test_data = [
            '1.1.1.1',
            '2.2.2.2',
        ]
        result = ip4_addr.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip4_addr_failing(self):
        """INET clause, ip4_addr element, purposely failing"""
        test_data = [
            '3.3.3.3/24',  # This is a pure IPv4 with no subnetting allowed
            '1,1,1,1',  # notice the commas?
            '1;1;1;1',
            '1:1:1:1',  # This is IPv4, not IPv6
            '257.257.257.257',  # This is not a valid IPv4
            'any',  # This is IPv4, not reserved ACL names
        ]
        result = ip4_addr.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_ip4_subnet_passing(self):
        """INET clause, ip4_subnet passing"""
        test_data = [
            '1',
            '24',
            '31',
            '32',
        ]
        result = ip4s_subnet.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip4_subnet_failing(self):
        """INET clause, ip4_subnet failing"""
        test_data = [
#            '0',    # TODO: Do we really want to restrict this field to <1-31>?
#            '33',
#            '32',
            '256',
        ]
        result = ip4s_subnet.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_ip4s_prefix_passing(self):
        """INET clause, ip4_subnet passing"""
        test_data = [
            '2.2.2.2/24',
            '3.3.3.3/2',
        ]
        result = ip4s_prefix.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip4s_prefix_failing(self):
        """INET clause, ip4_subnet failing"""
        test_data = [
            '1.1.1.1',   # ip4s_prefix is strictly IPv4 with required subnetting
            '0/-',
            '257.257.257.257/24',
        ]
        result = ip4s_prefix.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_ip4s_prefix_list_series_passing(self):
        """INET object, ip4s_prefix_list_series passing"""
        test_data = [
            '123.123.123.123/3;',
            '234.234.234.234/4;',
            '45.45.45.45/5; 56.56.56.56/6;',
            '67.67.67.67/7; 78.78.78.78/8;  89.89.89.89/9;'
        ]
        result = ip4s_prefix_list_series.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip4s_prefix_list_series_failing(self):
        """INET object, ip4s_prefix_list_series failing"""
        test_data = [
            '123.123.123.123/113;',
            '234.234.234.234/23234;',
            '45.45.45/5; 56.56/6;',
            '67.67.67.67/-1; 78.78.78.78=8;  89.89.89.89+9;'
        ]
        result = ip4s_prefix_list_series.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_ip6_addr_passing(self):
        """INET clause, ip6_addr passing
         1::                              1:2:3:4:5:6:7::
         1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
         1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
         1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
         1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
         1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
         1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8
         fe80::7:8%eth0   (link-local IPv6 addresses with zone index)
         fe80::7:8%1     (link-local IPv6 addresses with zone index)
         ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::
         ::ffff:0:255.255.255.255 (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
         ::ffff:255.255.255.255 (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
         2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
         ::255.255.255.255 (IPv4-mapped IPv6 addresses and IPv4-translated addresses)

        """
        test_data = [
            'fe01::1',
            '1::1',
            '1::',
            '1:2:3:4:5:6:7::',
            '1::8',
            '1:2:3:4:5:6::8',
            '1::7:8',
            '1:2:3:4:5::7:8',
            '1:2:3:4:5::8',
            '1::6:7:8',
            '1:2:3:4::6:7:8',
            '1:2:3:4::8',
            '1::5:6:7:8',
            '1:2:3::5:6:7:8',
            '1:2:3::8',
            '1::4:5:6:7:8',
            '1:2::4:5:6:7:8',
            '1:2::8',
            '1::3:4:5:6:7:8',
            '1::8',
            'fe80::7:8%eth0',
            'fe80::7:8%1',
            '::2:3:4:5:6:7:8',
            '::8',
            '::ffff:0:255.255.255.255',
            '::ffff:255.255.255.255',
            '2001:db8:3:4::192.0.2.33',
            '64:ff9b::192.0.2.33',
            '::255.255.255.255'
        ]
        result = ip6_addr.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip6_addr_failing(self):
        """INET clause, ip6_addr failing"""
        test_data = [
            'geee::1',
            'iii::1',
        ]
        result = ip6_addr.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])
        
    def test_isc_inet_ip6_addr_list_series(self):
        """INET object, ip6_addr_list_series passing
        Full IPv6 (without the trailing '/') with trailing semicolon

        """
        test_data = [
            '2001:610:210::;',
            '2001:67c:2e8::;',
        ]
        result = ip6_addr_list_series.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip46_addr_passing(self):
        """INET clause, ip46_addr passing"""
        test_data = [
            'fe01::1',
            '1::1',
        ]
        result = ip46_addr.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip46_addr_failing(self):
        """INET clause, ip46_addr failing"""
        test_data = [
            'geee::1',
            'iii::1',
        ]
        result = ip46_addr.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_ip46_addr_or_prefix_passing(self):
        """INET clause, ip46_addr_or_prefix passing"""
        test_data = [
            '1::1',
            '127.0.0.1',
            '127.0.0.0/8',
            'ffe2::1',
        ]
        result = ip46_addr_or_prefix.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip46_addr_or_prefix_failing(self):
        """INET clause, ip46_addr_or_prefix failing"""
        test_data = [
            'geee::1',
            'iii::1',
        ]
        result = ip46_addr_or_prefix.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_ip_port_passing(self):
        """INET clause, IP port passing"""
        test_data = [
            '1',
            '80',
            '443',
            '8080',
            '32767',
            '65537',
        ]
        result = ip_port.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip_port_failing(self):
        """INET clause, IP port failing"""
        test_data = [
            '-1',
#            '0',      #  TODO: Need to do range checking on IP TCP/UDP/SCTP/DDP port numbers
#            '65538',
#            '100000',
        ]
        result = ip_port.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_dscp_port_passing(self):
        """INET clause, DSCP port passing"""
        test_data = [
            '1',
            '80',
            '443',
            '8080',
            '32767',
            '65537',
        ]
        result = dscp_port.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_dscp_port_failing(self):
        """INET clause, DSCP port failing"""
        test_data = [
            '-1',
#            '0',      #  TODO: Need to do range checking on IP TCP/UDP/SCTP/DDP port numbers
#            '65538',
#            '100000',
        ]
        result = dscp_port.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_ip46_addr_port_passing(self):
        """ Clause INET; IPv4/6 address with 'port' keyword+number; passing """
        test_data = [
            '1.1.1.1 port 1111;',
            'fe::2 port 2222;',
            ]
        result = ip46_addr_and_port_list.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            ip46_addr_and_port_list,
            '1.1.1.1 port 1111;',
            {'addr': '1.1.1.1', 'ip_port': 1111}
        )

    def test_isc_inet_ip46_addr_or_wildcard_passing(self):
        """INET clause, IPv4/6 address with optional wildcard optionpassing"""
        test_data = [
            '22.22.22.22',
            'ffe1::1',
            "*",
            '*',
            "'*'",
            '"*"',
        ]
        result = ip46_addr_or_wildcard.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip46_addr_or_wildcard_failing(self):
        """INET clause, IPv4/6 address with optional wildcard failing"""
        test_data = [
            '1.1.1.1;',
            '*3.3.3.3',
            '**',
            '\'*',  # lone single-quote not allowed
            "*'",  # lone single-quote not allowed
            '*\"',  # lone double-quote not allowed
            '"*',  # lone double-quote not allowed
            '&',
        ]
        result = ip46_addr_or_wildcard.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_ip4_addr_semicolon_passing(self):
        """INET clause, IPv4 address with semicolon passing"""
        test_data = [
            " 22.22.22.22;",
            "23.23.23.23 ;",
            "24.24.24.24; ",
            " 25.25.25.25;",
            " 26.26.26.26 ;",
            " 27.27.27.27; ",
            " 28.28.28.28 ; ",
            "\t29.29.29.29;",
            "30.30.30.30\t;",
            "31.31.31.31;",
            "32.32.32.32;\t",
            "\t33.33.33.33\t;",
            "\t34.34.34.34;\t",
            "\t35.35.35.35\t;\t",
        ]
        result = ip4_addr_list.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip4_addr_semicolon_failing(self):
        """INET clause, IPv4 address with semicolon failing"""
        test_data = [
            '-1',
#            '65538',
#            '100000',
        ]
        result = ip4_addr_list.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_ip4_addr_semicolon_series_passing(self):
        """INET clause, a series of IPv4 address with semicolon passing"""
        test_data = [
            '1.1.1.1;',
            '2.2.2.2; 3.3.3.3;',
            '4.4.4.4; 5.5.5.5; 6.6.6.6;',
            '36.36.36.36; 37.37.37.37; 38.38.38.38;\t',
        ]
        result = ip4_addr_list_series.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip4_addr_semicolon_series_failing(self):
        """INET clause, a series of IPv4 address with semicolon failing"""
        test_data = [
            'fe0b::1;',  # supports IPv4 only
            'any;',      # No reserved ACL word allowed
            'none;',      # No reserved ACL word allowed
            '127.0.0,1;\t',  # comma used instead of a period
            "36.36.36.36; 37.37.37.37 38.38.38.38;\t",  # missing semicolon
            "36.36.36.36: 37.37.37.37; 38.38.38.38;\t"  # colon used, instead of semicolon
        ]
        result = ip4_addr_list_series.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()
