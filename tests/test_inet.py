#!/usr/bin/env python3
"""
File: test_inet.py

Description:  Performs unit test on the isc_inet.py source file.
"""

import unittest
from bind9_parser.isc_utils import OneOrMore, \
    assert_parser_result_dict_false, assert_parser_result_dict_true
from bind9_parser.isc_inet import \
    dscp_port, \
    ip_port, \
    inet_ip_port_keyword_and_number_element, \
    inet_ip_port_keyword_and_wildcard_element, \
    ip4_addr, \
    ip4_addr_or_wildcard, \
    ip4s_subnet, \
    ip4s_prefix, \
    _ip6_device_index, \
    ip6s_subnet, \
    ip6_part, \
    ip6_full_addr, \
    ip6_addr, \
    ip6_ll_zone_index_addr, \
    ip6_0_1_addr, \
    ip6_0_7_addr, \
    ip6_0_0_addr, \
    ip6_addr_index, \
    ip6_addr_or_index, \
    ip6s_prefix, \
    ip6_addr_or_wildcard, \
    ip46_addr, \
    ip46_addr_or_prefix, \
    ip46_addr_or_wildcard, \
    ip46_addr_prefix_or_wildcard, \
    ip4_addr_list, \
    ip4s_prefix_list, \
    ip6_addr_list, \
    ip46_addr_list, \
    ip46_addr_and_port_list, \
    ip4_addr_list_series, \
    ip4s_prefix_list_series, \
    ip6_addr_list_series, \
    ip46_addr_list_series, \
    ip_addr_semicolon_series


class TestINET(unittest.TestCase):
    """ Element INET """

    def setUp(self):
        pass

    def test_isc_inet_ip_port_passing(self):
        """INET clause, IP port passing"""
        test_data = [
            '1',
            '80',
            '443',
            '8080',
            '32767',
        ]
        result = ip_port.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip_port_failing(self):
        """INET clause, IP port failing"""
        test_data = [
            '-1',
            '65537',
            #            '0',      #  TODO: Need to do range checking on IP TCP/UDP/SCTP/DDP port numbers
            '65538',
            '100000',
        ]
        result = ip_port.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_port_low_passing(self):
        """INET clause; ip_port element; lowest value; passing mode"""
        assert_parser_result_dict_true(
            ip_port,
            '1',
            {'ip_port': '1'}
        )

    def test_isc_inet_port_low_failing(self):
        """INET clause; ip_port element; lowest value; failing mode"""
        assert_parser_result_dict_false(
            ip_port,
            '0',
            {'ip_port': '0'}
        )

    def test_isc_inet_port_high_passing(self):
        """INET clause; ip_port element; highest value; passing mode"""
        assert_parser_result_dict_true(
            ip_port,
            ' 65535',
            {'ip_port': '65535'}
        )

    def test_isc_inet_port_high_failing(self):
        """INET clause; ip_port element; highest value; failing mode"""
        assert_parser_result_dict_false(
            ip_port,
            '65536',
            {'ip_port': '65536'}
        )

    def test_isc_inet_port_element_low_passing(self):
        """INET clause; port element; low; passing"""
        assert_parser_result_dict_true(
            inet_ip_port_keyword_and_number_element,
            'port 1',
            {'ip_port': '1'}
        )

    def test_isc_inet_port_element_high_passing(self):
        """INET clause; port element; high passing"""
        assert_parser_result_dict_true(
            inet_ip_port_keyword_and_number_element,
            'port 65535',
            {'ip_port': '65535'}
        )

    def test_isc_inet_port_element_low_failing(self):
        """INET clause; port element; low; failing"""
        assert_parser_result_dict_false(
            inet_ip_port_keyword_and_number_element,
            'port 0',
            {'ip_port': '0'}
        )

    def test_isc_inet_port_element_high_failing(self):
        """INET clause; port element; high failing"""
        assert_parser_result_dict_false(
            inet_ip_port_keyword_and_number_element,
            'port 65536',
            {'ip_port': '65536'}
        )

    def test_isc_inet_port_element_wildcard_passing(self):
        """INET clause; port element; wildcard; passing"""
        assert_parser_result_dict_true(
            inet_ip_port_keyword_and_wildcard_element,
            'port *',
            {'ip_port_w': '*'}
        )

    def test_isc_inet_port_element_port_wildcard_passing(self):
        """INET clause; port element; wildcard; passing"""
        assert_parser_result_dict_true(
            inet_ip_port_keyword_and_wildcard_element,
            'port 123',
            {'ip_port_w': '123'}
        )

    def test_isc_inet_port_element_wildcard_high_failing(self):
        """INET clause; port element; wildcard; failing"""
        assert_parser_result_dict_false(
            inet_ip_port_keyword_and_wildcard_element,
            'port "*"',
            {'ip_port_w': '*'}
        )

    def test_isc_inet_port_element_wildcard_high_failing(self):
        """INET clause; port element; wildcard; failing"""
        assert_parser_result_dict_false(
            inet_ip_port_keyword_and_wildcard_element,
            'port x',
            {'ip_port_w': '*'}
        )

    def test_isc_inet_ip4_subnet_passing(self):
        """INET clause, ip4_subnet passing"""
        test_data = ['0', '1', '24', '31', '32']
        result = ip4s_subnet.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip4_subnet_failing(self):
        """INET clause, ip4_subnet failing"""
        test_data = [
            '33',
            '256',
        ]
        result = ip4s_subnet.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_ip4_addr_passing(self):
        """INET clause; ip4_addr element; passing mode"""
        test_data = [
            '0.0.0.0',
            '1.0.0.0',
            '2.2.2.2',
            '9.9.9.9',
            '10.10.10.10',
            '33.33.33.33',
            '99.99.99.99',
            '100.100.100.100',
            '199.199.199.199',
            '200.200.200.200',
            '249.249.249.249',
            '250.250.250.250',
            '255.255.255.255',
        ]
        result = ip4_addr.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip4_addr_failing(self):
        """INET clause, ip4_addr element, purposely failing"""
        test_data = [
            '3.3.3.3/24',  # This is a pure IPv4 with no subnetting allowed
            '1.1,1,1',  # notice the commas?
            '1;1;1;1',
            '1:1:1:1',  # This is IPv4, not IPv6
            '257.257.257.257',  # This is not a valid IPv4
            'any',  # This is IPv4, not reserved ACL names
        ]
        result = ip4_addr.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_ip4_addr_wildcard_passing(self):
        """INET clause; ip4_addr_or_wildcard element; passing mode"""
        test_data = ['1.1.1.1', '*']
        result = ip4_addr_or_wildcard.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip4s_prefix_passing(self):
        """INET clause, ip4_subnet passing"""
        test_data = [
            '0.0.0.0/0',
            '2.2.2.2/1',
            '3.3.3.3/9',
            '9.9.3.9/10',
            '10.10.10.10/19',
            '19.19.19.19/20',
            '99.99.99.99/29',
            '199.199.199.199/30',
            '200.200.200.200/31',
            '249.249.249.249/32',
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

    # _ip6_device_index
    def test_isc_inet_ip6_device_index_passing(self):
        """INET clause, ip6_device_index passing"""
        test_data = [
            '%lo',
            '%lo0',
            '%eth0',
            '%wlan0',
            '%e0p0s3',
        ]
        result = _ip6_device_index.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip6_addr_ut_passing(self):
        """INET clause, ip6_addr unittest passing
         1::                              1:2:3:4:5:6:7::
         1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
         1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
         1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
         1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
         1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
         1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8
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
            'fe80::7:8',
            '::2:3:4:5:6:7:8',
            '::8',
            '::ffff:0:255.255.255.255',
            '::ffff:255.255.255.255',
            '2001:db8:3:4::192.0.2.33',
            '64:ff9b::192.0.2.33',
            '::255.255.255.255',
            '2001::',
            '2001:240::',
            '2001:610:240::',
            '2001:f810:610:240::'
        ]
        result = ip6_addr.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip6_addr_suffix(self):
        """INET clause, ip6_addr suffix; passing"""
        assert_parser_result_dict_true(
            ip6_addr,
            "::127.0.0.1",
            {'ip6_addr': '::127.0.0.1'}
        )

    def test_isc_inet_ip6_addr_failing(self):
        """INET clause, ip6_addr failing"""
        test_data = [
            'geee::1',
            'iii::1',
        ]
        result = ip6_addr.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

        """INET object, ip6_addr_list_series passing
        Full IPv6 (without the trailing '/') with trailing semicolon
        """
        test_data = [
            '::1;',
            '1:2::8; 2:3::7; ',  # two IP6 in a series
            '1:2::8; 2:3::7; ::1;',  # three IP6 in a series
            '1:2::8; 2:3::7; 3:4::6; ::1;',
        ]
        result = ip6_addr_list_series.runTests(test_data, failureTests=False)
        print("result: ", result)
        self.assertTrue(result[0])

# ip6s_subnet
    def test_isc_inet_ip6s_subnet_passing(self):
        """INET clause; ip6s_subnet element; passing mode"""
        test_data = ['0', '9', '10', '19', '20', '99', '100', '119', '120', '128']
        result = ip6s_subnet.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip6s_subnet_failing(self):
        """INET clause; ip6s_subnet element; failing mode"""
        test_data = ['129', '130', '139', '199', '200']
        result = ip6s_subnet.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_ip6_part_success(self):
        """INET clause; ip6_part element; success mode"""
        test_data = [
            '0', '00', '000', '0001', '1000',
            '9', '99', '999', '9998', '9999',
            'a', 'aa', 'aaa', 'AAAA', 'aAaA',
            'f', 'Ff', 'fFF', 'FfFF', 'FFFF',
        ]
        result = ip6_part.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip6_part_failing(self):
        """INET clause; ip6_part element; failing mode"""
        test_data = ['gee', 'oops', 'aaaaa', '00000', '20z']
        result = ip6_part.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_ip6_full_addr_passing(self):
        """INET clause; ip6_full_addr element; passing mode"""
        test_data = [
            '0:0:0:0:0:0:0:0',
            '9:9:9:9:9:9:9:9',
            'a:a:a:a:a:a:a:a',
            'f:f:f:f:f:f:f:f',
        ]
        result = ip6_full_addr.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip6_addr2_passing(self):
        """INET clause; ip6_addr element; passing mode"""
        test_data = [
            '::', '::8', '::2:3:4:5:6:7:8',
            '1::', '1::8', '1::7:8', '1::6:7:8', '1::5:6:7:8', '1::4:5:6:7:8', '1::3:4:5:6:7:8',
            '1:2::8', '1:2::4:5:6:7:8',
            '1:2:3::8', '1:2:3::5:6:7:8',
            '1:2:3:4::8', '1:2:3:4::6:7:8',
            '1:2:3:4:5::8', '1:2:3:4:5::7:8',
            '1:2:3:4:5:6::8', '1:2:3:4:5:6::8',
            '2001:db8:3:4::192.0.2.33', 'ff9b::192.0.2.33',  # (IPv4 - Embedded IPv6 Address)
            '::ffff:255.255.255.255',  # (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
            '::255.255.255.255',  # (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
            '2001:db8::2:192.0.2.33',  # (unknown 2-1 combo)
            '2001::13f:9:192.8.1.16',  # (unknown 1-2 combo)
            '2001::13f:192.8.1.16',   #  (unknown 1-1 combo)
            '2001::192.8.1.16',  # (unknown 1-0 combo)'
            ]
        result = ip6_addr.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip6_full_addr_failing(self):
        """INET clause; ip6_full_addr element; failing mode"""
        test_data = [
            '0:0:0:0:0.0:0:0',     # missed that comma, did ya?
            '9:9:9:9:9:9:9:9:9',   # one too many tuple item
            'a:a:a:a:a:a:a',       # short one tuple
            'f:f:f:f:f:fff0f:f:f',  # one tuple is too long
        ]
        result = ip6_full_addr.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_ip6_addr_index_passing(self):
        """INET clause; ip6_addr_index element; passing mode"""
        test_data = [
            'fe80::1%ne0',
            'fe80::1ff:fe23:4567:890a%eth2',  # Nearly all *nixes
            'fe80::1ff:fe23:4567:890a%3',  # Microsoft Windows
            ### 'fe80:3::1ff:fe23:4567:890a',  # BSD and macOS
            'A:a:a:a:a:a:a:a%wlan0',
            'f:f:f:f:f:f:f:f%vps1',
            'f:f:f:f:f:f:f:f%wirelan0',
            'f:f:f:f:f:f:f:f%e0p1s3',
        ]
        result = ip6_addr_index.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip6_addr_index_failing(self):
        """INET clause; ip6_addr_index element; failing mode"""
        test_data = [
            'fe80::1?ne0',  # only accepts '%'  TODO: Consider an extra ':' for BSD/macOS?
            'fe80::1ff:fe23:4567:890a%___2',  # Invalid device name
            'fe80::1ff:fe23:4567:890a%-1',  # Microsoft Windows
            ### 'fe80:3::1ff:fe23:4567:890a',  # BSD and macOS
        ]
        result = ip6_addr_index.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_inet_ip6_addr_or_index_passing(self):
        """INET clause; ip6_addr_or_index element; passing mode"""
        test_data = [
            '::127.0.0.1',
            '::192.168.1.1',
            'fe80::1ff:fe23:4567:890a',
            'fe80::1%ne0',
            'fe80::1ff:fe23:4567:890a%eth2',  # Nearly all *nixes
            'fe80::1ff:fe23:4567:890a%3',  # Microsoft Windows
            ### 'fe80:3::1ff:fe23:4567:890a',  # BSD and macOS
            'A:a:a:a:a:a:a:a%wlan0',
            'f:f:f:f:f:f:f:f%vps1',
            'f:f:f:f:f:f:f:f%wirelan0',
            'f:f:f:f:f:f:f:f%e0p1s3',
        ]
        result = ip6_addr_or_index.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip6s_prefix_ut_passing(self):
        """INET clause; ip6s_prefix element; unittest passing mode"""
        test_data = [
            '::127.0.0.1/16',
            '::192.168.1.1/24',
            'fe80::1ff:fe23:4567:890a/128',
            'fe80::1/124',
            'fe80::1ff:fe23:4567:890a/96',
            'fe80::1ff:fe23:4567:890a/48',
        ]
        result = ip6s_prefix.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip6s_prefix_passing(self):
        """INET clause; ip6s_prefix element; passing mode"""
        assert_parser_result_dict_true(
            ip6s_prefix,
            """::127.0.0.1/16"""
# ::192.168.1.1/24
# fe80::1ff:fe23:4567:890a/128
# fe80::1/124
# fe80::1ff:fe23:4567:890a/96
# fe80::1ff:fe23:4567:890a/48
# """,
            ,
            {'ip6_addr': '::127.0.0.1', 'ip6s_subnet': '16'}
        )

    def test_isc_inet_ip6_addr_or_wildcard_passing(self):
        """INET clause; ip6_addr_or_wildcard element; passing mode"""
        test_data = [
            '::127.0.0.1',
            '*',
            '::192.168.1.1',
            'fe80::1ff:fe23:4567:890a',
            'fe80::1',
        ]
        result = ip6_addr_or_wildcard.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_inet_ip46_addr2_passing(self):
        """INET clause; ip46_addr element; passing mode"""
        test_data = [
            '127.0.0.1',
            '::127.0.0.1',
            '::192.168.1.1',
            '192.168.1.1',
            'fe80::1ff:fe23:4567:890a',
            'fe80::1',
        ]
        result = ip46_addr.runTests(test_data, failureTests=False)
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

    def test_isc_inet_ip6_addr_list_series_failing(self):
        """
        INET object, ip6_addr_list_series failing
        Full IPv6 (without the trailing '/') with trailing semicolon
        """
        test_data = [
            '1:2::',  # missing semicolon
            '1:2:;',  # missing colon
            '1:::;',  # too many colons
            '1:2::; 2:3::7; ::1;',  # missing ending digit in 1st item of series
            '1:2::8, 2:3::7; ::1;',  # comma used instead of semicolon
            '1:2::8; 2:3::; ::1;',  # missing ending digit in 2nd item of series
            '1:2::; 2:3::7; :7:1;',  # missing double colon in 3rd item of series
        ]
        result = ip6_addr_list_series.runTests(test_data, failureTests=False)
        self.assertFalse(result[0])

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

    def test_isc_inet_ip46_addr_and_port_list_passing(self):
        """INET clause, IPv4 and port; one IPv4; passing"""
        assert_parser_result_dict_true(
            ip46_addr_and_port_list,
            '1.1.1.1;',
            {'ip_addr': '1.1.1.1'}
        )
    def test_isc_inet_ip46_addr_and_port_list_1_ip4_port_passing(self):
        """INET clause, IPv4 and port; one IPv4 with port; passing"""
        assert_parser_result_dict_true(
            ip46_addr_and_port_list,
            '2.2.2.2 port 2222;',
            {'ip_addr': '2.2.2.2', 'ip_port': '2222'}
        )

    def test_isc_inet_ip4_addr_semicolon_failing(self):
        """INET clause, IPv4 address with semicolon; failing"""
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
