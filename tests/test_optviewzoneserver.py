#!/usr/bin/env python3
"""
File: test_optviewzoneserver.py

Description:  Performs unit test on the isc_optviewzoneserver.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue
from bind9_parser.isc_optviewzoneserver import \
    optviewzoneserver_stmt_also_notify, \
    optviewzoneserver_statements_set, \
    optviewzoneserver_statements_series


class TestOptionsViewZoneServer(unittest.TestCase):
    """ Clause Options/View/Zone/Server; only under 'options', 'view', 'zone', and 'server' clause """

    def test_isc_optviewzoneserver_stmt_also_notify_passing(self):
        """ Clause options/view/zone/server; Statement also-notify; passing """
        test_string = [
            'also-notify { masters; };',
            'also-notify { masters key lockbox0_key; };',
            'also-notify { masters port 54; };',
            'also-notify { masters port 54 key lockbox1_key; };',
            'also-notify { masters port 55 dscp 3; };',
            'also-notify { masters port 55 dscp 3 key lockbox2_key; };',
            'also-notify { masters dscp 3; };',
            'also-notify { masters dscp 3 key lockbox3_key; };',
            'also-notify { 1.1.1.1; };',
            'also-notify { 1.1.1.1 key lockbox4_key; };',
            'also-notify { 1.1.1.1 port 57; };',
            'also-notify { 1.1.1.1 port 57 key lockbox5_key; };',
            'also-notify { 1.1.1.1 port 58 dscp 4; };',
            'also-notify { 1.1.1.1 port 58 dscp 4 key lockbox6_key; };',
            'also-notify { 1.1.1.1 dscp 5; };',
            'also-notify { 1.1.1.1 dscp 5 key lockbox7_key; };',
            'also-notify { fe01::1; };',
            'also-notify { fe01::1 key lockbox8_key; };',
            'also-notify { fe01::1 port 59; };',
            'also-notify { fe01::1 port 59 key lockbox9_key; };',
            'also-notify { fe01::1 port 59 dscp 6; };',
            'also-notify { fe01::1 port 59 dscp 6 key lockbox10_key; };',
            'also-notify { fe01::1 dscp 6; };',
            'also-notify { fe01::1 dscp 6 key lockbox11_key; };',
        ]
        result = optviewzoneserver_stmt_also_notify.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzoneserver_stmt_also_notify_2_passing(self):
        """ Clause options/view/zone/server; Statement also-notify 2; passing """
        assertParserResultDictTrue(
            optviewzoneserver_stmt_also_notify,
            'also-notify { 1.1.1.1 port 58 dscp 4 key lockbox6_key; fe01::1 dscp 6 key lockbox11_key; };',
            {'also_notify': [{'addr': '1.1.1.1',
                              'dscp_port': 4,
                              'ip_port': '58',
                              'key_id': 'lockbox6_key'},
                             {'addr': 'fe01::1',
                              'dscp_port': 6,
                              'key_id': 'lockbox11_key'}]}
        )

    def test_isc_optviewzoneserver_statements_set_passing(self):
        """ Clause optviewzoneserver; Statement statements_set; passing """
        test_string = [
            'also-notify { masters; };',
            'also-notify { masters key lockbox0_key; };',
            'also-notify { masters port 54; };',
            'also-notify { masters port 54 key lockbox1_key; };',
            'also-notify { masters port 55 dscp 3; };',
            'also-notify { masters port 55 dscp 3 key lockbox2_key; };',
            'also-notify { masters dscp 3; };',
            'also-notify { masters dscp 3 key lockbox3_key; };',
            'also-notify { 1.1.1.1; };',
            'also-notify { 1.1.1.1 key lockbox4_key; };',
            'also-notify { 1.1.1.1 port 57; };',
            'also-notify { 1.1.1.1 port 57 key lockbox5_key; };',
            'also-notify { 1.1.1.1 port 58 dscp 4; };',
            'also-notify { 1.1.1.1 port 58 dscp 4 key lockbox6_key; };',
            'also-notify { 1.1.1.1 dscp 5; };',
            'also-notify { 1.1.1.1 dscp 5 key lockbox7_key; };',
            'also-notify { fe01::1; };',
            'also-notify { fe01::1 key lockbox8_key; };',
            'also-notify { fe01::1 port 59; };',
            'also-notify { fe01::1 port 59 key lockbox9_key; };',
            'also-notify { fe01::1 port 59 dscp 6; };',
            'also-notify { fe01::1 port 59 dscp 6 key lockbox10_key; };',
            'also-notify { fe01::1 dscp 6; };',
            'also-notify { fe01::1 dscp 6 key lockbox11_key; };',
            'also-notify { 1.1.1.1 port 58 dscp 4 key lockbox6_key; fe01::1 dscp 6 key lockbox11_key; };',
            'also-notify { masters; };',
            'also-notify { masters key DDNS_UPDATER; };',
            'also-notify { 1.1.1.1; };',
            'also-notify { 11.11.11.11 port 11; };',
            'also-notify { 11.11.11.11 key MY_UPDATER; };',
            'also-notify { 11.11.11.11 port 11 key MY_UPDATER; };',
            'also-notify { fe01::1; };',
            'also-notify { fe01::1 key YOUR_UPDATER; };',
            'also-notify { fe01::1 port 12; };',
            'also-notify { fe01::1 port 12 key YOUR_UPDATER; };',
        ]
        result = optviewzoneserver_statements_set.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzoneserver_statements_set_2_passing(self):
        """ Clause optviewzoneserver; Statement statements_set 2; passing """
        assertParserResultDictTrue(
            optviewzoneserver_statements_set,
            'also-notify { 1.1.1.1 port 58 dscp 4 key lockbox6_key; };',
            {'also_notify': [{'addr': '1.1.1.1',
                              'dscp_port': 4,
                              'ip_port': '58',
                              'key_id': 'lockbox6_key'}]}
        )

    def test_isc_optviewzoneserver_stmt_statements_set_failing(self):
        """ Clause optviewzoneserver; Statement statements_set; failing """
        test_string = [
            'statements_set "YYYY";',
        ]
        result = optviewzoneserver_statements_set.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


    def test_isc_optviewzoneserver_statements_series_passing(self):
        """ Clause optviewzoneserver; Statement optviewzoneserver_statements_series; passing """

        # Only one also-notify allowed per clause section (be that it may, options, view, zone, or server).
        assertParserResultDictTrue(
            optviewzoneserver_statements_series,
            'also-notify { 1.1.1.1 port 58 dscp 4 key lockbox6_key; };' +
            'also-notify { 2.2.2.2 port 52 dscp 2 key lockbox16_key; };',
            {'also_notify': [{'addr': '2.2.2.2',
                              'dscp_port': 2,
                              'ip_port': '52',
                              'key_id': 'lockbox16_key'}]}
        )

    def test_isc_optviewzoneserver_stmt_statements_series_failing(self):
        """ Clause optviewzoneserver; Statement statements_series; failing """
        test_string = [
            'statements_series "YYYY";',
        ]
        result = optviewzoneserver_statements_series.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()
