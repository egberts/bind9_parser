#!/usr/bin/env python3
"""
File: test_optviewserver.py

Description:  Performs unit test on the isc_optviewserver.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue
from bind9_parser.isc_optviewserver import \
    optviewserver_stmt_edns_udp_size,\
    optviewserver_stmt_provide_ixfr,\
    optviewserver_stmt_query_source,\
    optviewserver_stmt_query_source_v6, \
    optviewserver_stmt_request_ixfr,\
    optviewserver_stmt_send_cookie,\
    optviewserver_stmt_transfer_format,\
    optviewserver_statements_series


class TestOptionsViewServer(unittest.TestCase):
    """ Clause Options/View/Server; things found only under 'options', 'view', and 'server' clause """

    def test_isc_server_stmt_edns_udp_size_passing(self):
        """ Clause server; Statement edns_udp_size; passing mode """
        test_string = [
            'edns-udp-size 0;',
            'edns-udp-size 1;',
            'edns-udp-size 102;',
            'edns-udp-size 255;',
        ]
        result = optviewserver_stmt_edns_udp_size.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_server_stmt_edns_udp_size_dict_passing(self):
        assertParserResultDictTrue(optviewserver_stmt_edns_udp_size, 'edns-udp-size 255;', {'edns_udp_size': 255})

    def test_isc_server_stmt_edns_udp_size_failing(self):
        """ Clause server; Statement edns_udp_size; failing mode """
        test_string = [
            'edns-udp-size yes;',
            'edns-udp-size -3;',
        ]
        result = optviewserver_stmt_edns_udp_size.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_optviewserver_stmt_provide_ixfr_passing(self):
        """ Clause Options/View/Server; Statement provide-ixfr; passing mode """
        test_string = [
            'provide-ixfr yes;',
            'provide-ixfr 1;',
            'provide-ixfr 0;',
            'provide-ixfr no;',
            'provide-ixfr True;',
            'provide-ixfr False;',
        ]
        result = optviewserver_stmt_provide_ixfr.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewserver_stmt_provide_ixfr_dict_passing(self):
        assertParserResultDictTrue(
            optviewserver_stmt_provide_ixfr,
            'provide-ixfr yes;',
            {'provide_ixfr': 'yes'}
        )

    def test_isc_optviewserver_stmt_provide_ixfr_failing(self):
        """ Clause Options/View/Server; Statement provide-ixfr; failing mode """
        test_string = [
            'provide-ixfr Y'
        ]
        result = optviewserver_stmt_provide_ixfr.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_optviewserver_stmt_query_source_ut_passing(self):
        """ Clause Options/View/Server; Statement 'query-source' unittest; passing mode """
        test_string = [
            'query-source port *;',
            'query-source port * dscp 1;',
            'query-source * port *;',
            'query-source * dscp 1;',
            'query-source * port * dscp 1;',
            'query-source 127.0.0.1 port *;',
            'query-source 127.0.0.1 dscp 1;',
            'query-source 127.0.0.1 port * dscp 1;',
            'query-source address 127.0.0.1;',
            'query-source address 127.0.0.1 port *;',
            'query-source address 127.0.0.1 dscp 1;',
            'query-source address 127.0.0.1 port * dscp 1;',
            'query-source address *;',
            'query-source address * port *;',
            'query-source address * dscp 1;',
            'query-source address * port * dscp 1;',
        ]
        result = optviewserver_stmt_query_source.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewserver_stmt_query_source_passing(self):
        """ Clause Options/View/Server; Statement 'query-source' unittest; passing mode """
        assertParserResultDictTrue(
            optviewserver_stmt_query_source,
            'query-source address 172.16.0.0 port 443 dscp 15;',
            {'query_source': {'dscp_port': 15,
                              'ip4_addr_w': '172.16.0.0',
                              'ip_port_w': '443'}}
        )

    def test_isc_optviewserver_stmt_query_source_v6_ut_passing(self):
        """ Clause Options/View/Server; Statement 'query-source-v6' unittest; passing mode """
        test_string = [
            'query-source-v6 port *;',
            'query-source-v6 port * dscp 1;',
            'query-source-v6 * port *;',
            'query-source-v6 * dscp 1;',
            'query-source-v6 * port * dscp 1;',
            'query-source-v6 fec2::1 port *;',
            'query-source-v6 fec2::1 dscp 1;',
            'query-source-v6 fec2::1 port * dscp 1;',
            'query-source-v6 address fec2::1;',
            'query-source-v6 address fec2::1 port *;',
            'query-source-v6 address fec2::1 dscp 1;',
            'query-source-v6 address fec2::1 port * dscp 1;',
            'query-source-v6 address *;',
            'query-source-v6 address * port *;',
            'query-source-v6 address * dscp 1;',
            'query-source-v6 address * port * dscp 1;',
        ]
        result = optviewserver_stmt_query_source_v6.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewserver_stmt_query_source_v6_passing(self):
        """ Clause Options/View/Server; Statement 'query-source-v6' unittest; passing mode """
        assertParserResultDictTrue(
            optviewserver_stmt_query_source_v6,
            'query-source-v6 address fec2::1 port 443 dscp 15;',
            {'query_source_v6': {'dscp_port': 15,
                                 'ip6_addr_w': 'fec2::1',
                                 'ip_port_w': '443'}}
        )

    def test_isc_server_stmt_request_ixfr_passing(self):
        """ Clause server; Statement request-ixfr; passing mode """
        test_string = [
            'request-ixfr yes;',
            'request-ixfr 1;',
            'request-ixfr 0;',
            'request-ixfr no;',
            'request-ixfr True;',
            'request-ixfr False;',
        ]
        result = optviewserver_stmt_request_ixfr.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_server_stmt_request_ixfr_dict_passing(self):
        assertParserResultDictTrue(
            optviewserver_stmt_request_ixfr,
            'request-ixfr True;',
            {'request_ixfr': 'True'}
        )

    def test_isc_server_stmt_send_cookie_passing(self):
        assertParserResultDictTrue(
            optviewserver_stmt_send_cookie,
            'send-cookie yes;',
            {'send_cookie': 'yes'}
        )

    def test_isc_server_stmt_request_ixfr_failing(self):
        """ Clause server; Statement request-ixfr; failing mode """
        test_string = [
            'request-ixfr Y;'
        ]
        result = optviewserver_stmt_request_ixfr.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_optviewserver_stmt_transfer_format_passing(self):
        """ Clause Options/View/Server; Statement transfer-format; passing mode """
        test_string = [
            'transfer-format one-answer;',
            'transfer-format many-answers;',
        ]
        result = optviewserver_stmt_transfer_format.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewserver_stmt_transfer_format,
            'transfer-format one-answer;',
            {'transfer_format': 'one-answer'}
        )

    def test_isc_optviewserver_stmt_transfer_format_failing(self):
        """ Clause Options/View/Server; Statement transfer-format; failing mode """
        test_string = [
            'transfer-format no-answer;',
            'transfer-format !one-answer;',
            'transfer-format many-answer;',
        ]
        result = optviewserver_stmt_transfer_format.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_optviewserver_statements_series_passing(self):
        """ Clause optviewserver; Statement optviewserver_statements_series; passing """
        assertParserResultDictTrue(
            optviewserver_statements_series,
            'provide-ixfr yes;' +
            'request-ixfr yes;' +
            'transfer-format one-answer;',
            {'provide_ixfr': 'yes',
             'request_ixfr': 'yes',
             'transfer_format': 'one-answer'}
        )

    def test_isc_optviewserver_stmt_statements_series_failing(self):
        """ Clause optviewserver; Statement statements_series; failing """
        test_string = [
            'statements_series "YYYY";',
        ]
        result = optviewserver_statements_series.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()
