#!/usr/bin/env python3
"""
File: test_server.py

Description:  Performs unit test on the isc_server.py source file.
"""
import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue, assertParserResultDictFalse
from bind9_parser.isc_clause_server import server_all_statements_set, \
    server_all_statements_series,\
    clause_stmt_server_standalone,clause_stmt_server_series


class TestClauseServer(unittest.TestCase):
    """ Clause server """

    # TODO: Exercise server_all_statements_set, server_all_statements_series

    def test_isc_server_all_statements_set_passing(self):
        """ Clause server; Set Statements; passing mode """
        test_data = [
            'bogus yes;',
            'edns no;',
            'edns-udp-size 102;',
            'edns-version 2;',
            'keys my_key_name_to_private_dns;',
            'max-udp-size 32768;',
            'notify-source *;',
            'notify-source-v6 *;',
            'padding 53;',
            'provide-ixfr yes;',
            'query-source *;',
            'query-source address *;',
            'query-source-v6 *;',
            'request-expire yes;',
            'request-ixfr yes;',
            'request-nsid yes;',
            'send-cookie yes;',
            'tcp-keepalive yes;',
            'tcp-only yes;',
            'transfer-format one-answer;',
            'transfer-source *;',
            'transfer-source-v6 *;',
            'transfers 36;',
        ]
        result = server_all_statements_set.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_server_all_statements_set_failing(self):
        """ Clause server; Set Statements; failing mode """
        test_data = [
            'edns no',
            'edns-udp-size -1;',
            'edns-udp-size -1024;',
        ]
        result = server_all_statements_set.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_all_statements_series_passing(self):
        """ Clause server; Series Statements; passing mode """
        test_data = [
            'bogus yes; edns yes;',
            'edns no; bogus no;',
        ]
        result = server_all_statements_series.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_server_all_statements_series_failing(self):
        """ Clause server; Series Statements; failing mode """
        test_data = [
            'edns no bogus no',
        ]
        result = server_all_statements_series.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_clause_stmt_server_standalone_passing(self):
        """ Clause server; Element Statement; passing mode """
        test_data = [
            'server 123.123.123.123 { bogus yes; };',
            'server 234.234.234.234 { edns no; };',
        ]
        result = clause_stmt_server_standalone.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_clause_stmt_server_standalone_dict_passing(self):
        assertParserResultDictTrue(
            clause_stmt_server_standalone,
            'server 4.4.4.4 { edns yes; };',
            {'server': [{'configs': {'edns': 'yes'}, 'ip_addr': '4.4.4.4'}]}
        )

    def test_isc_clause_stmt_server_standalone_dict2_passing(self):
        assertParserResultDictTrue(
            clause_stmt_server_standalone,
            'server 3.4.5.6 { bogus yes; edns no; edns-udp-size 102; edns-version 2;' +
            ' keys my_key_name_to_private_dns; max-udp-size 32768; notify-source *; notify-source-v6 *;' +
            ' padding 53; provide-ixfr yes; query-source *; query-source address *; query-source-v6 *;' +
            ' request-expire yes; request-ixfr yes; request-nsid yes; send-cookie yes; tcp-keepalive yes; ' +
            ' tcp-only yes; transfer-format one-answer; transfer-source *; transfer-source-v6 *; transfers 36; };',
            {'server': [{'configs': {'bogus': 'yes',
                                     'edns': 'no',
                                     'edns_udp_size': 102,
                                     'edns_version': 2,
                                     'keys': 'my_key_name_to_private_dns',
                                     'max_udp_size': 32768,
                                     'notify_source': {'ip4_addr': '*'},
                                     'notify_source_v6': {'ip6_addr': '*'},
                                     'padding': 53,
                                     'provide_ixfr': 'yes',
                                     'query_source': {'ip4_addr_w': '*'},
                                     'query_source_v6': {'ip6_addr_w': '*'},
                                     'request_expire': 'yes',
                                     'request_ixfr': 'yes',
                                     'request_nsid': 'yes',
                                     'send_cookie': 'yes',
                                     'tcp_keepalive': 'yes',
                                     'tcp_only': 'yes',
                                     'transfer_format': 'one-answer',
                                     'transfer_source': {'ip4_addr_w': '*'},
                                     'transfer_source_v6': {'ip6_addr_w': '*'},
                                     'transfers': 36},
                         'ip_addr': '3.4.5.6'}]}
        )

    def test_isc_clause_stmt_server_standalone_failing(self):
        """ Clause server; Element Statement; failing mode """
        test_data = [
            'server 11.11.11.11 { no-such-option no; };',
        ]
        result = clause_stmt_server_standalone.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_clause_stmt_server_series_passing(self):
        """ Clause server; Series, Statements; passing mode """
        assertParserResultDictTrue(
            clause_stmt_server_series,
            'server 3.3.3.3 { edns yes; };' +
            'server 4.4.4.4 { edns yes; };',
            {'server': [{'ip_addr': '3.3.3.3', 'configs': {'edns': 'yes'}},
                         {'ip_addr': '4.4.4.4', 'configs': {'edns': 'yes'}}]}
        )


if __name__ == '__main__':
    unittest.main()
