#!/usr/bin/env python3.7
"""
File: test_server.py

Clause: server

Title: Statements Used Only By server Clause.

Description: Provides server-related grammar in PyParsing engine
             for ISC-configuration style
"""
import unittest
from isc_utils import assertParserResultDictTrue, assertParserResultDictFalse

from isc_server import server_stmt_bogus, server_stmt_edns,\
    server_stmt_edns_version,\
    server_stmt_keys, server_stmt_max_udp_size,\
    server_stmt_notify_source, server_stmt_notify_source_v6,\
    server_stmt_padding,\
    server_stmt_query_source, server_stmt_query_source_v6,\
    server_stmt_request_expire,\
    server_stmt_request_nsid, server_stmt_send_cookie,\
    server_stmt_tcp_keepalive, server_stmt_tcp_only,\
    server_stmt_transfers,\
    server_stmt_transfer_source, server_stmt_transfer_source_v6,\
    server_statement_set, server_statement_series


class TestServer(unittest.TestCase):
    """ Clause server """

    def test_isc_server_stmt_bogus_passing(self):
        """ Clause server; Statement bogus; passing mode """
        test_string = [
            'bogus yes;',
            'bogus 1;',
            'bogus 0;',
            'bogus no;',
            'bogus True;',
            'bogus False;',
        ]
        result = server_stmt_bogus.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

        assertParserResultDictTrue(server_stmt_bogus, 'bogus yes;', {'bogus': 'yes'})

    def test_isc_server_stmt_bogus_failing(self):
        """ Clause server; Statement bogus; failing mode """
        test_string = [
            'bogus Y;'
        ]
        result = server_stmt_bogus.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_edns_passing(self):
        """ Clause server; Statement edns; passing mode """
        test_string = [
            'edns no;',
            'edns yes;',
            'edns 0;',
            'edns 1;',
            'edns True;',
            'edns False;',
        ]
        result = server_stmt_edns.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

        assertParserResultDictTrue(server_stmt_edns, 'edns yes;', {'edns': 'yes'})

    def test_isc_server_stmt_edns_failing(self):
        """ Clause server; Statement edns; failing mode """
        test_string = [
            'edns N;',
        ]
        result = server_stmt_edns.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_edns_version_passing(self):
        """ Clause server; Statement version; passing mode """
        test_string = [
            'edns-version 1;',
            'edns-version 0;',
            'edns-version 104;',
            'edns-version 255;',
        ]
        result = server_stmt_edns_version.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(server_stmt_edns_version, 'edns-version 0;', {'edns_version': 0})

    def test_isc_server_stmt_edns_version_failing(self):
        """ Clause server; Statement edns_version; failing mode """
        test_string = [
            'edns-version Y;'
            'edns-udp-size -3;',
            # 'edns-udp-size 256;',  # TODO: Enforce integer range checking on <byte_type>
            'edns-udp-size 1024;',
        ]
        result = server_stmt_edns_version.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_keys_passing(self):
        """ Clause server; Statement keys; passing mode """
        test_string = [
            'keys yes;',
            'keys 1;',
            'keys 0;',
            'keys no;',
            'keys True;',
            'keys False;',
        ]
        result = server_stmt_keys.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(server_stmt_keys, 'keys True;', {'keys': 'True'})

    def test_isc_server_stmt_keys_failing(self):
        """ Clause server; Statement keys; failing mode """
        test_string = [
            'keys we@rd_keyname;'
        ]
        result = server_stmt_keys.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_max_udp_size_passing(self):
        """ Clause server; Statement max_udp_size; passing mode """
        test_string = [
            'max-udp-size 1;',
            'max-udp-size 0;',
        ]
        result = server_stmt_max_udp_size.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(server_stmt_max_udp_size, 'max-udp-size 2048;', {'max_udp_size': 2048})

    def test_isc_server_stmt_max_udp_size_failing(self):
        """ Clause server; Statement max-udp-size; failing mode """
        test_string = [
            'max-udp-size -1;'
            'max-udp-size Y;'
        ]
        result = server_stmt_max_udp_size.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_notify_source_passing(self):
        """ Clause server; Statement notify-source; passing mode """
        test_string = [
            'notify-source *;',
            'notify-source 128.0.0.1;',
            'notify-source 128.0.0.1 port *;',
            'notify-source 128.0.0.1 port 8053;',
            'notify-source 128.0.0.1 port 8053 dscp 5;',
        ]
        result = server_stmt_notify_source.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            server_stmt_notify_source,
            'notify-source 127.0.0.1 port 15 dscp 1;',  # Missing 'addr'
            {
                'notify_source': {
                    'addr': '127.0.0.1',
                    'dscp_port': 1,
                    'ip_port_w': 15}}
        )

    def test_isc_server_stmt_notify_source_failing(self):
        """ Clause server; Statement notify-source; failing mode """
        test_string = [
            'notify-source &;',
            'notify-source-v6 yes;',
        ]
        result = server_stmt_notify_source.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_notify_source_v6_passing(self):
        """ Clause server; Statement notify-source-v6; passing mode """
        test_string = [
            'notify-source-v6 *;',
            'notify-source-v6 fe09::1;',
            'notify-source-v6 fe0a::1 port *;',
            'notify-source-v6 fe0b::1 port 8053;',
            'notify-source-v6 * port * dscp 5;',
        ]
        result = server_stmt_notify_source_v6.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            server_stmt_notify_source_v6,
            'notify-source-v6 fe09::1 port 19 dscp 2;',  # Missing 'addr'
            {
                'notify_source_v6': {
                    'addr': 'fe09::1',
                    'dscp_port': 2,
                    'ip_port_w': 19}}
        )

    def test_isc_server_stmt_notify_source_v6_failing(self):
        """ Clause server; Statement notify-source-v6; failing mode """
        test_string = [
            'notify-source-v6 Y;'
        ]
        result = server_stmt_notify_source_v6.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_padding_passing(self):
        """ Clause server; Statement padding; passing mode """
        test_string = [
            'padding 1;',
            'padding 0;',
        ]
        result = server_stmt_padding.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            server_stmt_padding,
            'padding 387;',
            {'padding': 387}
        )

    def test_isc_server_stmt_padding_failing(self):
        """ Clause server; Statement padding; failing mode """
        test_string = [
            'padding yes'
            'padding Yeah;'
            'paddling no;'
        ]
        result = server_stmt_padding.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_query_source_passing(self):
        """ Clause server; Statement query-source; passing mode """
        test_string = [
            'query-source *;',
            'query-source address *;',
            'query-source address 127.0.0.1;',
            'query-source 127.0.0.1;',
        ]
        result = server_stmt_query_source.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            server_stmt_query_source,
            'query-source address * port *;',
            {'query_source': {'ip4_addr_w': '*', 'ip_port_w': '*'}}
        )

    def test_isc_server_stmt_query_source_failing(self):
        """ Clause server; Statement query-source; failing mode """
        test_string = [
            'query-source Y;'
        ]
        result = server_stmt_query_source.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_query_source_v6_passing(self):
        """ Clause server; Statement query-source-v6; passing mode """
        test_string = [
            'query-source-v6 fe0c::1;',
            'query-source-v6 fe0c::1 port *;',
            'query-source-v6 fe0c::1 port 8053;',
            'query-source-v6 fe0c::1 port * dscp 9;',
        ]
        result = server_stmt_query_source_v6.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            server_stmt_query_source_v6,
            'query-source-v6 address * port *;',
            {'query_source_v6': {'ip6_addr_w': '*', 'ip_port_w': '*'}}
        )

    def test_isc_server_stmt_query_source_v6_failing(self):
        """ Clause server; Statement query-source-v6; failing mode """
        test_string = [
            'query-source-v6 fe0c::1 port * dscp *;',
        ]
        result = server_stmt_query_source_v6.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_request_expire_passing(self):
        """ Clause server; Statement request-expire; passing mode """
        test_string = [
            'request-expire yes;',
            'request-expire 1;',
            'request-expire 0;',
            'request-expire no;',
            'request-expire True;',
            'request-expire False;',
        ]
        result = server_stmt_request_expire.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            server_stmt_request_expire,
            'request-expire True;',
            {'request_expire': 'True'}
        )

    def test_isc_server_stmt_request_expire_failing(self):
        """ Clause server; Statement request-expire; failing mode """
        test_string = [
            'request-expire Y'
        ]
        result = server_stmt_request_expire.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_request_nsid_passing(self):
        """ Clause server; Statement request-nsid; passing mode """
        test_string = [
            'request-nsid yes;',
            'request-nsid 1;',
            'request-nsid 0;',
            'request-nsid no;',
            'request-nsid True;',
            'request-nsid False;',
        ]
        result = server_stmt_request_nsid.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            server_stmt_request_nsid,
            'request-nsid True;',
            {'request_nsid': 'True'}
        )

    def test_isc_server_stmt_request_nsid_failing(self):
        """ Clause server; Statement request-nsid; failing mode """
        test_string = [
            'request-nsid Y;'
        ]
        result = server_stmt_request_nsid.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_send_cookie_passing(self):
        """ Clause server; Statement send-cookie; passing mode """
        test_string = [
            'send-cookie yes;',
            'send-cookie 1;',
            'send-cookie 0;',
            'send-cookie no;',
            'send-cookie True;',
            'send-cookie False;',
        ]
        result = server_stmt_send_cookie.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            server_stmt_send_cookie,
            'send-cookie yes;',
            {'send_cookie': 'yes'}
        )

    def test_isc_server_stmt_send_cookie_failing(self):
        """ Clause server; Statement send-cookie; failing mode """
        test_string = [
            'send-cookie Y;'
        ]
        result = server_stmt_send_cookie.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_tcp_keepalive_passing(self):
        """ Clause server; Statement tcp-keepalive; passing mode """
        test_string = [
            'tcp-keepalive yes;',
            'tcp-keepalive 1;',
            'tcp-keepalive 0;',
            'tcp-keepalive no;',
            'tcp-keepalive True;',
            'tcp-keepalive False;',
        ]
        result = server_stmt_tcp_keepalive.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            server_stmt_tcp_keepalive,
            'tcp-keepalive yes;',
            {'tcp_keepalive': 'yes'}
        )

    def test_isc_server_stmt_tcp_keepalive_failing(self):
        """ Clause server; Statement tcp-keepalive; failing mode """
        test_string = [
            'tcp-keepalive Y;'
        ]
        result = server_stmt_tcp_keepalive.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_tcp_only_passing(self):
        """ Clause server; Statement tcp-only; passing mode """
        test_string = [
            'tcp-only yes;',
            'tcp-only 1;',
            'tcp-only 0;',
            'tcp-only no;',
            'tcp-only True;',
            'tcp-only False;',
        ]
        result = server_stmt_tcp_only.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            server_stmt_tcp_only,
            'tcp-only yes;',
            {'tcp_only': 'yes'}
        )

    def test_isc_server_stmt_tcp_only_failing(self):
        """ Clause server; Statement tcp-only; failing mode """
        test_string = [
            'tcp-only Y;'
        ]
        result = server_stmt_tcp_only.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_transfers_passing(self):
        """ Clause server; Statement transfers; passing mode """
        test_string = [
            'transfers 1;',
            'transfers 0;',
        ]
        result = server_stmt_transfers.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            server_stmt_transfers,
            'transfers 1;',
            {'transfers': 1}
        )

    def test_isc_server_stmt_transfers_failing(self):
        """ Clause server; Statement transfers; failing mode """
        test_string = [
            'transfers Y;'
            'transfers yes;',
            'transfers no;',
            'transfers True;',
            'transfers False;',
        ]
        result = server_stmt_transfers.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_transfer_source_passing(self):
        """ Clause server; Statement transfer-source; passing mode """
        test_string = [
            'transfer-source 130.0.0.0;',
            'transfer-source 131.0.0.1 port 8053;',
            'transfer-source 132.0.0.2 port 8053 dscp 8;',
            'transfer-source 132.0.0.2 port * dscp 8;',
            'transfer-source 133.0.0.3;',
        ]
        result = server_stmt_transfer_source.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            server_stmt_transfer_source,
            'transfer-source 123.123.123.123 port * dscp 7;',
            {'transfer_source': {'dscp_port': 7,
                                 'ip4_addr_w': '123.123.123.123',
                                 'ip_port_w': '*'}}
        )

    def test_isc_server_stmt_transfer_source_failing(self):
        """ Clause server; Statement transfer-source; failing mode """
        test_string = [
            'transfer-source 132.0.0.2 port 8053 dscp *;',
            'transfer-source 132.0.0.2 port * dscp *;',
        ]
        result = server_stmt_transfer_source.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_stmt_transfer_source_v6_passing(self):
        """ Clause server; Statement transfer-source-v6; passing mode """
        test_string = [
            'transfer-source-v6 ffed::1;',
            'transfer-source-v6 ffee::1 port 8053;',
            'transfer-source-v6 ffef::1 port 8053 dscp 8;',
            'transfer-source-v6 fff0::1 port * dscp 8;',
            'transfer-source-v6 fff1::1;',
        ]
        result = server_stmt_transfer_source_v6.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            server_stmt_transfer_source_v6,
            'transfer-source-v6 ff01::1 port * dscp 7;',
            {'transfer_source_v6': {'dscp_port': 7,
                                    'ip6_addr_w': 'ff01::1',
                                    'ip_port_w': '*'}}
        )

    def test_isc_server_stmt_transfer_source_v6_failing(self):
        """ Clause server; Statement transfer-source-v6; failing mode """
        test_string = [
            'transfer-source-v6 fff2::1 port 8053 dscp *;',
            'transfer-source-v6 fff3::1 port * dscp *;',
        ]
        result = server_stmt_transfer_source_v6.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_statement_set_passing(self):
        """ Clause server; Statement Set; passing mode """
        test_string = [
            'transfers 1;',
            'tcp-only yes;',
        ]
        result = server_statement_set.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_server_statement_set_dict_passing(self):
        assertParserResultDictTrue(
            server_statement_set,
            'transfers 15;',
            {'transfers': 15}
        )

    def test_isc_server_statement_set_failing(self):
        """ Clause server; Statement Set; failing mode """
        test_string = [
            'transfers Y;'
            'transfers yes;',
            'transfers no;',
            'transfers True;',
            'transfers False;',
        ]
        result = server_statement_set.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_server_statement_series_passing(self):
        """ Clause server; Statement Series; passing mode """
        test_string = [
            'bogus yes;',
            'edns yes;',
            'edns no;',
            'edns-version 255; edns no;',
        ]
        result = server_statement_series.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_server_statement_series_dict_passing(self):
        assertParserResultDictTrue(
            server_statement_series,
            'edns yes; bogus yes; ',
            {'bogus': 'yes', 'edns': 'yes'}
        )

    def test_isc_server_statement_series_failing(self):
        """ Clause server; Statement Series; failing mode """
        test_string = [
            'transfers Y;'
            'transfers yes;',
            'transfers no;',
            'transfers True;',
            'transfers False;',
        ]
        result = server_statement_series.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()
