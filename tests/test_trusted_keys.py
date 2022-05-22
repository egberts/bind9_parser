#!/usr/bin/env python3.7
"""
File: test_trusted_keys.py

Clause: trusted_keys

Title: Statements Used Only By trusted_keys Clause.

Description: Provides trusted_keys-related grammar in PyParsing engine
             for ISC-configuration style
"""
import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue, assertParserResultDictFalse
from bind9_parser.isc_trusted_keys import \
    trusted_keys_stmt_key_id_integer, \
    trusted_keys_protocol_type_integer, \
    trusted_keys_algorithm_id_integer, \
    trusted_keys_stmt_group_set, \
    trusted_keys_stmt_group_series, \
    trusted_keys_stmt_standalone, \
    trusted_keys_stmt_set, trusted_keys_stmt_series


class TestTrustedKeys(unittest.TestCase):
    """ Clause trusted_keys """

# trusted_keys_stmt_key_id_integer
# trusted_keys_protocol_type_integer
# trusted_keys_algorithm_id_integer

    def test_isc_trusted_keys_statements_element_key_id_passing(self):
        """ Clause trusted_keys; Statement; key-id; passing mode """
        test_string = [
            '1', '9', '10', '99', '100', '999', '1000', '9999', '65535'
        ]
        result = trusted_keys_stmt_key_id_integer.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_trusted_keys_statements_element_key_id_failing(self):
        """ Clause trusted_keys; Statement; key-id; failing mode """
        test_string = [
            '-1', # '65536', '99999'   # TODO need a 16-bit range
        ]
        result = trusted_keys_stmt_key_id_integer.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_trusted_keys_statements_element_protocol_passing(self):
        """ Clause trusted_keys; Statement; protocol; passing mode """
        test_string = [
            '1', '9', '10', '99', '100', '255'
        ]
        result = trusted_keys_protocol_type_integer.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_trusted_keys_statements_element_protocol_failing(self):
        """ Clause trusted_keys; Statement; protocol; failing mode """
        test_string = [
            '-1',  '1.1' # '256', '999', '65536', '99999'   # TODO need a 8-bit range
        ]
        result = trusted_keys_protocol_type_integer.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_trusted_keys_statements_element_algorithm_id_passing(self):
        """ Clause trusted_keys; Statement; algorithm_id; passing mode """
        test_string = [
            '1', '9', '10', '99', '100', '255'
        ]
        result = trusted_keys_algorithm_id_integer.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_trusted_keys_statements_element_algorithm_id_failing(self):
        """ Clause trusted_keys; Statement; algorithm_id; failing mode """
        test_string = [
            '-1', '1.1'  # '256', '999', '65536', '99999'   # TODO need a 8-bit range
        ]
        result = trusted_keys_algorithm_id_integer.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    # trusted_keys_stmt_group_set
    def test_isc_trusted_keys_statements_group_set_one_passing(self):
        """ Clause trusted_keys; Statement group set one; passing mode """
        assertParserResultDictTrue(
            trusted_keys_stmt_group_set,
            "\".\" 257 3 7 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC';",
            {'trusted_keys': [{'algorithm_id': '7',
                               'domain': '"."',
                               'key_id': '257',
                               'protocol_type': '3',
                               'pubkey_base64': 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC'}]}
        )

    def test_isc_trusted_keys_statements_group_series_one_passing(self):
        """ Clause trusted_keys; Statement group two; passing mode """
        assertParserResultDictTrue(
        trusted_keys_stmt_group_series,
            "\"16.172.in-addr.arpa.\" 256 3 15 'ZZZZZZZZZ+YYYYYYYYYYYYY/XXXXXXXXXXXXXXXX';",
            {'trusted_keys': [{'algorithm_id': '15',
                               'domain': '"16.172.in-addr.arpa."',
                               'key_id': '256',
                               'protocol_type': '3',
                               'pubkey_base64': 'ZZZZZZZZZ+YYYYYYYYYYYYY/XXXXXXXXXXXXXXXX'}]}
            )

    def test_isc_trusted_keys_statements_group_series_two_passing(self):
        """ Clause trusted_keys; Statement group two; passing mode """
        assertParserResultDictTrue(
            trusted_keys_stmt_group_series,
            """
    \".\" 257 3 7 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC';
    \"16.172.in-addr.arpa.\" 256 3 15 'ZZZZZZZZZ+YYYYYYYYYYYYY/XXXXXXXXXXXXXXXX';
    """,
            {'trusted_keys': [{'algorithm_id': '7',
                               'domain': '"."',
                               'key_id': '257',
                               'protocol_type': '3',
                               'pubkey_base64': 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC'},
                              {'algorithm_id': '15',
                               'domain': '"16.172.in-addr.arpa."',
                               'key_id': '256',
                               'protocol_type': '3',
                               'pubkey_base64': 'ZZZZZZZZZ+YYYYYYYYYYYYY/XXXXXXXXXXXXXXXX'}]}
            )

    # trusted_keys_stmt_group_series
    def test_isc_trusted_keys_statements_group_series_many_passing(self):
        """ Clause trusted_keys; Statement group series many; passing mode """
        assertParserResultDictTrue(
            trusted_keys_stmt_group_series,
            """
\".\" 257 3 8 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC';
\".\" 257 3 10 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC';
\".\" 256 3 13 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC';
\".\" 257 3 14 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC';
\".\" 256 3 15 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC';
""",
            {'trusted_keys': [{'algorithm_id': '8',
                               'domain': '"."',
                               'key_id': '257',
                               'protocol_type': '3',
                               'pubkey_base64': 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC'},
                              {'algorithm_id': '10',
                               'domain': '"."',
                               'key_id': '257',
                               'protocol_type': '3',
                               'pubkey_base64': 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC'},
                              {'algorithm_id': '13',
                               'domain': '"."',
                               'key_id': '256',
                               'protocol_type': '3',
                               'pubkey_base64': 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC'},
                              {'algorithm_id': '14',
                               'domain': '"."',
                               'key_id': '257',
                               'protocol_type': '3',
                               'pubkey_base64': 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC'},
                              {'algorithm_id': '15',
                               'domain': '"."',
                               'key_id': '256',
                               'protocol_type': '3',
                               'pubkey_base64': 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC'}]}
        )

    # trusted_keys_stmt_standalone
    def test_isc_trusted_keys_statements_standalone_passing(self):
        """ Clause trusted_keys; Statement; passing mode """
        assertParserResultDictTrue(
            trusted_keys_stmt_standalone,
            "trusted-keys { \".\" 257 3 7 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC';};",
            {'trusted_keys': [{'algorithm_id': '7',
                               'domain': '"."',
                               'key_id': '257',
                               'protocol_type': '3',
                               'pubkey_base64': 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC'}]}
        )

    def test_isc_trusted_keys_statements_set_syntax_passing(self):
        """ Clause trusted_keys; Statement Series; Syntax passing mode """
        test_string = [
            'trusted-keys { abc 1 1 1 "ASBASDASD";};',
            'trusted-keys { "." 257 3 3 "AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC";};',
            "trusted-keys { \".\" 257 3 3 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC';};",
            'trusted-keys { "." 1 243 4 "BBBBBEEEEE++++/////ASDASDASDASDASD"; };',
        ]
        result = trusted_keys_stmt_set.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_trusted_keys_statements_set_multiple_passing(self):
        """ Clause trusted_keys; Statement Set multiple; passing mode """
        test_string = """trusted-keys { 
    abc 1 1 1 "ASBASDASD";
    "." 257 3 3 "AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC";
    \".\" 257 3 3 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC';
    "." 1 243 4 "BBBBBEEEEE++++/////ASDASDASDASDASD";
    };
            """
        assertParserResultDictTrue(
            trusted_keys_stmt_set,
            test_string,
            {'trusted_keys': [{'algorithm_id': '1',
                               'domain': 'abc',
                               'key_id': '1',
                               'protocol_type': '1',
                               'pubkey_base64': 'ASBASDASD'},
                              {'algorithm_id': '3',
                               'domain': '"."',
                               'key_id': '257',
                               'protocol_type': '3',
                               'pubkey_base64': 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC'},
                              {'algorithm_id': '3',
                               'domain': '"."',
                               'key_id': '257',
                               'protocol_type': '3',
                               'pubkey_base64': 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC'},
                              {'algorithm_id': '4',
                               'domain': '"."',
                               'key_id': '1',
                               'protocol_type': '243',
                               'pubkey_base64': 'BBBBBEEEEE++++/////ASDASDASDASDASD'}]}
        )

    def test_isc_trusted_keys_statements_set_passing2(self):
        """ Clause trusted_keys; Statement Series; passing mode """
        assertParserResultDictTrue(
            trusted_keys_stmt_set,
            "trusted-keys { \".\" 257 3 7 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC';};",
            {'trusted_keys': [{'algorithm_id': '7',
                               'domain': '"."',
                               'key_id': '257',
                               'protocol_type': '3',
                               'pubkey_base64': 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC'}]}
        )

    def test_isc_trusted_keys_statements_set_failing(self):
        """ Clause trusted_keys; Statement Set; failing mode """
        # copy the test_string from newer 'trust-anchors' to here, it should fail
        test_string = [
            'trusted-keys { "." initial-ds 257 3 3 "AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC";};',
            'trusted-keys { "." 257 initial-ds 3 3 "AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC";};',
            'trusted-keys { "." 257 3 initial-ds 3 "AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC";};',
            'trusted-keys { "." 257 3 3 initial-ds "AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC";};',
            'trusted-keys { "." 257 3 3 "AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC" initial-ds;};',
        ]
        result = trusted_keys_stmt_set.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_trusted_keys_statement_series_passing(self):
        """ Clause trusted_keys; Statement Series; passing mode """
        assertParserResultDictTrue(
            trusted_keys_stmt_series,
            'trusted-keys { abc 1 1 1 "ASBASDASD"; second-zone.test. 2 2 2 "ASASDASDASDASD"; };' +
            "trusted-keys { \".\" 3 3 3 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC';};" +
            'trusted-keys { "." 4 4 4 "BBBBBEEEEE++++/////ASDASDASDASDASD"; };' +
            'trusted-keys { "." 5 5 5 "AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC";};',
            {'trusted_keys': [{'algorithm_id': '1',
                               'domain': 'abc',
                               'key_id': '1',
                               'protocol_type': '1',
                               'pubkey_base64': 'ASBASDASD'},
                              {'algorithm_id': '2',
                               'domain': 'second-zone.test.',
                               'key_id': '2',
                               'protocol_type': '2',
                               'pubkey_base64': 'ASASDASDASDASD'},
                              {'algorithm_id': '3',
                               'domain': '"."',
                               'key_id': '3',
                               'protocol_type': '3',
                               'pubkey_base64': 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC'},
                              {'algorithm_id': '4',
                               'domain': '"."',
                               'key_id': '4',
                               'protocol_type': '4',
                               'pubkey_base64': 'BBBBBEEEEE++++/////ASDASDASDASDASD'},
                              {'algorithm_id': '5',
                               'domain': '"."',
                               'key_id': '5',
                               'protocol_type': '5',
                               'pubkey_base64': 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC'}]}
        )


if __name__ == '__main__':
    unittest.main()
