#!/usr/bin/env python3.7
"""
File: test_trusted_keys.py

Clause: trusted_keys

Title: Statements Used Only By trusted_keys Clause.

Description: Provides trusted_keys-related grammar in PyParsing engine
             for ISC-configuration style
"""
import unittest
from isc_utils import assertParserResultDictTrue, assertParserResultDictFalse
from isc_trusted_keys import trusted_keys_statements_set, trusted_keys_statements_series


class TestTrustedKeys(unittest.TestCase):
    """ Clause trusted_keys """

    def test_isc_trusted_keys_statements_set_passing(self):
        """ Clause trusted_keys; Statement Series; passing mode """
        test_string = [
            'trusted-keys { abc 1 1 1 "ASBASDASD==";};',
            'trusted-keys { "." 257 3 3 "AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC";};',
            "trusted-keys { \".\" 257 3 3 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC';};",
            'trusted-keys { "." 1 243 4 "BBBBBEEEEE++++/////ASDASDASDASDASD=="; };',
        ]
        result = trusted_keys_statements_set.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            trusted_keys_statements_set,
            "trusted-keys { \".\" 257 3 7 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC';};",
            {'trusted_keys': [{'algorithm_id': 7,
                               'domain': '.',
                               'flags': 257,
                               'protocol_id': 3}]}
        )

    def test_isc_trusted_keys_statements_set_failing(self):
        """ Clause trusted_keys; Statement Set; failing mode """
        test_string = [
            'trusted-keys { "." initial-key 257 3 3 "AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC";};',
        ]
        result = trusted_keys_statements_set.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_trusted_keys_statement_series_passing(self):
        """ Clause trusted_keys; Statement Series; passing mode """
        assertParserResultDictTrue(
            trusted_keys_statements_series,
            'trusted-keys { abc 1 1 1 "ASBASDASD==";};' +
            'trusted-keys { "." 257 3 3 "AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC";};' +
            "trusted-keys { \".\" 257 3 3 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC';};" +
            'trusted-keys { "." 1 243 4 "BBBBBEEEEE++++/////ASDASDASDASDASD=="; };',
            {'trusted_keys': [{'algorithm_id': 1,
                               'domain': 'abc',
                               'flags': 1,
                               'protocol_id': 1},
                              {'algorithm_id': 3,
                               'domain': '.',
                               'flags': 257,
                               'protocol_id': 3},
                              {'algorithm_id': 3,
                               'domain': '.',
                               'flags': 257,
                               'protocol_id': 3},
                              {'algorithm_id': 4,
                               'domain': '.',
                               'flags': 1,
                               'protocol_id': 243}]}
        )

    def test_isc_trusted_keys_statements_series_failing(self):
        """ Clause trusted_keys; Statement Series; failing mode """
        test_string = [
            'transfers Y;'
            'transfers yes;',
            'transfers no;',
            'transfers True;',
            'transfers False;',
        ]
        result = trusted_keys_statements_series.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()
