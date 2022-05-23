#!/usr/bin/env python3
"""
File: test_managed_keys.py

Clause: view, managed-keys

Statement: managed-keys

Description:  Performs unit test on the isc_managed_keys.py source file.

              The managed-keys statement used by either by:
                * 'view' clause as a statement or
                * top-level 'managed-keys' clause.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue, assertParserResultDictFalse
from bind9_parser.isc_managed_keys import managed_keyname_type,\
    managed_keyname_dquoted, managed_keyname_squoted,\
    managed_key_domain_name, managed_key_type,\
    managed_key_flags_type, managed_key_protocol_type,\
    managed_key_algorithm_name, managed_key_algorithm_type,\
    managed_key_secret_type, managed_keys_set,\
    managed_keys_series, managed_keys_statement_standalone,\
    quoted_managed_key_secret_type


class TestManagedKeys(unittest.TestCase):
    """ Statement managed-keys; used by view or managed-keys clause """

    def test_isc_managed_keys_domain_name_passing(self):
        """ Statement managed-keys; Type Domain Name; passing mode """
        test_data = [
            'key_name1',
            'unquoted-key_id2',
            "'squoted-key_id3'",
            '"dquoted-key_id4"',
        ]
        result = managed_key_domain_name.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_managed_keys_domain_name_failing(self):
        """ Statement managed-keys; Type Domain Name; failing mode """
        test_data = [
            'country us',
        ]
        result = managed_key_domain_name.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_managed_keys_algorithm_name_passing(self):
        """ Statement managed-keys; algorithm name; passing mode"""
        test_data = [
            'aABCDEFG',
            'hmac-md5',
            'hmac-sha512',
            'hmac-sha4096',
        ]
        result = managed_key_algorithm_name.runTests(
            test_data,
            failureTests=False
        )
        self.assertTrue(result[0])

    def test_isc_managed_keys_algorithm_name_failing(self):
        """ Statement managed-keys; algorithm name; failing mode"""
        test_data = [
            'aAB&DEFG',
            '\'aABDEFG',
            'aABDEFG\'',
            '"aABDEFG',
            'aABDEFG"',
            'bad*algorithm;',
        ]
        result = managed_key_algorithm_name.runTests(
            test_data,
            failureTests=True
        )
        self.assertTrue(result[0])

    #  domain name, flags, protocol, algorithm, and the Base64 representation of the
    #  key data.
    def test_isc_managed_keys_series_passing(self):
        """ Statement managed-keys; managed keys series; passing mode """
        test_data = [
            'abc initial-key 1 1 1 "ASBASDASD";',
            'abc initial-key 1 1 1 "ASBASDASD"; def initial-key 243 16 7 "LKJOULKJOIULKKJ+ASD";',
        ]
        result = managed_keys_series.runTests(
            test_data,
            failureTests=False
        )
        self.assertTrue(result[0])

    def test_isc_managed_keys_series_failing(self):
        """ Statement managed-keys; managed keys series, failing mode """
        test_data = [
            'abc initial-key X Y Z ASBASDASD;',
        ]
        result = managed_keys_series.runTests(
            test_data,
            failureTests=True
        )
        self.assertTrue(result[0])

    def test_isc_managed_keys_statement_set_passing(self):
        """ Statement managed-keys; passing mode """
        test_data = [
            'managed-keys { abc initial-key 1 1 1 "ASBASDASD";};',
            'managed-keys { example.com initial-key 1 1 1 "ASBASDASD";};',
            'managed-keys { www.example.com initial-key 1 1 1 "ASBASDASD";};',
            'managed-keys { www1.www.example.com initial-key 1 1 1 "ASBASDASD";};',
            'managed-keys { www1.www.example.com initial-key 1 1 1 "ASBASDASD";};',
            'managed-keys { "." initial-key 257 3 3 "AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC";};',
            "managed-keys { \".\" initial-key 257 3 3 'AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC';};",
            'managed-keys { "." initial-key 257 3 3 "AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC";};',
        ]
        result = managed_keys_statement_standalone.runTests(
            test_data,
            failureTests=False
        )
        self.assertTrue(result[0])

    def test_isc_managed_keys_statement_set_failing(self):
        """ Statement managed-keys; failing mode """
        test_data = [
            'managed-keys { . initial_key 257 3 3 AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC;};',
        ]
        result = managed_keys_statement_standalone.runTests(
            test_data,
            failureTests=True
        )
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()
