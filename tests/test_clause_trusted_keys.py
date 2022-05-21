#!/usr/bin/env python3
"""
File: test_clause_trusted_keys

Description:
  Performs unit test on the 'trusted-keys' clause 
  in isc_clause_trusted_keys.py source file.
    
  Statement Grammar:

    trusted-keys { 
      <string> 
      <integer>
      <integer>
      <integer>
      <quoted_string>; ... };

"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue
from bind9_parser.isc_clause_trusted_keys import \
    clause_stmt_trusted_keys_standalone,\
    clause_stmt_trusted_keys_set, clause_stmt_trusted_keys_series


class TestClauseHttp(unittest.TestCase):
    """ Test Clause 'trusted_keys' """

    def test_clause_stmt_trusted_keys_standalone_empty_passing(self):
        """ Test Clause 'trusted-keys'; statement standalone empty; passing """
        test_string = """trusted-keys { };"""
        expected_result = {'trusted_keys': []}
        assertParserResultDictTrue(
            clause_stmt_trusted_keys_standalone,
            test_string,
            expected_result)

    def test_clause_stmt_trusted_keys_standalone_passing(self):
        """ Test Clause 'trusted-keys'; statement standalone; passing """
        test_string = """
    trusted-keys {
        test.example 256 3 8 "ABCDEFG==";
        };
    """
        expected_result = {'trusted_keys': [{'algorithm_id': '8',
                                             'domain': 'test.example',
                                             'key_id': '256',
                                             'protocol_type': '3',
                                             'pubkey_base64': '"ABCDEFG=="'}]}
        assertParserResultDictTrue(
            clause_stmt_trusted_keys_standalone,
            test_string,
            expected_result)

    def test_clause_stmt_trusted_keys_set_passing(self):
        """ Test Clause 'trusted_keys'; statement set; passing """
        test_string = """
trusted-keys {
    test.example 256 3 8 "ABCDEFG==";
    };
"""
        expected_result = { 'trusted_keys': [ { 'algorithm_id': '8',
                       'domain': 'test.example',
                       'key_id': '256',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'}]}
        assertParserResultDictTrue(
            clause_stmt_trusted_keys_set,
            test_string,
            expected_result)

    def test_stmt_clause_trusted_keys_series_passing(self):
        """ Test Clause 'trusted_keys'; statement series; passing """
        test_string = """
trusted-keys {
    test.example 256 3 8 "ABCDEFG==";
    };
trusted-keys {
    test.example 257 3 10 "ABCDEFG==";
    };
trusted-keys {
    test.example 256 3 13 "ABCDEFG==";
    };
"""
        expected_result = { 'trusted_keys': [ { 'algorithm_id': '8',
                       'domain': 'test.example',
                       'key_id': '256',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '10',
                       'domain': 'test.example',
                       'key_id': '257',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '13',
                       'domain': 'test.example',
                       'key_id': '256',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'}]}
        assertParserResultDictTrue(
                clause_stmt_trusted_keys_series,
                test_string,
                expected_result)

    def test_stmt_clause_trusted_keys_complex_passing(self):
        """ Test Clause 'trusted_keys'; complex statement; passing """
        test_string = """
trusted-keys {
    test10.example 256 3 8 "ABCDEFG==";
    test12.example 257 3 10 "ABCDEFG==";
    test13.example 256 3 13 "ABC+DEFG==";
    test14.example 257 3 14 "ABC/DEFGasdfasddfasddf==";
    test15.example 256 3 15 'ABC/DEFGasdfasddfasddf==';
    };
trusted-keys {
    test20.example 256 3 8 "ABCDEFG==";
    test22.example 257 3 10 "ABCDEFG==";
    test23.example 256 3 13 "ABC+DEFG==";
    test24.example 257 3 14 "ABC/DEFGasdfasddfasddf==";
    test25.example 256 3 15 'ABC/DEFGasdfasddfasddf==';
    };
trusted-keys {
    test30.example 256 3 8 "ABCDEFG==";
    test32.example 257 3 10 "ABCDEFG==";
    test33.example 256 3 13 "ABC+DEFG==";
    test34.example 257 3 14 "ABC/DEFGasdfasddfasddf==";
    test35.example 256 3 15 'ABC/DEFGasdfasddfasddf==';
    };
"""
        expected_result = { 'trusted_keys': [ { 'algorithm_id': '8',
                       'domain': 'test10.example',
                       'key_id': '256',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '10',
                       'domain': 'test12.example',
                       'key_id': '257',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '13',
                       'domain': 'test13.example',
                       'key_id': '256',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABC+DEFG=="'},
                     { 'algorithm_id': '14',
                       'domain': 'test14.example',
                       'key_id': '257',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABC/DEFGasdfasddfasddf=="'},
                     { 'algorithm_id': '15',
                       'domain': 'test15.example',
                       'key_id': '256',
                       'protocol_type': '3',
                       'pubkey_base64': "'ABC/DEFGasdfasddfasddf=='"},
                     { 'algorithm_id': '8',
                       'domain': 'test20.example',
                       'key_id': '256',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '10',
                       'domain': 'test22.example',
                       'key_id': '257',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '13',
                       'domain': 'test23.example',
                       'key_id': '256',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABC+DEFG=="'},
                     { 'algorithm_id': '14',
                       'domain': 'test24.example',
                       'key_id': '257',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABC/DEFGasdfasddfasddf=="'},
                     { 'algorithm_id': '15',
                       'domain': 'test25.example',
                       'key_id': '256',
                       'protocol_type': '3',
                       'pubkey_base64': "'ABC/DEFGasdfasddfasddf=='"},
                     { 'algorithm_id': '8',
                       'domain': 'test30.example',
                       'key_id': '256',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '10',
                       'domain': 'test32.example',
                       'key_id': '257',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '13',
                       'domain': 'test33.example',
                       'key_id': '256',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABC+DEFG=="'},
                     { 'algorithm_id': '14',
                       'domain': 'test34.example',
                       'key_id': '257',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABC/DEFGasdfasddfasddf=="'},
                     { 'algorithm_id': '15',
                       'domain': 'test35.example',
                       'key_id': '256',
                       'protocol_type': '3',
                       'pubkey_base64': "'ABC/DEFGasdfasddfasddf=='"}]}
        assertParserResultDictTrue(
                clause_stmt_trusted_keys_series,
                test_string,
                expected_result)


if __name__ == '__main__':
    unittest.main()
