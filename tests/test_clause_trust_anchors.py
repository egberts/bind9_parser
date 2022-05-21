#!/usr/bin/env python3
"""
File: test_clause_trust_anchors

Description:
  Performs unit test on the 'trust-anchors' clause 
  in isc_clause_trust_anchors.py source file.
    
  Statement Grammar:

    trust-anchors { <string> ( static-key |
      initial-key | static-ds | initial-ds )
      <integer> <integer> <integer>
      <quoted_string>; ... };

"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue
from bind9_parser.isc_clause_trust_anchors import trust_anchors_stmt_key_type_keyword, \
    trust_anchors_stmt_key_id_integer, \
    trust_anchors_stmt_element, trust_anchors_stmt_element_series, \
    clause_stmt_trust_anchors_standalone,\
    clause_stmt_trust_anchors_set, clause_stmt_trust_anchors_series


class TestClauseHttp(unittest.TestCase):
    """ Test Clause 'trust_anchors' """

    def test_trust_anchors_key_type_passing(self):
        """ Test Clause 'trust_anchors'; key-type; passing """
        test_string = 'initial-ds'
        expected_result = {'key_type': 'initial-ds'}
        assertParserResultDictTrue(
            trust_anchors_stmt_key_type_keyword,
            test_string,
            expected_result)

    def test_trust_anchors_stmt_element_passing(self):
        """ Test Clause 'trust_anchors'; statement element; passing """
        test_string = 'test.example static-ds 256 3 8 "ABCDEFG==";'
        expected_result = { 'trust_anchors': [ { 'algorithm_id': '8',
                       'domain': 'test.example',
                       'key_id': '256',
                       'key_type': 'static-ds',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'}]}
        assertParserResultDictTrue(
            trust_anchors_stmt_element,
            test_string,
            expected_result)

    def test_trust_anchors_stmt_element_series_passing(self):
        """ Test Clause 'trust_anchors'; element set 'ca-file'; passing """
        test_string = """
test.example initial-ds 256 3 8 "ABCDEFG==";
test2.example static-ds 257 3 10 "ABCDEFG==";
test3.example initial-key 256 3 13 "ABC+DEFG==";
test4.example static-key 257 3 14 "ABC/DEFGasdfasddfasddf==";
test5.example static-key 256 3 15 'ABC/DEFGasdfasddfasddf==';
"""
        expected_result = { 'trust_anchors': [ { 'algorithm_id': '8',
                       'domain': 'test.example',
                       'key_id': '256',
                       'key_type': 'initial-ds',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '10',
                       'domain': 'test2.example',
                       'key_id': '257',
                       'key_type': 'static-ds',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '13',
                       'domain': 'test3.example',
                       'key_id': '256',
                       'key_type': 'initial-key',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABC+DEFG=="'},
                     { 'algorithm_id': '14',
                       'domain': 'test4.example',
                       'key_id': '257',
                       'key_type': 'static-key',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABC/DEFGasdfasddfasddf=="'},
                     { 'algorithm_id': '15',
                       'domain': 'test5.example',
                       'key_id': '256',
                       'key_type': 'static-key',
                       'protocol_type': '3',
                       'pubkey_base64': "'ABC/DEFGasdfasddfasddf=='"}]}
        assertParserResultDictTrue(
            trust_anchors_stmt_element_series,
            test_string,
            expected_result)

    def test_clause_stmt_trust_anchors_standalone_passing(self):
        """ Test Clause 'trust-anchors'; statement standalone; passing """
        test_string = """
trust-anchors {
    test.example initial-ds 256 3 8 "ABCDEFG==";
    };
"""
        expected_result = { 'trust_anchors': [ { 'algorithm_id': '8',
                       'domain': 'test.example',
                       'key_id': '256',
                       'key_type': 'initial-ds',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'}]}
        assertParserResultDictTrue(
            clause_stmt_trust_anchors_standalone,
            test_string,
            expected_result)

    def test_clause_stmt_trust_anchors_set_passing(self):
        """ Test Clause 'trust_anchors'; statement set; passing """
        test_string = """
trust-anchors {
    test.example initial-ds 256 3 8 "ABCDEFG==";
    };
"""
        expected_result = { 'trust_anchors': [ { 'algorithm_id': '8',
                       'domain': 'test.example',
                       'key_id': '256',
                       'key_type': 'initial-ds',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'}]}
        assertParserResultDictTrue(
            clause_stmt_trust_anchors_set,
            test_string,
            expected_result)

    def test_stmt_clause_trust_anchors_series_passing(self):
        """ Test Clause 'trust_anchors'; statement series; passing """
        test_string = """
trust-anchors {
    test.example static-ds 256 3 8 "ABCDEFG==";
    };
trust-anchors {
    test.example initial-key 257 3 10 "ABCDEFG==";
    };
trust-anchors {
    test.example static-key 256 3 13 "ABCDEFG==";
    };
"""
        expected_result = { 'trust_anchors': [ { 'algorithm_id': '8',
                       'domain': 'test.example',
                       'key_id': '256',
                       'key_type': 'static-ds',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '10',
                       'domain': 'test.example',
                       'key_id': '257',
                       'key_type': 'initial-key',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '13',
                       'domain': 'test.example',
                       'key_id': '256',
                       'key_type': 'static-key',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'}]}
        assertParserResultDictTrue(
                clause_stmt_trust_anchors_series,
                test_string,
                expected_result)

    def test_stmt_clause_trust_anchors_complex_passing(self):
        """ Test Clause 'trust_anchors'; complex statement; passing """
        test_string = """
trust-anchors {
    test10.example initial-ds 256 3 8 "ABCDEFG==";
    test12.example initial-ds 257 3 10 "ABCDEFG==";
    test13.example initial-ds 256 3 13 "ABC+DEFG==";
    test14.example initial-ds 257 3 14 "ABC/DEFGasdfasddfasddf==";
    test15.example initial-ds 256 3 15 'ABC/DEFGasdfasddfasddf==';
    };
trust-anchors {
    test20.example static-ds 256 3 8 "ABCDEFG==";
    test22.example static-ds 257 3 10 "ABCDEFG==";
    test23.example static-ds 256 3 13 "ABC+DEFG==";
    test24.example static-ds 257 3 14 "ABC/DEFGasdfasddfasddf==";
    test25.example static-ds 256 3 15 'ABC/DEFGasdfasddfasddf==';
    };
trust-anchors {
    test30.example initial-key 256 3 8 "ABCDEFG==";
    test32.example initial-key 257 3 10 "ABCDEFG==";
    test33.example initial-key 256 3 13 "ABC+DEFG==";
    test34.example initial-key 257 3 14 "ABC/DEFGasdfasddfasddf==";
    test35.example initial-key 256 3 15 'ABC/DEFGasdfasddfasddf==';
    };
"""
        expected_result = { 'trust_anchors': [ { 'algorithm_id': '8',
                       'domain': 'test10.example',
                       'key_id': '256',
                       'key_type': 'initial-ds',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '10',
                       'domain': 'test12.example',
                       'key_id': '257',
                       'key_type': 'initial-ds',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '13',
                       'domain': 'test13.example',
                       'key_id': '256',
                       'key_type': 'initial-ds',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABC+DEFG=="'},
                     { 'algorithm_id': '14',
                       'domain': 'test14.example',
                       'key_id': '257',
                       'key_type': 'initial-ds',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABC/DEFGasdfasddfasddf=="'},
                     { 'algorithm_id': '15',
                       'domain': 'test15.example',
                       'key_id': '256',
                       'key_type': 'initial-ds',
                       'protocol_type': '3',
                       'pubkey_base64': "'ABC/DEFGasdfasddfasddf=='"},
                     { 'algorithm_id': '8',
                       'domain': 'test20.example',
                       'key_id': '256',
                       'key_type': 'static-ds',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '10',
                       'domain': 'test22.example',
                       'key_id': '257',
                       'key_type': 'static-ds',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '13',
                       'domain': 'test23.example',
                       'key_id': '256',
                       'key_type': 'static-ds',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABC+DEFG=="'},
                     { 'algorithm_id': '14',
                       'domain': 'test24.example',
                       'key_id': '257',
                       'key_type': 'static-ds',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABC/DEFGasdfasddfasddf=="'},
                     { 'algorithm_id': '15',
                       'domain': 'test25.example',
                       'key_id': '256',
                       'key_type': 'static-ds',
                       'protocol_type': '3',
                       'pubkey_base64': "'ABC/DEFGasdfasddfasddf=='"},
                     { 'algorithm_id': '8',
                       'domain': 'test30.example',
                       'key_id': '256',
                       'key_type': 'initial-key',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '10',
                       'domain': 'test32.example',
                       'key_id': '257',
                       'key_type': 'initial-key',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABCDEFG=="'},
                     { 'algorithm_id': '13',
                       'domain': 'test33.example',
                       'key_id': '256',
                       'key_type': 'initial-key',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABC+DEFG=="'},
                     { 'algorithm_id': '14',
                       'domain': 'test34.example',
                       'key_id': '257',
                       'key_type': 'initial-key',
                       'protocol_type': '3',
                       'pubkey_base64': '"ABC/DEFGasdfasddfasddf=="'},
                     { 'algorithm_id': '15',
                       'domain': 'test35.example',
                       'key_id': '256',
                       'key_type': 'initial-key',
                       'protocol_type': '3',
                       'pubkey_base64': "'ABC/DEFGasdfasddfasddf=='"}]}
        assertParserResultDictTrue(
                clause_stmt_trust_anchors_series,
                test_string,
                expected_result)


if __name__ == '__main__':
    unittest.main()
