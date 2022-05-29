#!/usr/bin/env python3
"""
File: test_clause_key.py

Description:  Performs unit test on the isc_clause_key.py source file.
"""

import unittest
from bind9_parser.isc_utils import key_id_keyword_and_name_pair, key_id_keyword_and_name_element,\
    assert_parser_result_dict_true, key_secret_dequotable, key_secret
from bind9_parser.isc_clause_key import key_algorithm_name,\
    key_secret_element, key_id, key_algorithm_element, clause_stmt_key_series


class TestClauseKey(unittest.TestCase):
    """ ISC Bind Clause Key """

    def test_isc_key_key_id_dict_passing(self):
        """ Clause Keys; Element KeyId; List/Dict; passing """
        test_data = 'my_key_id'
        expected_result = {'key_id': 'my_key_id'}
        assert_parser_result_dict_true(key_id, test_data, expected_result)

    def test_isc_key_id_keyword_and_name_element_passing(self):
        """ Clause Keys; Element KeyId and Name; passing """
        test_data = [
            'key my_key_id',
            'key "my_dquoted_key_id"',
            'key \'my_squoted_key_id\'',
        ]
        result = key_id_keyword_and_name_pair.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_key_id_keyword_and_name_element_dict_passing(self):
        """ Clause Keys; Element KeyId and Name; Dict/List; passing """
        test_data = 'key your_key_id'
        expected_result = {'key_id': 'your_key_id'}
        assert_parser_result_dict_true(key_id_keyword_and_name_pair,
                                       test_data,
                                       expected_result)
        test_data = 'key your_key_id'
        expected_result = {'key_id': 'your_key_id'}
        assert_parser_result_dict_true(key_id_keyword_and_name_pair,
                                       test_data,
                                       expected_result)
        test_data = 'key "my_dquoted_key_id"'
        expected_result = {'key_id': '"my_dquoted_key_id"'}
        assert_parser_result_dict_true(key_id_keyword_and_name_pair,
                                       test_data,
                                       expected_result)
        test_data = 'key \'my_squoted_key_id\''
        expected_result = {'key_id': '\'my_squoted_key_id\''}
        assert_parser_result_dict_true(key_id_keyword_and_name_pair,
                                       test_data,
                                       expected_result)

    def test_isc_key_id_keyword_and_name_element_failing(self):
        """ Clause Keys; Element KeyId and Name; failing """
        test_data = [
            'key \'there_is_a_gap in_my_key_id\'',
            'key no&ampersand&allowed'
        ]
        result = key_id_keyword_and_name_pair.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_key_secret_passing(self):
        """ Clause key; Type Secret; passing mode """
        test_data = [
            'ABASDASDAD=',  # equal symbol is allowed
            'ABCDEFABCDEFABCDEFABCDEFABCDEF',
            'AB/DEFABCDEFABCDEFABCDEFABCDEF',   # slash symbol is allowed
            'ABCDEFA+CDEFABCDEFABCDEFABCDEF',   # plus symbol is allowed
        ]
        result = key_secret.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_key_secret_dict_passing(self):
        """ Clause key; Type key_secret; List/Dict; passing """
        test_data = 'ASDASDASDASDASSD123123123123123'
        expected_result = {'key_secret': 'ASDASDASDASDASSD123123123123123'}
        assert_parser_result_dict_true(key_secret, test_data, expected_result)

    def test_isc_key_secret_failing(self):
        """ Clause key; Type Secret; failing mode """
        test_data = [
            'secret a',
            'ABCDEFA&CDEFABCDEFABCDEFABCDEF',  # ampersand symbol is not allowed
        ]
        result = key_secret_element.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_key_algorithm_name_passing(self):
        """ Clause key; Type Algorithm Name; passing mode """
        test_data = [
            'hmac-sha512',
            'aABCDEFG',
        ]
        result = key_algorithm_name.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_key_algorithm_name_dict_passing(self):
        """ Clause key; Type key_algorithm_name; List/Dict; passing """
        test_data = 'hmac-sha2048-cdc'
        expected_result = {'algorithm': 'hmac-sha2048-cdc'}
        assert_parser_result_dict_true(key_algorithm_name, test_data, expected_result)

    def test_isc_key_algorithm_name_failing(self):
        """ Clause key; Type Algorithm Name; failing mode """
        test_data = [
            'hmac=sha512',
            'hmac_sha512',
            'aA&CDEFG',
        ]
        result = key_algorithm_name.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_key_id_passing(self):
        """ Clause key; Type key_id; passing mode """
        test_data = [
            'basickeyname',
            'Normal_Key_Name',
            'Hyphenated-key-name',
            'unquoted-key_id',
            "'squoted-key_id'",
            '"dquoted-key_id"',
        ]
        result = key_id.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_key_id_failing(self):
        """ Clause key; Type key_id; failing mode """
        test_data = [
            'key name without quotes',
            '\'Misquoted-key-name',  # only one single-quote used here
            'Misquoted-key-name2\"',  # only one double-quote used here
            '\"Misquoted-key-name3',  # only one double-quote used here
            'Misquoted-key-name4\'',  # only one single-quote used here
            'starred-*-key-name',
        ]
        result = key_id.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_key_reference_list_passing(self):
        """ Clause key; List key reference; passing mode """
        test_data = [
            'key 0123456789ABCDEF;',
            'key ab2d2fg;',
            '     key hi3j3kl;',
            'key mn4o5pq     ;',
            '     key rs6t7uv     ;',
            '     key wx8y9za    ;',
            '     key bc0d1ef;     ',
            '     key gh2i3jk    ;     ',
            'key lm4n5op    ;     ',
        ]
        key_id_keyword_and_name_element.setWhitespaceChars(' \n\t')
        result = key_id_keyword_and_name_element.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_key_key_id_keyword_and_name_list_dict_passing(self):
        """ Clause key; Type key_id_keyword_and_name_element; List/Dict; passing """
        test_data = 'key first_key;'
        expected_result = {'key_id': 'first_key'}
        assert_parser_result_dict_true(key_id_keyword_and_name_element, test_data, expected_result)

    def test_isc_key_reference_list_failing(self):
        """ Clause key; List key reference; failing mode """
        test_data = [
            'key name without quotes',
            'algorithm hmac-sha512;',
        ]
        result = key_id_keyword_and_name_element.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    # TODO Additional unit tests for key_algorithm_element

    #  key key_id { algorithm <algorithm_name>; secret <key_secret>; };
    def test_isc_clause_stmt_key_passing(self):
        """ Clause key; Statement key; passing mode """
        test_data = [
            'key my_key_1 { algorithm hmac-sha512; secret ABCDEFABCDEFABCDEFABCDEF; };',
            'key dyndns { algorithm hmac-sha512; secret ABCDEFG; };',
            'key DDNS_UPDATER { algorithm hmac-md5; secret "+TlDtzhAe/akZ/tF507/zQ";};',
        ]
        result = clause_stmt_key_series.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_clause_stmt_key_dict_passing(self):
        """ Clause key; Statement clause_stmt_key_series; List/Dict; passing """
        test_data = 'key DDNS_UPDATER { algorithm hmac-md5; secret "oopsiedaisy"; };'
        expected_result = { 'key': [ { 'algorithm': 'hmac-md5',
             'key_id': 'DDNS_UPDATER',
             'secret': 'oopsiedaisy'}]}
        assert_parser_result_dict_true(clause_stmt_key_series, test_data, expected_result)

    def test_isc_clause_stmt_multiple_key_dict_passing(self):
        """ Clause key; Statement clause_stmt_key_series; multiple List/Dict; passing """
        assert_parser_result_dict_true(
            clause_stmt_key_series,
            'key my_key_1 { algorithm hmac-sha512; secret ABCDEFABCDEFABCDEFABCDEF; };' +
            'key dyndns { algorithm hmac-sha512; secret ABCDEFG; };' +
            'key DDNS_UPDATER { algorithm hmac-md5; secret "+TlDtzhAe/akZ/tF507/zQ";};',
            {'key': [{'algorithm': 'hmac-sha512',
                      'key_id': 'my_key_1',
                      'secret': 'ABCDEFABCDEFABCDEFABCDEF'},
                     {'algorithm': 'hmac-sha512',
                      'key_id': 'dyndns',
                      'secret': 'ABCDEFG'},
                     {'algorithm': 'hmac-md5',
                      'key_id': 'DDNS_UPDATER',
                      'secret': '+TlDtzhAe/akZ/tF507/zQ'}]}
        )

    def test_isc_key_clause_stmt_failing(self):
        """ Clause key; Statement key; failing mode """
        test_data = [
            'key what_is_mine { database ghi; search disabled;};',
            'deny { }',
            'key dyndns { algorithm hmac*sha512; secret ABCDEFG; };',  # inadvert '*'
            'key dyndns { algorithm,  hmac-sha512; secret ABCDEFG; };',  # mistyped ';' with ','
            'key dyndns { oops-algorithm  hmac-sha512; secret ABCDEFG; };',  # missing semicolon
            'key bad { algorithm sha512; secret ABCDEFGHIJK; }',  # missing semicolon at end
        ]
        result = clause_stmt_key_series.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])
