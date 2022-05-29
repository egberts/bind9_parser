#!/usr/bin/env python3
"""
File: test_clause_managed_keys.py

Description:  Performs unit test on the isc_managed_keys.py source file.
"""

import unittest
from bind9_parser.isc_utils import assert_parser_result_dict_true, assert_parser_result_dict_false
from bind9_parser.isc_clause_managed_keys import clause_stmt_managed_keys_series


class TestClauseManagedKeys(unittest.TestCase):
    """ Clause managed-keys """

    def test_isc_clause_stmt_managed_keys_passing(self):
        """ Clause managed-keys; passing mode"""
        test_string = 'managed-keys { abc initial-key 1 2 3 "ASBASDASD";};'
        expected_result = { 'managed_keys': [ { 'algorithm_id': 3,
                      'flags': 1,
                      'key_secret': '"ASBASDASD"',
                      'protocol_id': 2,
                      'rr_domain': 'abc'}]}
        assert_parser_result_dict_true(clause_stmt_managed_keys_series,
                                       test_string,
                                       expected_result)
        test_string = 'managed-keys { example.com initial-key 4 5 6 "ASBASDASD";};'
        expected_result = { 'managed_keys': [ { 'algorithm_id': 6,
                      'flags': 4,
                      'key_secret': '"ASBASDASD"',
                      'protocol_id': 5,
                      'rr_domain': 'example.com'}]}
        assert_parser_result_dict_true(clause_stmt_managed_keys_series,
                                       test_string,
                                       expected_result)
        test_string = 'managed-keys { www.example.com initial-key 7 8 9 "ZZZZZZASD";};'
        expected_result = { 'managed_keys': [ { 'algorithm_id': 9,
                      'flags': 7,
                      'key_secret': '"ZZZZZZASD"',
                      'protocol_id': 8,
                      'rr_domain': 'www.example.com'}]}
        assert_parser_result_dict_true(clause_stmt_managed_keys_series,
                                       test_string,
                                       expected_result)
        test_string = 'managed-keys { www1.www.example.com initial-key 1 1 1 "ASBASDASD";};'
        expected_result = { 'managed_keys': [ { 'algorithm_id': 1,
                      'flags': 1,
                      'key_secret': '"ASBASDASD"',
                      'protocol_id': 1,
                      'rr_domain': 'www1.www.example.com'}]}
        assert_parser_result_dict_true(clause_stmt_managed_keys_series,
                                       test_string,
                                       expected_result)
        test_string = 'managed-keys { www1.www.example.com initial-key 1 1 1 "ASBASDASD";};'
        expected_result = { 'managed_keys': [ { 'algorithm_id': 1,
                      'flags': 1,
                      'key_secret': '"ASBASDASD"',
                      'protocol_id': 1,
                      'rr_domain': 'www1.www.example.com'}]}
        assert_parser_result_dict_true(clause_stmt_managed_keys_series,
                                       test_string,
                                       expected_result)
        # Example extracted from https://docs.menandmice.com/display/MM/How+to+enable+DNSSEC+validation+in+a+resolving+BIND+DNS+Server
        test_string = """managed-keys {
   "." initial-key 257 3 8
    "AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF
     FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX
     bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD
     X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz
     W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS
     Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq
     QxA+Uk1ihz0=";
}; """
        expected_result = { 'managed_keys': [ { 'algorithm_id': 8,
                      'flags': 257,
                      'key_secret': '"AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF\n'
                                    '     '
                                    'FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX\n'
                                    '     '
                                    'bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD\n'
                                    '     '
                                    'X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz\n'
                                    '     '
                                    'W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS\n'
                                    '     '
                                    'Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq\n'
                                    '     QxA+Uk1ihz0="',
                      'protocol_id': 3,
                      'rr_domain': '"."'}]}
        assert_parser_result_dict_true(clause_stmt_managed_keys_series,
                                       test_string,
                                       expected_result)

    def test_isc_clause_stmt_managed_keys_failing(self):
        """ Clause managed-keys; purposely failing mode"""
        test_string = 'managed-keys { . initial-key 257 3 3 "AAAAAAAAA+BBBBBBBBBBBBB/CCXCCCCCCCCCCCCC";};'
        expected_result = {}
        assert_parser_result_dict_false(clause_stmt_managed_keys_series,
                                        test_string,
                                        expected_result)


if __name__ == '__main__':
    unittest.main()
