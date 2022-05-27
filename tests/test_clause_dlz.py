#!/usr/bin/env python3
"""
File: test_clause_dlz.py

Description:  Performs unit test on the isc_clause_dlz.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue
from bind9_parser.isc_clause_dlz import dlz_database_element, dlz_search_element, \
    dlz_element_group, clause_stmt_dlz_standalone, clause_stmt_dlz_series


class TestClauseDLZ(unittest.TestCase):
    """ Clause DLZ """

    def test_isc_dlz_database_element_passing(self):
        """ Clause dlz; Element database; passing mode """
        test_data = 'database "a";'
        expected_result = {'db_args': 'a'}
        assertParserResultDictTrue(dlz_database_element, test_data, expected_result)

    def test_isc_dlz_database_element2_passing(self):
        assertParserResultDictTrue(
            dlz_database_element,
            'database "dlopen ../dlz_perl_driver.so dlz_perl_example.pm dlz_perl_example";',
            {'db_args': 'dlopen ../dlz_perl_driver.so dlz_perl_example.pm '
                        'dlz_perl_example'}
        )

    def test_isc_dlz_database_element_failing(self):
        """ Clause dlz; Element database; failing mode """
        test_data = [
            'database "p;.qr;"']
        result = dlz_database_element.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_dlz_search_element_passing(self):
        """ Clause dlz; Element search; passing mode """
        test_data = [
            'search 0;',
            'search yes;',
            'search TRUE;',
            'search 1;',
            'search No;',
            'search FALSE;',
        ]
        result = dlz_search_element.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            dlz_search_element,
            'search TRUE;',
            {'search': 'True'}
        )


    def test_isc_dlz_search_element_failing(self):
        """ Clause dlz; Element search; failing mode """
        test_data = [
            'search a*b;',
            'search noPE',
            'search Noooooooo',
            'search 15',
        ]
        result = dlz_search_element.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_dlz_element_group_passing(self):
        """ Clause dlz; Element group; passing mode """
        test_data = [
            'database "abc"; search no;',
            'search yes; database "def";',
        ]
        result = dlz_element_group.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_dlz_element_group_dict_passing(self):
        assertParserResultDictTrue(
            dlz_element_group,
            'database "ghi"; search yes;',
            {'db_args': 'ghi', 'search': 'yes'}
        )

    def test_isc_dlz_element_group_failing(self):
        """ Clause dlz; Element group; failing mode """
        test_data = [
            '* * port 954 allow { 127.0.0.2; 127.0.0.3;} keys { public&-rndc-key; }',
            'database a*b; search off;'
            'database ab; search enabling;'
            'databas3 ab; search off;'
        ]
        result = dlz_element_group.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_dlz_dlz_stmt_passing(self):
        """ Element dlz; Statment group; passing mode """
        test_data = [
            'dlz my_dlz_1 { database "def"; search yes; };',
            'dlz example { database "dlopen driver.so args"; search yes; };'
        ]
        result = clause_stmt_dlz_standalone.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_dlz_dlz_stmt_dict_passing(self):
        assertParserResultDictTrue(
            clause_stmt_dlz_standalone,
            'dlz your_IBM_2 { database "RSDMS"; search no; };',
            {'dlz': [{'db_args': 'RSDMS',
                      'dlz_name': 'your_IBM_2',
                      'search': 'no'}]}
        )

    def test_isc_dlz_dlz_stmt_failing(self):
        """ Element dlz; Statment group; failing mode """
        test_data = [
            'dlz what_is_mine { database ghi; search disabled;};',
            'deny { }',
        ]
        result = clause_stmt_dlz_standalone.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_clause_stmt_dlz_single_passing(self):
        """ Clause dlz; Single Statment group; passing mode """
        test_data = 'dlz my_dlz_1 { database "def"; search yes; };'
        expected_result = {
            'dlz': [
                {'db_args': 'def', 'dlz_name': 'my_dlz_1', 'search': 'yes'}
            ]
        }
        assertParserResultDictTrue(clause_stmt_dlz_series, test_data, expected_result)

    def test_isc_clause_stmt_dlz_multiple_passing(self):
        """ Clause dlz; Multiple Statments group; passing mode """
        assertParserResultDictTrue(
            clause_stmt_dlz_series,
            """dlz my_dlz_1 { database "def"; search yes; };
               dlz example { database "dlopen driver.so args"; search yes; };
               dlz other { database "dlopen driver.so args"; search no; };
               dlz their_mysql { database "mysql"; search 1; };""",
            {'dlz': [{'db_args': 'def',
                      'dlz_name': 'my_dlz_1',
                      'search': 'yes'},
                     {'db_args': 'dlopen driver.so args',
                      'dlz_name': 'example',
                      'search': 'yes'},
                     {'db_args': 'dlopen driver.so args',
                      'dlz_name': 'other',
                      'search': 'no'},
                     {'db_args': 'mysql',
                      'dlz_name': 'their_mysql',
                      'search': '1'}]}
        )


if __name__ == '__main__':
    unittest.main()
