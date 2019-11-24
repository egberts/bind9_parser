#!/usr/bin/env python3
"""
File: test_viewzone.py

Description:  Performs unit test on the isc_viewzone.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue, dlz_name_type
from bind9_parser.isc_viewzone import \
    viewzone_stmt_database,\
    viewzone_stmt_dlz,\
    viewzone_statements_set,\
    viewzone_statements_series


class TestViewZone(unittest.TestCase):
    """ Clause View/Zone; things found only under 'view' and 'zone' clause """

    def test_isc_zone_stmt_database_passing(self):
        """ Clause zone; Statement database; passing """
        test_string = [
            'database rbt;',   # default database, Bind9 native red-black tree
            'database MySQL;',
        ]
        result = viewzone_stmt_database.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_zone_stmt_database_failing(self):
        """ Clause zone; Statement database; failing """
        test_string = [
            'databases nosuchdb;',
        ]
        result = viewzone_stmt_database.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


    def test_isc_zone_stmt_database_dict_passing(self):
        assertParserResultDictTrue(
            viewzone_stmt_database,
            'database specialized_highspeed_intensity_tracing_database;',
            {'database': 'specialized_highspeed_intensity_tracing_database'}
        )

    def test_isc_viewzone_stmt_dlz_passing(self):
        """ Clause view/zone; Statement dlz; passing """
        test_string = [
            'dlz my_custom_database;'
        ]
        result = viewzone_stmt_dlz.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            viewzone_stmt_dlz,
            'dlz my_custom_database;',
            {'dlz': 'my_custom_database'}
        )

    def test_isc_viewzone_statements_set_passing(self):
        """ Clause viewzone; Statement statements_set; passing """
        test_string = [
            'dlz custom_MySQL;',
            'database rbt;',
            'dlz MySql;',
        ]
        result = viewzone_statements_set.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_viewzone_statements_set_dict_passing(self):
        assertParserResultDictTrue(
            viewzone_statements_set,
            'dlz custom_MySQL;',
            {'dlz': 'custom_MySQL'}
        )

    def test_isc_viewzone_stmt_statements_set_failing(self):
        """ Clause viewzone; Statement statements_set; failing """
        test_string = [
            '"dlz;";',
        ]
        result = viewzone_statements_set.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


    def test_isc_viewzone_statements_series_passing(self):
        """ Clause viewzone; Statement viewzone_statements_series; passing """
        assertParserResultDictTrue(
            viewzone_statements_series,
            'dlz my_custom_database; dlz custom_MySQL;',
            {'dlz': 'custom_MySQL'}  # only the last one is saved  (1-per-view or 1-per-zone)
        )

    def test_isc_viewzone_stmt_statements_series_failing(self):
        """ Clause viewzone; Statement statements_series; failing """
        test_string = [
            'statements_series "dlz";',
        ]
        result = viewzone_statements_series.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()
