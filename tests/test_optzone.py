#!/usr/bin/env python3
"""
File: test_optzone.py

Description:  Performs unit test on the isc_optzone.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue, assertParserResultDictFalse
from bind9_parser.isc_optzone import \
    optzone_stmt_notify_to_soa,\
    optzone_statements_set,\
    optzone_statements_series


class TestOptionsZone(unittest.TestCase):
    """ Clause Options/Zone; only under 'options' and 'zone' clause """
    def test_isc_optzone_stmt_notify_to_soa_passing(self):
        """ Clause options/zone; Statement notify-to-soa; passing """
        test_string = [
            'notify-to-soa yes;',
            'notify-to-soa no;',
            'notify-to-soa true;',
            'notify-to-soa false;',
            'notify-to-soa 0;',
            'notify-to-soa 1;',
        ]
        result = optzone_stmt_notify_to_soa.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optzone_stmt_notify_to_soa,
            'notify-to-soa yes;',
            {'notify_to_soa': 'yes'}
        )


    def test_isc_optzone_statements_set_passing(self):
        """ Clause optzone; Statement statements_set; passing """
        test_string = [
            'notify-to-soa yes;',
            'notify-to-soa no;',
            'notify-to-soa true;',
            'notify-to-soa false;',
            'notify-to-soa 0;',
            'notify-to-soa 1;',
        ]
        result = optzone_statements_set.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optzone_stmt_statements_set_failing(self):
        assertParserResultDictFalse(
            optzone_statements_set,
            'notify-to-soa wrong;',
            {'notify_to_soa': 'wrong'}
        )

    def test_isc_optzone_statements_series_passing(self):
        """ Clause optzone; Statement optzone_statements_series; passing """
        # Only one 'notify-to-soa' statement allowed in each options or zone clause
        assertParserResultDictTrue(
            optzone_statements_series,
            'notify-to-soa yes;' +
            'notify-to-soa no;',
            {'notify_to_soa': 'no'}
        )

    def test_isc_optzone_stmt_statements_series_failing(self):
        """ Clause optzone; Statement statements_series; failing """
        test_string = [
            'statements_series "YYYY";',
        ]
        result = optzone_statements_series.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()
