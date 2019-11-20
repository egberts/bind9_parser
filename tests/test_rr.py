#!/usr/bin/env python3
"""
File: test_rr.py

Description:  Performs unit test on the isc_rr.py source file.
"""

import unittest
from isc_utils import assertParserResultDictTrue
from isc_rr import \
    rr_fqdn_w_absolute,\
    rr_type_list_series,\
    rr_domain_name_or_root,\
    rr_domain_name,\
    rr_domain_name_or_wildcard,\
    rr_class_any,\
    rr_class_in,\
    rr_class_hesiod,\
    rr_type_a, \
    rr_type_aaaa,\
    rr_type_ns, \
    rr_class_set,\
    rr_type_set,\
    rr_type_series


class TestResourceRecords(unittest.TestCase):
    """ Element Resource Records """
    def test_isc_rr_class_any_passing(self):
        """ Element resource records; Set Class, Any; passing """
        test_string = [
            'any',
            'ANY',
        ]
        result = rr_class_set.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            rr_class_set,
            'any',
            {'rr_class': 'ANY'}
        )

    def test_isc_rr_type_a_passing(self):
        """ Element resource records; Type rr_type_a; passing """
        test_string = [
            'a',
            'A',
        ]
        result = rr_type_a.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_rr_type_set_passing(self):
        """ Clause rr; Statement rr_type_set; passing """
        test_string = [
            'a',
            'MX',
            'OPENPGPKEY',
        ]
        result = rr_type_set.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            rr_type_set,
            'srv',
            {'rr_type': 'SRV'}
        )

    def test_isc_rr_type_set_failing(self):
        """ Clause rr; Statement rr_type; failing """
        test_string = [
            'oops',
        ]
        result = rr_type_set.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


    def test_isc_rr_type_series_passing(self):
        """ Clause rr; Series Type; passing """
        test_string = [
            'A',
            'a',
            'SRV',
            'srv',
            'ns',
            'NS',
            'MX',
            'OPENPGPKEY',
            'A mx OPENPGPKEY',
        ]
        result = rr_type_series.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            rr_type_series,
            'A NS SRV',
            {'rr_types': ['A', 'NS', 'SRV']}
        )

if __name__ == '__main__':
    unittest.main()
