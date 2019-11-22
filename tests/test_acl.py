#!/usr/bin/env python3
"""
File: test_acl.py

Title: Test ACL

Description:  Performs unit test on the isc_acl.py source file.
"""

import unittest
from isc_acl import acl_geoip_country_element,\
    acl_geoip_group, acl_geoip_element


class TestACL(unittest.TestCase):
    """ Clause ACL, GeoIP element """

    def test_isc_acl_geoip_country_element_passing(self):
        """ACL clause, GeoIP element, country group, passing mode"""
        test_data = [
            'country us',
            'country US',
            'Country NZ',
            'COUNTRY JAP',
            ]
        result = acl_geoip_country_element.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_acl_geoip_group_passing(self):
        """ACL clause, GeoIP element group, passing mode"""
        test_data = [
            'country us',
            'region sierra',
            'city Boston',
            'continent Africa',
            'postal 20001',
            'metro inland',
            'area 916',
            'tz Eastern/US',
            'isp Verizon',
            'org Goodwill',
            'asnum AS411',
            'domain example.com',
            'netspeed 150000000',
        ]
        result = acl_geoip_group.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_acl_geoip_inet_allow_failing(self):
        test_data = [
            'deny { 127.0.0.2;}',
            'deny { }',
        ]
        result = acl_geoip_country_element.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_acl_geoip_inet_group_failing(self):
        """GeoIP clause, inet group element, purposely failing mode"""
        test_data = [
            '* & port 954 allow { 127.0.0.2; 127.0.0.3;} keys { public-rndc-key; };',
            '* * p0rt 954 allow { 127.0.0.2; 127.0.0.3;} keys { public-rndc-key; };',
            '* * port -954 allow { 127.0.0.2; 127.0.0.3;} keys { public-rndc-key; };',
            '* * port 954 disallow { 127.0.0.2; 127.0.0.3;} keys { public-rndc-key; };',
            '* * port 954 allow 127.0.0.2; 127.0.0.3; keys { public-rndc-key; };',
            '* * port 954 allow { hostname; 127.0.0.3;} keys { public-rndc-key; };',
            '* * port 954 allow { 127.0.0.2; 127.0.0.3;} masterkeys { public-rndc-key; };',
            '* * port 954 allow { 127.0.0.2; 127.0.0.3;} keys { public&-rndc-key; };',
            '* * port 954 allow { 127.0.0.2; 127.0.0.3;} keys { public&-rndc-key; }',
        ]
        result = acl_geoip_element.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()
