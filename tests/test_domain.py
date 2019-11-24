#!/usr/bin/env python3
"""
File: test_domain.py

Description:  Performs unit test on the isc_domain.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue, assertParserResultDictFalse
from bind9_parser.isc_domain import tld_label, domain_label, subdomain_label,\
    host_name, domain_fqdn, domain_generic_label,\
    domain_generic_fqdn, rr_domain_name_or_wildcard_type, rr_domain_name_type, rr_fqdn_w_absolute


class TestDomain(unittest.TestCase):
    """ Element Domain """

    def test_isc_domain_tld_label_passing(self):
        """ Element Domain; Label TLD Domain Type, passing mode """
        test_data = [
            'com',
            'nz',
            'org',
            'net',
            'rock',
            'museum',
        ]
        result = tld_label.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_domain_tld_label_failing(self):
        """ Element Domain; Label TLD Domain Type, failing mode """
        test_data = [
            'c0m',
        ]
        result = tld_label.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_domain_domain_label_passing(self):
        """ Element domain, Label Domain, passing mode """
        test_data = [
            'abc',
            'd-f',
            'g-ij',
            'l-mn-o',
            'p-rs-tu01',
            'averylongtld',
        ]
        result = domain_label.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_domain_domain_label_failing(self):
        """ Element domain, Label Domain, failing mode """
        test_data = [
            'exampl)',
        ]
        result = domain_label.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_domain_subdomain_label_passing(self):
        """ Element domain, Label Subdomain, passing mode """
        test_data = [
            'example',
        ]
        result = subdomain_label.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_domain_subdomain_label_failing(self):
        """ Element domain, Label Subdomain, failing mode """
        test_data = [
            'example,',
        ]
        result = subdomain_label.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_domain_domain_generic_label_passing(self):
        """ Element domain, Label Generic Domain, passing mode """
        test_data = [
            '_exa-mple',
        ]
        result = domain_generic_label.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_domain_domain_generic_label_failing(self):
        """ Element domain; Type hostname Name, failing mode """
        test_data = [
            '_exa-mple&',
        ]
        result = domain_generic_label.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_domain_domain_fqdn_passing(self):
        """ Element domain, Type Fully-Qualified Domain Name, passing mode"""
        test_data = [
            'abc',
            'def.net',
            'www.hij.net',
            'proxy1.www.klm.net',
            'aaa.proxy1.www.nop.net',
            'a.proxy1.www.qrs.net',
            '_965._tcp.example.net',
            'abc.be.ca.o.p.q.r.s.t.u.v.w.x.y.z.jobs.com',
            'a.b.ca.o.p.q.r.s.t.u.v.w.x.y.z.jobs.com',
            '_x53.tcp.example.net',
            '_53.tcp.example.net',
        ]
        result = domain_fqdn.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_domain_domain_fqdn_failing(self):
        """ Element domain, Type Fully-Qualified Domain Name, failing mode"""
        test_data = [
            '_965,_tcp.example.net',
        ]
        result = domain_fqdn.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_domain_domain_generic_fqdn_passing(self):
        """ Element domain; Type Generic FQDN; passing mode """
        test_data = [
            '_965._tcp.example.net',
        ]
        result = domain_generic_fqdn.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_domain_domain_generic_fqdn_failing(self):
        """ Element domain; Type Generic FQDN; failing mode """
        test_data = [
            '_965._tcp.example/net',
            '"_965._tcp.example/net"',
            "'_965._tcp.example/net'",
        ]
        result = domain_generic_fqdn.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_domain_rr_name_passing(self):
        """ Element domain; Type Resource-Record Name, passing mode """
        test_data = [
            '_965._tcp.example.net.',
        ]
        result = rr_domain_name_type.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_domain_rr_name_failing(self):
        """ Element domain; Type Resource-Record Name, failing mode """
        test_data = [
            '_965._tcp;example.net.',
        ]
        result = rr_domain_name_type.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_domain_rr_target_name_passing(self):
        """ Element domain; Type Target Resource-Record Name, passing mode """
        test_data = [
            '_965._tcp.example.net',
        ]
        result = rr_domain_name_or_wildcard_type.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_domain_rr_target_name_failing(self):
        """ Element domain; Type Target Resource-Record Name, failing mode """
        test_data = [
            '_965.&tcp.example.net',
        ]
        result = rr_domain_name_or_wildcard_type.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_domain_hostname_passing(self):
        """ Element domain; Type hostname Name, passing mode """
        test_data = [
            'a',      # Most OS-impose a minimum char-length of 3
            'cd',     # Most OS-impose a minimum char-length of 3
            'efg',
            'h-j',
            'plainhostname',
            'dashed-hostname',
            'multiple-hyphenated-hostname',
        ]
        result = host_name.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_domain_hostname_failing(self):
        """Domain clause, Hostname, failing mode"""
        test_data = [
            '-hostname',
            'hostname-',
            'hostname-.domain',  # MUST FAIL THIS
            'hostname.-domain',  # MUST FAIL THIS
            'hostname-.-domain',  # MUST FAIL THIS
            'hostname.-domain-',  # MUST FAIL THIS
            'hostname.domain',  # MUST FAIL THIS
        ]
        result = host_name.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()
