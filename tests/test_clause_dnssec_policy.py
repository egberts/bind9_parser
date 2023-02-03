#!/usr/bin/env python3
"""
File: test_clause_dnssec_policy.py

Description:  Performs unit test on the 'dnssec-policy' clause in isc_clause_dnssec_policy.py source file.

    dnssec-policy standard {
        dnskey-ttl 600;
        keys {
            ksk lifetime 365d algorithm ecdsap256sha256;
            zsk lifetime 60d algorithm ecdsap256sha256;
        };
        max-zone-ttl 600;
        parent-ds-ttl 600;
        parent-propagation-delay 2h;
        publish-safety 7d;
        retire-safety 7d;
        signatures-refresh 5d;
        signatures-validity 15d;
        signatures-validity-dnskey 15d;
        zone-propagation-delay 2h;
    };
"""

import unittest
from bind9_parser.isc_utils import assert_parser_result_dict_true
from bind9_parser.isc_clause_dnssec_policy import \
    dnssecpolicy_dnskey_ttl_element, dnssecpolicy_keys_element, \
    dnssecpolicy_max_zone_ttl_element, dnssecpolicy_parent_ds_ttl_element, \
    dnssecpolicy_parent_propagation_delay_element, \
    dnssecpolicy_publish_safety_element, dnssecpolicy_retire_safety_element, \
    dnssecpolicy_signatures_refresh_element, \
    dnssecpolicy_signatures_validity_element, \
    dnssecpolicy_signatures_validity_dnskey_element, \
    dnssecpolicy_zone_propagation_delay_element, \
    clause_stmt_dnssecpolicy_set, clause_stmt_dnssecpolicy_series


class TestClauseDnssecPolicy(unittest.TestCase):
    """ Test Clause DNSSEC Policy """

    def test_dnssecpolicy_dnskey_ttl_passing(self):
        """ Test Clause DNSSEC Policy; DNSKEY TTL; passing """
        test_string = 'dnskey-ttl 1h;'
        expected_result = {'dnskey_ttl': '1h'}
        assert_parser_result_dict_true(
            dnssecpolicy_dnskey_ttl_element,
            test_string,
            expected_result)

    def test_dnssecpolicy_keys_passing(self):
        """ Test Clause DNSSEC Policy; DNSKEY TTL; passing """
        test_string = 'keys { csk lifetime 1d algorithm SHA256 256; };'
        expected_result = {
            'keys': [
                {
                    'algorithm': {
                        'algorithm_name': 'SHA256',
                        'algorithm_size': '256'},
                    'lifetime': {'iso8601_duration': '1d'},
                    'type': 'csk'}]}
        assert_parser_result_dict_true(
            dnssecpolicy_keys_element,
            test_string,
            expected_result)

    def test_dnssecpolicy_max_zone_ttl_passing(self):
        """ Test Clause DNSSEC Policy; DNSKEY TTL; passing """
        test_string = 'max-zone-ttl 1w;'
        expected_result = {'max_zone_ttl': '1w'}
        assert_parser_result_dict_true(
            dnssecpolicy_max_zone_ttl_element,
            test_string,
            expected_result)

    def test_dnssecpolicy_parent_ds_ttl_passing(self):
        """ Test Clause DNSSEC Policy; DNSKEY TTL; passing """
        test_string = 'parent-ds-ttl 1w3d;'
        expected_result = {'parent_ds_ttl': '1w3d'}
        assert_parser_result_dict_true(
            dnssecpolicy_parent_ds_ttl_element,
            test_string,
            expected_result)

    def test_dnssecpolicy_parent_propagation_delay_passing(self):
        """ Test Clause DNSSEC Policy; DNSKEY TTL; passing """
        test_string = 'parent-propagation-delay 1h5m35s;'
        expected_result = {'parent_propagation_delay': '1h5m35s'}
        assert_parser_result_dict_true(
            dnssecpolicy_parent_propagation_delay_element,
            test_string,
            expected_result)

    def test_dnssecpolicy_publish_safety_passing(self):
        """ Test Clause DNSSEC Policy; DNSKEY TTL; passing """
        test_string = 'publish-safety 5d16h;'
        expected_result = {'publish_safety': '5d16h'}
        assert_parser_result_dict_true(
            dnssecpolicy_publish_safety_element,
            test_string,
            expected_result)

    def test_dnssecpolicy_retire_safety_passing(self):
        """ Test Clause DNSSEC Policy; DNSKEY TTL; passing """
        test_string = 'retire-safety 3h30m;'
        expected_result = {'retire_safety': '3h30m'}
        assert_parser_result_dict_true(
            dnssecpolicy_retire_safety_element,
            test_string,
            expected_result)

    def test_dnssecpolicy_signatures_refresh_passing(self):
        """ Test Clause DNSSEC Policy; DNSKEY TTL; passing """
        test_string = 'signatures-refresh 4d;'
        expected_result = {'signatures_refresh': '4d'}
        assert_parser_result_dict_true(
            dnssecpolicy_signatures_refresh_element,
            test_string,
            expected_result)

    def test_dnssecpolicy_signatures_validity_passing(self):
        """ Test Clause DNSSEC Policy; DNSKEY TTL; passing """
        test_string = 'signatures-validity 1D8H;'
        expected_result = {'signatures_validity': '1D8H'}
        assert_parser_result_dict_true(
            dnssecpolicy_signatures_validity_element,
            test_string,
            expected_result)

    def test_dnssecpolicy_signatures_validity_dnskey_passing(self):
        """ Test Clause DNSSEC Policy; DNSKEY TTL; passing """
        test_string = 'signatures-validity-dnskey 2D16H31M;'
        expected_result = {'signatures_validity_dnskey': '2D16H31M'}
        assert_parser_result_dict_true(
            dnssecpolicy_signatures_validity_dnskey_element,
            test_string,
            expected_result)

    def test_dnssecpolicy_zone_propagation_delay_passing(self):
        """ Test Clause DNSSEC Policy; DNSKEY TTL; passing """
        test_string = 'zone-propagation-delay 30S;'
        expected_result = {'zone_propagation_delay': '30S'}
        assert_parser_result_dict_true(
            dnssecpolicy_zone_propagation_delay_element,
            test_string,
            expected_result)

    def test_clause_stmt_dnssecpolicy_set_passing(self):
        """ Test Clause DNSSEC Policy; DNSKEY TTL; passing """
        test_string = """
dnssec-policy strict {
    keys { csk lifetime 1d algorithm SHA256 256; };
    keys { ksk "/var/lib/named/primary/dnssec.key" lifetime 365D algorithm SHA386 386; };
    };"""
        assert_parser_result_dict_true(
            clause_stmt_dnssecpolicy_set,
            test_string,
            {'dnssec_policy': [{'dnssec_policy_name': 'strict',
                                'keys': [{'algorithm': {'algorithm_name': 'SHA256',
                                                        'algorithm_size': '256'},
                                          'lifetime': {'iso8601_duration': '1d'},
                                          'type': 'csk'},
                                         {'algorithm': {'algorithm_name': 'SHA386',
                                                        'algorithm_size': '386'},
                                          'key_directory': '/var/lib/named/primary/dnssec.key',
                                          'lifetime': {'iso8601_duration': '365D'},
                                          'type': 'ksk'}]}]}
        )

    def test_clause_stmt_dnssecpolicy_series_passing(self):
        """ Test Clause DNSSEC Policy; DNSKEY TTL; passing """

        assert_parser_result_dict_true(
            clause_stmt_dnssecpolicy_series,
            """
dnssec-policy standard {
    keys { ksk lifetime 365d algorithm SHA256; };
    keys { zsk lifetime 30d algorithm SHA256 256; };
    keys { csk lifetime 1d algorithm SHA256; };
    };
dnssec-policy exlax {
    keys { csk lifetime 365d algorithm SHA128; };
    };
dnssec-policy enterprise {
    keys { zsk lifetime 4y algorithm SHA386; };
    keys { csk lifetime 4y algorithm SHA386; };
    };
    """,
            {'dnssec_policy': [{'dnssec_policy_name': 'standard',
                                'keys': [{'algorithm': {'algorithm_name': 'SHA256'},
                                          'lifetime': {'iso8601_duration': '365d'},
                                          'type': 'ksk'},
                                         {'algorithm': {'algorithm_name': 'SHA256',
                                                        'algorithm_size': '256'},
                                          'lifetime': {'iso8601_duration': '30d'},
                                          'type': 'zsk'},
                                         {'algorithm': {'algorithm_name': 'SHA256'},
                                          'lifetime': {'iso8601_duration': '1d'},
                                          'type': 'csk'}]},
                               {'dnssec_policy_name': 'exlax',
                                'keys': [{'algorithm': {'algorithm_name': 'SHA128'},
                                          'lifetime': {'iso8601_duration': '365d'},
                                          'type': 'csk'}]},
                               {'dnssec_policy_name': 'enterprise',
                                'keys': [{'algorithm': {'algorithm_name': 'SHA386'},
                                          'lifetime': {'iso8601_duration': '4y'},
                                          'type': 'zsk'},
                                         {'algorithm': {'algorithm_name': 'SHA386'},
                                          'lifetime': {'iso8601_duration': '4y'},
                                          'type': 'csk'}]}]}
)


if __name__ == '__main__':
    unittest.main()
