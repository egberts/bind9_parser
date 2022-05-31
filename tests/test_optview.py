#!/usr/bin/env python3
"""
File: test_optview.py

Description:  Performs unit test on the isc_optview.py source file.
"""

import unittest
from bind9_parser.isc_utils import assert_parser_result_dict_true, assert_parser_result_dict_false
from bind9_parser.isc_optview import \
    optview_stmt_acache_cleaning_interval, \
    optview_stmt_acache_enable, \
    optview_stmt_additional_from_auth, \
    optview_stmt_additional_from_cache, \
    optview_stmt_allow_new_zones, \
    optview_stmt_allow_query_cache_on, \
    optview_stmt_allow_query_cache, \
    optview_stmt_allow_recursion_on, \
    optview_stmt_allow_recursion, \
    optview_stmt_attach_cache, \
    optview_stmt_auth_nxdomain, \
    optview_stmt_cache_file, \
    optview_stmt_check_dup_records, \
    optview_stmt_check_integrity, \
    optview_stmt_check_mx_cname, \
    optview_stmt_check_mx, \
    optview_stmt_check_names, \
    optview_stmt_check_spf, \
    optview_stmt_check_srv_cname, \
    optview_stmt_check_wildcard, \
    optview_stmt_cleaning_interval, \
    optview_stmt_disable_algorithms, \
    optview_stmt_disable_ds_digests, \
    optview_multiple_stmt_disable_algorithms, \
    optview_multiple_stmt_disable_ds_digests, \
    optview_multiple_stmt_disable_algorithms, \
    optview_stmt_disable_ds_digests, \
    optview_stmt_disable_empty_zone, \
    optview_stmt_dns64, \
    optview_stmt_dns64_contact, \
    optview_stmt_dns64_server, \
    optview_stmt_dnsrps_enable, \
    optview_stmt_dnsrps_options, \
    optview_stmt_dnssec_accept_expired, \
    optview_stmt_dnssec_enable, \
    optview_stmt_dnssec_lookaside, \
    optview_stmt_dnssec_must_be_secure, \
    optview_stmt_dnssec_validation, \
    optview_stmt_dnstap, \
    optview_stmt_dual_stack_servers, \
    optview_stmt_empty_contact, \
    optview_stmt_empty_zones_enable, \
    optview_stmt_fetch_glue, \
    optview_stmt_fetch_quota_params, \
    optview_stmt_fetches_per_zone, \
    optview_stmt_fetches_per_server, \
    optview_stmt_files, \
    optview_stmt_heartbeat_interval, \
    optview_stmt_hostname, \
    optview_stmt_ipv4only_contact,\
    optview_stmt_ipv4only_enable,\
    optview_stmt_ipv4only_server, \
    optview_stmt_lame_ttl, \
    optview_stmt_lmdb_mapsize, \
    optview_stmt_managed_keys_directory, \
    optview_stmt_max_cache_size, \
    optview_stmt_max_cache_ttl, \
    optview_stmt_max_ncache_ttl, \
    optview_stmt_max_recursion_depth, \
    optview_stmt_max_recursion_queries, \
    optview_stmt_max_stale_ttl, \
    optview_stmt_max_udp_size, \
    optview_stmt_max_zone_ttl, \
    optview_stmt_message_compression, \
    optview_stmt_minimal_responses, \
    optview_stmt_no_case_compress, \
    optview_stmt_notify_rate, \
    optview_stmt_parental_source,\
    optview_stmt_parental_source_v6,\
    optview_stmt_preferred_glue, \
    optview_stmt_qname_minimization, \
    optview_stmt_query_source_v6, \
    optview_stmt_query_source, \
    optview_stmt_rate_limit, \
    optview_stmt_recursion, \
    optview_stmt_response_policy_zone_group_set, \
    optview_stmt_response_policy_global_element_set, \
    optview_stmt_response_policy, \
    optview_stmt_rfc2308_type1, \
    optview_stmt_root_delegation_only, \
    optview_rrset_order_group_series, \
    optview_stmt_rrset_order, \
    optview_stmt_sortlist, \
    optview_stmt_servfail_ttl, \
    optview_stmt_stale_answer_client_timeout, \
    optview_stmt_stale_answer_enable, \
    optview_stmt_stale_answer_ttl, \
    optview_stmt_stale_cache_enable, \
    optview_stmt_stale_refresh_time, \
    optview_stmt_suppress_initial_notify, \
    optview_stmt_synth_from_dnssec, \
    optview_stmt_trust_anchor_telemetry, \
    optview_stmt_v6_bias, \
    optview_stmt_validate_except, \
    optview_stmt_zero_no_soa_ttl_cache, \
    optview_statements_set, \
    optview_statements_series


class TestOptionsView(unittest.TestCase):
    """ Clause Options/View; things found only under 'options' and 'view' clause """

    def test_isc_optview_stmt_acache_cleaning_interval_passing(self):
        """ Clause options/view; Statement acache-cleaning-interval; passing """
        test_string = [
            'acache-cleaning-interval yes;'
        ]
        result = optview_stmt_acache_cleaning_interval.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_acache_cleaning_interval,
            'acache-cleaning-interval no;',
            {'acache_cleaning_interval': 'no'}
        )

    def test_isc_optview_stmt_acache_enable_passing(self):
        """ Clause options/view; Statement acache-enable; passing """
        test_string = [
            'acache-enable yes;'
        ]
        result = optview_stmt_acache_enable.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_acache_enable,
            'acache-enable no;',
            {'acache_enable': 'no'}
        )

    def test_isc_optview_stmt_additional_from_auth_passing(self):
        """ Clause options/view; Statement additional-from-auth; passing """
        test_string = [
            'additional-from-auth yes;'
        ]
        result = optview_stmt_additional_from_auth.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_additional_from_auth,
            'additional-from-auth True;',
            {'additional_from_auth': 'True'}
        )

    def test_isc_optview_stmt_additional_from_cache_passing(self):
        """ Clause options/view; Statement additional-from-cache; passing """
        test_string = [
            'additional-from-cache yes;'
        ]
        result = optview_stmt_additional_from_cache.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_additional_from_cache,
            'additional-from-cache False;',
            {'additional_from_cache': 'False'}
        )

    def test_isc_optview_stmt_allow_new_zones_passing(self):
        """ Clause options/view; Statement additional-from-cache; passing """
        test_string = [
            'allow-new-zones 0;'
        ]
        result = optview_stmt_allow_new_zones.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_allow_new_zones,
            'allow-new-zones 1;',
            {'allow_new_zones': '1'}
        )

    def test_isc_optview_stmt_allow_query_cache_on_passing(self):
        """ Clause options/view; Statement allow-query-cache-on; passing """
        test_string = [
            'allow-query-cache-on { localnets; localhost; };'
        ]
        result = optview_stmt_allow_query_cache_on.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_allow_query_cache_on,
            'allow-query-cache-on { localnets; localhost; };',
            {'allow_query_cache_on': {'aml': [{'keyword': 'localnets'},
                                              {'keyword': 'localhost'}]}}
        )

    def test_isc_optview_stmt_allow_query_cache_passing(self):
        """ Clause options/view; Statement allow-query-cache; passing """
        test_string = [
            'allow-query-cache { localnets; localhost; };'
        ]
        result = optview_stmt_allow_query_cache.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_allow_query_cache,
            'allow-query-cache { localnets; localhost; };',
            {'allow_query_cache': {'aml': [{'keyword': 'localnets'},
                                           {'keyword': 'localhost'}]}}
        )

    def test_isc_optview_stmt_allow_recursion_on_passing(self):
        """ Clause options/view; Statement allow-recursion-on; passing """
        test_string = [
            'allow-recursion-on { any; };'
        ]
        result = optview_stmt_allow_recursion_on.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_allow_recursion_on,
            'allow-recursion-on { any; };',
            {'allow-recursion-on': {'aml': [{'keyword': 'any'}]}}
        )

    def test_isc_optview_stmt_allow_recursion_passing(self):
        """ Clause options/view; Statement allow-recursion; passing """
        test_string = [
            'allow-recursion { localnets; localhost; };'
        ]
        result = optview_stmt_allow_recursion.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_allow_recursion,
            'allow-recursion { localnets; localhost; };',
            {'allow-recursion': {'aml': [{'keyword': 'localnets'},
                                         {'keyword': 'localhost'}]}}
        )

    def test_isc_optview_stmt_attach_cache_passing(self):
        """ Clause options/view; Statement attach-cache; passing """
        test_string = [
            'attach-cache hot_view;'
        ]
        result = optview_stmt_attach_cache.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optview_stmt_attach_cache_2_passing(self):
        """ Clause options/view; Statement attach-cache 2; passing """
        assert_parser_result_dict_true(
            optview_stmt_attach_cache,
            'attach-cache dmz_view;',
            {'attach_cache': 'dmz_view'}
        )

    def test_isc_optview_stmt_attach_cache_2_failing(self):
        """ Clause options/view; Statement attach-cache 2; failing """
        assert_parser_result_dict_false(
            optview_stmt_attach_cache,
            'attach-cache ***not_a_view_name***;',
            {'attach_cache': 'dmz_view'}
        )

    def test_isc_optview_stmt_auth_nxdomain_passing(self):
        """ Clause options/view; Statement auth-nxdomain; passing """
        test_string = [
            'auth-nxdomain yes;'
        ]
        result = optview_stmt_auth_nxdomain.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_auth_nxdomain,
            'auth-nxdomain no;',
            {'auth_nxdomain': 'no'}
        )

    def test_isc_optview_stmt_cache_file_passing(self):
        """ Clause options/view; Statement cache-file; passing """
        test_string = [
            'cache-file "/tmp/junk";'
        ]
        result = optview_stmt_cache_file.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_cache_file,
            'cache-file "/dev/null";',
            {'cache_file': '/dev/null'}
        )

    def test_isc_optview_stmt_check_dup_records_passing(self):
        """ Clause options/view; Statement check-dup-records; passing """
        test_string = [
            'check-dup-records warn;',
            'check-dup-records fail;',
            'check-dup-records ignore;',
        ]
        result = optview_stmt_check_dup_records.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_check_dup_records,
            'check-dup-records ignore;',
            {'check_dup_records': 'ignore'}
        )

    def test_isc_optview_stmt_check_integrity_passing(self):
        """ Clause options/view; Statement check-integrity; passing """
        test_string = [
            'check-integrity yes;',
            'check-integrity False;',
            'check-integrity 1;',
        ]
        result = optview_stmt_check_integrity.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_check_integrity,
            'check-integrity no;',
            {'check_integrity': 'no'}
        )

    def test_isc_optview_stmt_check_mx_cname_passing(self):
        """ Clause options/view; Statement check-mx-cname; passing """
        test_string = [
            'check-mx-cname ignore;',
            'check-mx-cname warn;',
            'check-mx-cname fail;',
        ]
        result = optview_stmt_check_mx_cname.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_check_mx_cname,
            'check-mx-cname fail;',
            {'check_mx_cname': 'fail'}
        )

    def test_isc_optview_stmt_check_mx_passing(self):
        """ Clause options/view; Statement check-mx; passing """
        test_string = [
            'check-mx ignore;',
            'check-mx warn;',
            'check-mx fail;',
        ]
        result = optview_stmt_check_mx.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_check_mx,
            'check-mx warn;',
            {'check_mx': 'warn'}
        )

    def test_isc_optview_stmt_check_names_passing(self):
        """ Clause options/view; Statement check-names; passing """
        test_string = [
            'check-names master warn;',
            'check-names slave fail;',
            'check-names response ignore;',
        ]
        result = optview_stmt_check_names.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_check_names,
            'check-names slave ignore;',
            {'check_names': [{'result_status': 'ignore',
                              'zone_type': 'slave'}]}
        )

    def test_isc_optview_stmt_check_spf_passing(self):
        """ Clause options/view; Statement check-spf; passing """
        test_string = [
            'check-spf ignore;'
        ]
        result = optview_stmt_check_spf.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_check_spf,
            'check-spf fail;',
            {'check_spf': 'fail'}
        )

    def test_isc_optview_stmt_check_srv_cname_passing(self):
        """ Clause options/view; Statement check-srv-cname; passing """
        test_string = [
            'check-srv-cname fail;'
        ]
        result = optview_stmt_check_srv_cname.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_check_srv_cname,
            'check-srv-cname warn;',
            {'check_srv_cname': 'warn'}
        )

    def test_isc_optview_stmt_check_wildcard_passing(self):
        """ Clause options/view; Statement check-wildcard; passing """
        test_string = [
            'check-wildcard yes;'
        ]
        result = optview_stmt_check_wildcard.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_check_wildcard,
            'check-wildcard no;',
            {'check_wildcard': 'no'}
        )

    def test_isc_optview_stmt_cleaning_interval_passing(self):
        """ Clause options/view; Statement cleaning-interval; passing """
        test_string = [
            'cleaning-interval 3600;'
        ]
        result = optview_stmt_cleaning_interval.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_cleaning_interval,
            'cleaning-interval 480;',
            {'cleaning_interval': 480}
        )

    def test_isc_optview_stmt_optview_stmt_disable_empty_zone(self):
        """ Clause options/view; Statement 'optview_stmt_disable_empty_zone'; passing """
        assert_parser_result_dict_true(
            optview_stmt_disable_empty_zone,
            'disable-empty-zone "127.in-addr.arpa";',
            {'disable_empty_zone': [{'zone_name': '127.in-addr.arpa'}]}
        )

    def test_isc_optview_stmt_optview_stmt_dns64_passing(self):
        """ Clause options/view; Statement 'optview_stmt_dns64'; passing """
        assert_parser_result_dict_true(
            optview_stmt_dns64,
            """
dns64 64:ff9b::/96 { 
    break-dnssec yes;
    recursive-only no;
    clients { 127.0.0.1; };
    exclude { 127.0.0.1; };
    mapped   { 127.0.0.1; };
    };""",
            {'dns64': [{'aml': [{'ip4_addr': '127.0.0.1'}],
                        'break_dnssec': 'yes',
                        'clients': [{'ip4_addr': '127.0.0.1'}],
                        'exclude': [{'ip4_addr': '127.0.0.1'}],
                        'mapped': [{'ip4_addr': '127.0.0.1'}],
                        'netprefix': {'ip6_addr': '64:ff9b::',
                                      'prefix': '96'},
                        'recursive_only': 'no'}]}
        )

    def test_isc_optview_stmt_disable_algorithms_passing(self):
        """ Clause options/view; Statement disable-algorithms; passing """
        test_string = [
            'disable-algorithms "example." { RSASHA512; };',
            'disable-algorithms "example.test." { RSASHA512; AES512; };',
            'disable-algorithms "www.example.test." { RSASHA512; AES512; ED25519; };',
        ]
        result = optview_stmt_disable_algorithms.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optview_stmt_disable_algorithms_series_passing(self):
        """ Clause options/view; Statement disable-algorithms series; passing """
        assert_parser_result_dict_true(
            optview_multiple_stmt_disable_algorithms,
            """disable-algorithms "example." { RSASHA512; };
disable-algorithms "example.test." { RSASHA512; AES512; };
disable-algorithms "www.example.test." { RSASHA512; AES512; ED25519; };""",
            {'disable_algorithms': [{'algorithms': ['RSASHA512'],
                                     'domain_name': 'example.'},
                                    {'algorithms': ['RSASHA512', 'AES512'],
                                     'domain_name': 'example.test.'},
                                    {'algorithms': ['RSASHA512',
                                                    'AES512',
                                                    'ED25519'],
                                     'domain_name': 'www.example.test.'}]}
        )

    def test_isc_optview_stmt_disable_algorithms_2_passing(self):
        assert_parser_result_dict_true(
            optview_stmt_disable_algorithms,
            'disable-algorithms . { sha512; cbc32; };',
            {'disable_algorithms': {'algorithms': ['sha512', 'cbc32'],
                                    'domain_name': '.'}}
        )

    def test_isc_optview_stmt_disable_algorithms_2a_passing(self):
        assert_parser_result_dict_true(
            optview_stmt_disable_algorithms,
            'disable-algorithms "example.com." { sha512; };',
            {'disable_algorithms': {'algorithms': ['sha512'],
                                    'domain_name': 'example.com.'}}
        )

    def test_isc_optview_stmt_disable_algorithms_3_passing(self):
        assert_parser_result_dict_true(
            optview_stmt_disable_algorithms,
            'disable-algorithms \'172.in-addr.arpa.\' { aes256; sha-1; rsa; };',
            {'disable_algorithms': {'algorithms': ['aes256',
                                                   'sha-1',
                                                   'rsa'],
                                    'domain_name': '172.in-addr.arpa.'}}
        )

    def test_isc_optview_stmt_disable_algorithms_4_passing(self):
        assert_parser_result_dict_true(
            optview_multiple_stmt_disable_algorithms,
            'disable-algorithms example.com { sha512; cbc32; }; disable-algorithms yahoo.com { cbc128; };',
            {'disable_algorithms': [{'algorithms': ['sha512', 'cbc32'],
                                     'domain_name': 'example.com'},
                                    {'algorithms': ['cbc128'],
                                     'domain_name': 'yahoo.com'}]}
        )

    def test_isc_optview_stmt_part_disable_ds_digests_1_passing(self):
        assert_parser_result_dict_true(
            optview_stmt_disable_ds_digests,
            'disable-ds-digests example.com { hmac; cbc32; };',
            {'disable_ds_digests': [{'algorithm_name': ['hmac', 'cbc32'],
                                     'domain_name': 'example.com'}]}
            )

    def test_isc_optview_stmt_part_disable_ds_digests_passing(self):
        assert_parser_result_dict_true(
            optview_multiple_stmt_disable_ds_digests,
            'disable-ds-digests example.com { hmac; cbc32; };'
            'disable-ds-digests bing.com { crc32; };',
            {'disable_ds_digests': [{'algorithm_name': ['hmac', 'cbc32'],
                                     'domain_name': 'example.com'},
                                    {'algorithm_name': ['crc32'],
                                     'domain_name': 'bing.com'},
                                    [{'algorithm_name': ['hmac', 'cbc32'],
                                      'domain_name': 'example.com'},
                                     {'algorithm_name': ['crc32'],
                                      'domain_name': 'bing.com'}]]}
            )

    def test_isc_optview_stmt_disable_empty_zone_passing(self):
        """ Clause options/view; Statement disable-empty-zone; passing """
        test_string = [
            'disable-empty-zone ".";',
            'disable-empty-zone 168.192.in-addr.arpa.;',
            'disable-empty-zone "example.com";',
        ]
        result = optview_stmt_disable_empty_zone.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_disable_empty_zone,
            'disable-empty-zone ".";',
            {'disable_empty_zone': [{'zone_name': '.'}]}
        )
        assert_parser_result_dict_true(
            optview_stmt_disable_empty_zone,
            'disable-empty-zone example.com.;',
            {'disable_empty_zone': [{'zone_name': 'example.com.'}]}
        )

    def test_isc_optview_stmt_dns64_contact_passing(self):
        """ Clause options/view; Statement 'dns64-contact'; passing """
        assert_parser_result_dict_true(
            optview_stmt_dns64_contact,
            'dns64-contact johndoe.example.test;',
            {'dns64_contact': {'soa_rname': 'johndoe.example.test'}}
        )

    def test_isc_optview_stmt_dns64_server_passing(self):
        """ Clause options/view; Statement 'dns64-server'; passing """
        assert_parser_result_dict_true(
            optview_stmt_dns64_server,
            'dns64-server johndoe.example.test;',
            {'dns64_server': {'soa_rname': 'johndoe.example.test'}}
        )

    def test_isc_optview_stmt_dnsrps_enable_passing(self):
        """ Clause options/view; Statement 'dnsrps-enable'; passing """
        assert_parser_result_dict_true(
            optview_stmt_dnsrps_enable,
            'dnsrps-enable yes;',
            {'dnsrps_enable': 'yes'}
        )

    def test_isc_optview_stmt_dnsrps_options_passing(self):
        """ Clause options/view; Statement 'dnsrps-options'; passing """
        assert_parser_result_dict_true(
            optview_stmt_dnsrps_options,
            'dnsrps-options { "gee whiz, fancy stuff goes here"; };',
            {'dnsrps_options': ['gee whiz, fancy stuff goes here']}
        )

    def test_isc_optview_stmt_dnssec_accept_expired_passing(self):
        """ Clause options/view; Statement dnssec-accept-expired; passing """
        assert_parser_result_dict_true(
            optview_stmt_dnssec_accept_expired,
            'dnssec-accept-expired False;',
            {'dnssec_accept_expired': 'False'}
        )

    def test_isc_optview_stmt_dnssec_enable_passing(self):
        """ Clause options/view; Statement dnssec-enable; passing """
        test_string = [
            'dnssec-enable yes;'
        ]
        result = optview_stmt_dnssec_enable.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_dnssec_enable,
            'dnssec-enable yes;',
            {'dnssec_enable': 'yes'}
        )

    def test_isc_optview_stmt_dnssec_lookaside_passing(self):
        """ Clause options/view; Statement dnssec-lookaside; passing """
        test_string = [
            'dnssec-lookaside auto;',
            'dnssec-lookaside string trust-anchor string2;',
            'dnssec-lookaside no;'
        ]
        result = optview_stmt_dnssec_lookaside.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_dnssec_lookaside,
            'dnssec-lookaside example-dlv.com trust-anchor prepend_key_name;',
            {
                'dnssec_lookaside': {
                    'trust_anchor_method': {
                        'prepend_key_name': 'prepend_key_name',
                        'rr_set': 'example-dlv.com'}}}
        )
        assert_parser_result_dict_true(
            optview_stmt_dnssec_lookaside,
            'dnssec-lookaside auto;',
            {'dnssec_lookaside': ['auto']}
        )

    def test_isc_optview_stmt_dnssec_must_be_secure_passing(self):
        """ Clause options/view; Statement dnssec-must-be-secure; passing """
        test_string = [
            'dnssec-must-be-secure tlv.example.com. yes;'
        ]
        result = optview_stmt_dnssec_must_be_secure.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_dnssec_must_be_secure,
            'dnssec-must-be-secure www.example.com. no;',
            {'dnssec_must_be_secure': [{'dnssec_secured': 'no',
                                        'fqdn': 'www.example.com.'}]}
        )

    def test_isc_optview_stmt_dnssec_validation_passing(self):
        """ Clause options/view; Statement dnssec-validation; passing """
        test_string = [
            'dnssec-validation no;',
            'dnssec-validation yes;',
            'dnssec-validation auto;',
        ]
        result = optview_stmt_dnssec_validation.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_dnssec_validation,
            'dnssec-validation auto;',
            {'dnssec_validation': 'auto'}
        )

    def test_isc_optview_stmt_dnstap(self):
        """ Clause options/view; Statement dnstap; passing """
        test_string = [
            'dnstap { all; };',
            'dnstap { forwarder; resolver; };',
            'dnstap { update; client; };',
        ]
        result = optview_stmt_dnstap.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

        assert_parser_result_dict_true(
            optview_stmt_dnstap,
            'dnstap { all; forwarder; resolver; update; client; };',
            {'dnstap': ['all', 'forwarder', 'resolver', 'update', 'client']}
        )

    def test_isc_optview_stmt_dual_stack_servers_passing(self):
        """ Clause options/view; Statement dual-stack-servers; passing """
        test_string = [
            'dual-stack-servers { 1.1.1.1; };',
            'dual-stack-servers { 2.2.2.2 port 563; };',
            'dual-stack-servers { fe0a::1; };',
            'dual-stack-servers { fe0a::2 port 771; };',
            'dual-stack-servers port 593 { 3.3.3.3; };',
            'dual-stack-servers port 593 { "bastion1.example.com" port 693; };',
            'dual-stack-servers port 593 { "bastion2.example.com" port 893; };',
            'dual-stack-servers port 593 { "bastion3.example.com" port 893; "bastion4.example.com" port 993; };',
        ]
        result = optview_stmt_dual_stack_servers.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_dual_stack_servers,
            'dual-stack-servers port 593 { "dmz.example.com" port 893; "hidden-dns.example.com" port 993; };',
            {
                'dual_stack_servers': {
                    'addrs': [
                        {
                            'domain': '"dmz.example.com"',
                            'ip_port': '893'
                        },
                        {
                            'domain': '"hidden-dns.example.com"',
                            'ip_port': '993'
                        }
                    ],
                    'ip_port': '593'
                }
            }
        )

    def test_isc_optview_stmt_empty_contact_passing(self):
        """ Clause options/view; Statement empty-contact; passing """
        test_string = [
            'empty-contact admin.example.com;',
            'empty-contact admin.example.com.;',
        ]
        result = optview_stmt_empty_contact.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_empty_contact,
            'empty-contact admin.example.com;',
            {'empty_contact': {'soa_contact_name': 'admin.example.com'}}
        )

    def test_isc_optview_stmt_empty_zones_enable_passing(self):
        """ Clause options/view; Statement empty-zones-enable; passing """
        test_string = [
            'empty-zones-enable False;'
        ]
        result = optview_stmt_empty_zones_enable.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_empty_zones_enable,
            'empty-zones-enable yes;',
            {'empty_zones_enable': 'yes'}
        )

    def test_isc_optview_stmt_fetch_glue_passing(self):
        """ Clause options/view; Statement fetch-glue; passing """
        test_string = [
            'fetch-glue no;'
        ]
        result = optview_stmt_fetch_glue.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_fetch_glue,
            'fetch-glue yes;',
            {'fetch_glue': 'yes'}
        )

    def test_isc_optview_stmt_fetch_quota_params_set_passing(self):
        """ Clause options/view; Statement 'fetch-quota-params'; passing """
        test_string = [
            'fetch-quota-params 1 2 3 4;',
            'fetch-quota-params 2 3 4 5;',
            'fetch-quota-params 2 4.4 5.5 6.6;',
        ]
        result = optview_stmt_fetch_quota_params.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optview_stmt_fetch_quota_params_max_passing(self):
        """ Clause options/view; Statement 'fetch-quota-params'; passing """
        assert_parser_result_dict_true(
            optview_stmt_fetch_quota_params,
            'fetch-quota-params 1 2 3 4;',
            {'fetch_quota_params': {'high_threshold': 3,
                                    'low_threshold': 2,
                                    'moving_average_discount_rate': 4,
                                    'moving_avg_recalculate_interval': 1}}
        )

    def test_isc_optview_stmt_fetches_per_server_ut_passing(self):
        """ Clause options/view; Statement 'fetches-per-server unittests'; passing """
        test_string = [
            'fetches-per-server 0;',
            'fetches-per-server 10000;',
            'fetches-per-server 15 drop;',
            'fetches-per-server 15 fail;',
        ]
        result = optview_stmt_fetches_per_server.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optview_stmt_fetches_per_server_passing(self):
        """ Clause options/view; Statement 'fetches-per-server'; passing """
        assert_parser_result_dict_true(
            optview_stmt_fetches_per_server,
            'fetches-per-server 0 fail;',
            {'fetches_per_server': {'action': 'fail', 'fetches': 0}}
        )

    def test_isc_optview_stmt_fetches_per_zone_ut_passing(self):
        """ Clause options/view; Statement 'fetches-per-zone unittests'; passing """
        test_string = [
            'fetches-per-zone 0;',
            'fetches-per-zone 10000;',
            'fetches-per-zone 15 drop;',
            'fetches-per-zone 15 fail;',
        ]
        result = optview_stmt_fetches_per_zone.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optview_stmt_fetches_per_zone_passing(self):
        """ Clause options/view; Statement 'fetches-per-zone'; passing """
        assert_parser_result_dict_true(
            optview_stmt_fetches_per_zone,
            'fetches-per-zone 0 drop;',
            {'fetches_per_zone': {'action': 'drop', 'fetches': 0}}
        )

    # XXXX optview_stmt_files
    def test_isc_optview_stmt_files_passing(self):
        """ Clause options/view; Statement files; passing """
        test_string = [
            'files default;',
            'files unlimited;',
            'files 1024;',
        ]
        result = optview_stmt_files.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_files,
            'files unlimited;',
            {'files': {'files_count': 'unlimited'}}
        )
        assert_parser_result_dict_true(
            optview_stmt_files,
            'files default;',
            {'files': {'files_count': 'default'}}
        )
        assert_parser_result_dict_true(
            optview_stmt_files,
            'files 1025;',
            {'files': {'files_count': 1025}}
        )

    def test_isc_optview_stmt_heartbeat_interval_passing(self):
        """ Clause options/view; Statement heartbeat-interval; passing """
        test_string = [
            'heartbeat-interval 60;'
        ]
        result = optview_stmt_heartbeat_interval.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_heartbeat_interval,
            'heartbeat-interval 3600;',
            {'heartbeat_interval': 3600}
        )

    def test_isc_optview_stmt_hostname_passing(self):
        """ Clause options/view; Statement hostname; passing """
        test_string = [
            'hostname none;',  # 'none', since v9.4.0
            'hostname example.com;',
            'hostname "example.com";',  # no quote support in v9.4.0
        ]
        result = optview_stmt_hostname.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_hostname,
            'hostname none;',
            {'hostname': {'none': 'none'}}
        )
        assert_parser_result_dict_true(
            optview_stmt_hostname,
            'hostname example.com;',
            {'hostname': {'name': 'example.com'}}
        )

    def test_isc_optview_stmt_ipv4only_contact_passing(self):
        """ Clause options/view; Statement 'ipv4only-contact'; passing """
        assert_parser_result_dict_true(
            optview_stmt_ipv4only_contact,
            'ipv4only-contact johndoe.example.test;',
            {'ipv4only_contact': {'soa_rname': 'johndoe.example.test'}}
        )

    def test_isc_optview_stmt_ipv4only_enable_passing(self):
        """ Clause options/view; Statement 'ipv4only-enable'; passing """
        assert_parser_result_dict_true(
            optview_stmt_ipv4only_enable,
            'ipv4only-enable yes;',
            {'ipv4only_enable': 'yes'}
        )

    def test_isc_optview_stmt_ipv4only_server_passing(self):
        """ Clause options/view; Statement 'ipv4only-server'; passing """
        assert_parser_result_dict_true(
            optview_stmt_ipv4only_server,
            'ipv4only-server johndoe.example.test;',
            {'ipv4only_server': {'soa_rname': 'johndoe.example.test'}}
        )

    def test_isc_optview_stmt_lame_ttl_passing(self):
        """ Clause options/view; Statement lame-ttl; passing """
        test_string = [
            'lame-ttl 0;',  # disable caching
            'lame-ttl 63;',
            'lame-ttl 600;',  # default value
            'lame-ttl 1800;',  # maximum value
        ]
        result = optview_stmt_lame_ttl.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_lame_ttl,
            'lame-ttl 32;',
            {'lame_ttl': 32}
        )

    def test_isc_optview_stmt_lmdb_mapsize_ut_passing(self):
        """ Clause options/view; Statement 'lmdb-mapzie; passing """
        test_string = [
            'lmdb-mapsize 0;',  # disable caching
            'lmdb-mapsize 128K;',  # default value
            'lmdb-mapsize 15M;',  # maximum value
            'lmdb-mapsize 999G;',  # maximum value
        ]
        result = optview_stmt_lmdb_mapsize.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optview_stmt_lmdb_mapsize_passing(self):
        """ Clause options/view; Statement 'lmdb-mapzie; passing """
        assert_parser_result_dict_true(
            optview_stmt_lmdb_mapsize,
            'lmdb-mapsize 32K;',
            {'lmdb_mapsize': {'amount': 32, 'unit': 'K'}}
        )

    def test_isc_optview_stmt_managed_keys_directory_passing(self):
        """ Clause options/view; Statement managed-keys-directory; passing """
        test_string = [
            'managed-keys-directory "/var/lib/bind9/managed-keys/public/";'
        ]
        result = optview_stmt_managed_keys_directory.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_managed_keys_directory,
            'managed-keys-directory "/var/lib/bind9/managed-keys/public/";',
            {'managed_keys_directory': '/var/lib/bind9/managed-keys/public/'}
        )

    def test_isc_optview_stmt_max_cache_size_passing(self):
        """ Clause options/view; Statement max-cache-size; passing """
        test_string = [
            'max-cache-size 0;',
            'max-cache-size 2048000;',
            'max-cache-size 14M;',
            'max-cache-size 4g;',
            'max-cache-size unlimited;',
        ]
        result = optview_stmt_max_cache_size.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_max_cache_size,
            'max-cache-size 14m;',
            {'max_cache_size': [14, 'm']}
        )
        assert_parser_result_dict_true(
            optview_stmt_max_cache_size,
            'max-cache-size unlimited;',
            {'max_cache_size': ['unlimited']}
        )

    def test_isc_optview_stmt_max_cache_ttl_ut_passing(self):
        """ Clause options/view; Statement max-cache-ttl unittest; passing """
        test_string = [
            'max-cache-ttl 0;',
            'max-cache-ttl 3600;',
            'max-cache-ttl 604800;',  # default value
            'max-cache-ttl 2048000000;',
        ]
        result = optview_stmt_max_cache_ttl.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optview_stmt_max_cache_ttl_passing(self):
        """ Clause options/view; Statement max-cache-ttl; passing """
        assert_parser_result_dict_true(
            optview_stmt_max_cache_ttl,
            'max-cache-ttl 3600;',
            {'max_cache_ttl': '3600'}  # it's in a string format because '7D', '1W', '24H' are all valid here
        )

    def test_isc_optview_stmt_max_ncache_ttl_ut_passing(self):
        """ Clause options/view; Statement max-ncache-ttl unittest; passing """
        test_string = [
            'max-ncache-ttl 0;',
            'max-ncache-ttl 10800;',  # default value
            'max-ncache-ttl 604800;',  # maximum value
        ]
        result = optview_stmt_max_ncache_ttl.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optview_stmt_max_ncache_ttl_passing(self):
        """ Clause options/view; Statement max-ncache-ttl; passing """
        assert_parser_result_dict_true(
            optview_stmt_max_ncache_ttl,
            'max-ncache-ttl 10800;',
            {'max_ncache_ttl': '10800'}  # it's in a string format because '7D', '1W', '24H' are all valid here
        )

    #    optview_stmt_max_recursion_depth
    def test_isc_optview_stmt_max_recursion_depth_passing(self):
        """ Clause options/view; Statement 'max-recursion-depth'; passing """
        test_string = [
            'max-recursion-depth 0;',
            'max-recursion-depth 10800;',
            'max-recursion-depth 604800;',
        ]
        result = optview_stmt_max_recursion_depth.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_max_recursion_depth,
            'max-recursion-depth 10800;',
            {'max_recursion_depth': 10800}
        )

#    optview_stmt_max_recursion_queries
    def test_isc_optview_stmt_max_recursion_queries_passing(self):
        """ Clause options/view; Statement 'max-recursion-queries'; passing """
        test_string = [
            'max-recursion-queries 0;',
            'max-recursion-queries 10800;',
            'max-recursion-queries 604800;',
        ]
        result = optview_stmt_max_recursion_queries.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_max_recursion_queries,
            'max-recursion-queries 10800;',
            {'max_recursion_queries': 10800}
        )

#    optview_stmt_max_stale_ttl
    def test_isc_optview_stmt_max_stale_ttl_passing(self):
        """ Clause options/view; Statement 'max-stale-ttl'; passing """
        test_string = [
            'max-stale-ttl 0;',
            'max-stale-ttl 60;',
            'max-stale-ttl 3600;',
            'max-stale-ttl 60M;',
            'max-stale-ttl 24H;',
            'max-stale-ttl 5D;',
            'max-stale-ttl 1W;',
        ]
        result = optview_stmt_max_stale_ttl.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_max_stale_ttl,
            'max-stale-ttl 24H;',
            {'max_stale_ttl': '24H'}
        )

#    optview_stmt_max_udp_size
    def test_isc_optview_stmt_max_udp_size_passing(self):
        """ Clause options/view; Statement 'max-udp-size'; passing """
        test_string = [
            'max-udp-size 128;',
            'max-udp-size 512;',
            'max-udp-size 1024;',
            'max-udp-size 1121;',
            'max-udp-size 2048;',
            'max-udp-size 4096;',
        ]
        result = optview_stmt_max_udp_size.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_max_udp_size,
            'max-udp-size 1121;',
            {'max_udp_size': 1121}
        )

#    optview_stmt_max_zone_ttl
    def test_isc_optview_stmt_max_zone_ttl_ut_passing(self):
        """ Clause options/view; Statement 'max-zone-ttl' unittest; passing """
        test_string = [
            'max-zone-ttl 0;',
            'max-zone-ttl 2048000;',
            'max-zone-ttl 14M;',
            'max-zone-ttl 24H;',
            'max-zone-ttl unlimited;',
        ]
        result = optview_stmt_max_zone_ttl.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optview_stmt_max_zone_ttl_passing(self):
        """ Clause options/view; Statement 'max-zone-ttl' unittest; passing """
        assert_parser_result_dict_true(
            optview_stmt_max_zone_ttl,
            'max-zone-ttl 24H;',
            {'max-zone-ttl': '24H'}
        )

    def test_isc_optview_stmt_max_zone_ttl_2_passing(self):
        """ Clause options/view; Statement 'max-zone-ttl'; passing """
        assert_parser_result_dict_true(
            optview_stmt_max_zone_ttl,
            'max-zone-ttl unlimited;',
            {'max-zone-ttl': 'unlimited'}
        )

    #  optview_stmt_message_compression
    def test_isc_optview_stmt_message_compression_passing(self):
        """ Clause options/view; Statement 'message-compression'; passing """
        assert_parser_result_dict_true(
            optview_stmt_message_compression,
            'message-compression yes;',
            {'message_compression': 'yes'}
        )

    def test_isc_optview_stmt_minimal_responses_passing(self):
        """ Clause options/view; Statement minimal-responses; passing """
        test_string = [
            'minimal-responses no-auth-recursive;',
            'minimal-responses no-auth;',
            'minimal-responses yes;',
            'minimal-responses no;',
            'minimal-responses True;',
            'minimal-responses False;',
            'minimal-responses 0;',
            'minimal-responses 1;',
        ]
        result = optview_stmt_minimal_responses.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_minimal_responses,
            'minimal-responses no;',
            {'minimal_responses': 'no'}
        )

    def test_isc_optview_stmt_no_case_compress_ut_passing(self):
        """ Clause options/view; Statement 'no-case-compress' unittest; passing """
        test_string = [
            'no-case-compress { "corp"; };',
            'no-case-compress { corp; };',
        ]
        result = optview_stmt_no_case_compress.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optview_stmt_no_case_compress_passing(self):
        """ Clause options/view; Statement 'no-case-compress'; passing """
        assert_parser_result_dict_true(
            optview_stmt_no_case_compress,
            'no-case-compress { "corp"; "museum"; net; };',
            {'no_case_compress': [{'acl_name': '"corp"'},
                                  {'acl_name': '"museum"'},
                                  {'acl_name': 'net'}]}
        )

    #   optview-stmt-notify-rate <integer>  # [Opt, View]
    def test_isc_optview_stmt_notify_rate_passing(self):
        """ Clause options/view; Statement 'notify-rate'; passing """
        test_string = [
            'notify-rate 0;',  # minimum
            'notify-rate 20;',  # default
            'notify-rate 2100000000;'  # maximum
            ]
        result = optview_stmt_notify_rate.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_notify_rate,
            'notify-rate 20;',  # default
            {'notify_rate': 20}
        )

    def test_isc_optview_stmt_parental_source_ut_passing(self):
        """ Clause options/view; Statement 'parental-source' unittest; passing """
        test_string = [
            'parental-source * port *;',  # default
            'parental-source * port * dscp 2;',
            'parental-source * port 443;',
            'parental-source * port 443 dscp 3;',
            'parental-source 127.0.0.1 port *;',
            'parental-source 127.0.0.1 port * dscp 4;',
            'parental-source 127.0.0.1 port 444;',
            'parental-source 127.0.0.1 port 445 dscp 5;',
        ]
        result = optview_stmt_parental_source.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optview_stmt_parental_source_passing(self):
        """ Clause options/view; Statement 'parental-source'; passing """
        assert_parser_result_dict_true(
            optview_stmt_parental_source,
            'parental-source  127.0.0.1 port 442;',  # default
            {'parental_source': {'ip4_addr_w': '127.0.0.1',
                                 'ip_port_w': '442'}}
        )

    def test_isc_optview_stmt_parental_source_v6_passing(self):
        """ Clause options/view; Statement 'parental-source-v6'; passing """
        test_string = [
            'parental-source-v6 * port *;',  # default
            'parental-source-v6 * port * dscp 2;',
            'parental-source-v6 * port 443;',
            'parental-source-v6 * port 443 dscp 3;',
            'parental-source-v6 ffc2::1 port *;',
            'parental-source-v6 FFd2::1   port * dscp 4;',
            'parental-source-v6 Fee2::1  port 444;',
            'parental-source-v6 fdd3::1 port 445 dscp 5;',
        ]
        result = optview_stmt_parental_source_v6.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_parental_source_v6,
            'parental-source-v6  ffe2::1 port 442;',  # default
            {'parental_source_v6': {'ip6_addr_w': 'ffe2::1',
                                    'ip_port_w': '442'}}
        )

    def test_isc_optview_stmt_preferred_glue_passing(self):
        """ Clause options/view; Statement preferred-glue; passing """
        test_string = [
            'preferred-glue A;',  # default
            'preferred-glue a;',  # default
            'preferred-glue aaaa;',
            'preferred-glue AAAA;',
            'preferred-glue none;',  # introduced in 9.15.0-ish
            'preferred-glue NONE;',  # introduced in 9.15.0-ish
        ]
        result = optview_stmt_preferred_glue.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_preferred_glue,
            'preferred-glue A;',  # default
            {'preferred_glue': 'A'}
        )

    def test_isc_optview_stmt_qname_ut_minimization(self):
        """ Clause options/view; Statement 'qname-minimization' unittest; passing """
        test_string = [
            'qname-minimization disabled;',
            'qname-minimization relaxed;',  # default
            'qname-minimization strict;',
            'qname-minimization off;'
        ]
        result = optview_stmt_qname_minimization.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optview_stmt_qname_minimization(self):
        """ Clause options/view; Statement 'qname-minimization'; passing """
        assert_parser_result_dict_true(
            optview_stmt_qname_minimization,
            'qname-minimization relaxed;',  # default
            {'qname_minimization': 'relaxed'}
        )

    def test_isc_optview_stmt_query_source_v6_passing(self):
        """ Clause options/view; Statement YYYY; passing """
        test_string = [
            'query-source-v6;',  # INADDR_ANY (wildcard)
            'query-source-v6 address fe01::1;',
            'query-source-v6 address *;',
            'query-source-v6 address fe01::2 port 53;',
            'query-source-v6 address fe01::3 port *;',
            'query-source-v6 address * port 153;',
            'query-source-v6 address * port *;',
            'query-source-v6 port 253;',
            'query-source-v6 port *;',
        ]
        result = optview_stmt_query_source_v6.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_query_source_v6,
            'query-source-v6 address * port 353;',
            {'query_source_v6': {'ip6_addr': '*', 'ip_port_w': '353'}}
        )
        assert_parser_result_dict_true(
            optview_stmt_query_source_v6,
            'query-source-v6 address fe08::08 port *;',
            {'query_source_v6': {'ip6_addr': 'fe08::08', 'ip_port_w': '*'}}
        )

    def test_isc_optview_stmt_query_source_passing(self):
        """ Clause options/view; Statement query-source; passing """
        test_string = [
            'query-source;',  # INADDR_ANY (wildcard)
            'query-source address 4.4.4.4;',
            'query-source address *;',
            'query-source address 5.5.5.5 port 53;',
            'query-source address 6.6.6.6 port *;',
            'query-source address * port 153;',
            'query-source address * port *;',
            'query-source port 253;',
            'query-source port *;',
        ]
        result = optview_stmt_query_source.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_query_source,
            'query-source address * port 353;',
            {'query_source': {'ip4_addr': '*', 'ip_port_w': '353'}}
        )
        assert_parser_result_dict_true(
            optview_stmt_query_source,
            'query-source address 7.7.7.7 port *;',
            {'query_source': {'ip4_addr': '7.7.7.7', 'ip_port_w': '*'}}
        )

    # XXXX optview_stmt_rate_limit
    def test_isc_optview_stmt_rate_limit_passing(self):
        """ Clause options/view; Statement rate-limit; passing """
        test_string = [
            'rate-limit { all-per-second 60; };',
            'rate-limit { errors-per-second 60; };',
            'rate-limit { exempt-clients { 4.4.4.4; }; };',
            'rate-limit { ipv4-prefix-length 8; };',
            'rate-limit { ipv6-prefix-length 8; };',
            'rate-limit { log-only yes; };',
            'rate-limit { max-table-size 1500; };',
            'rate-limit { min-table-size 1500; };',
            'rate-limit { nodata-per-second 5; };',
            'rate-limit { nxdomains-per-second 5; };',
            'rate-limit { qps-scale 5; };',
            'rate-limit { referrals-per-second 5; };',
            'rate-limit { responses-per-second 5; };',
            'rate-limit { slip 5; };',
            'rate-limit { window 5; };',
        ]
        result = optview_stmt_rate_limit.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_rate_limit,
            'rate-limit { exempt-clients { 5.5.5.5; }; slip 5; window 6; responses-per-second 60; };',
            {'rate_limit': [{'ip4_addr': '5.5.5.5'},
                            {'slip': 5},
                            {'window': 6},
                            {'responses_per_second': 60}]}
        )

    # XXXX optview_stmt_recursion
    def test_isc_optview_stmt_recursion_passing(self):
        """ Clause options/view; Statement recursion; passing """
        test_string = [
            'recursion yes;',
            'recursion no;',
            'recursion true;',
            'recursion false;',
            'recursion 0;',
            'recursion 1;',
        ]
        result = optview_stmt_recursion.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_recursion,
            'recursion yes;',
            {'recursion': 'yes'}
        )

    # XXXX optview_stmt_response_policy

    # Focus on within the curly '{}' braces (per-zone) basis 'zone_element'
    # these zone-specific elements do not have semicolon separator, except at the end
    def test_isc_optview_stmt_response_policy_zone_group_empty_passing(self):
        """ Clause options/view; Statement response-policy zone group empty; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy_zone_group_set,
            'zone grey;',
            {'zone_name': 'grey'}
        )

    def test_isc_optview_stmt_response_policy_zone_group_empty_dot_passing(self):
        """ Clause options/view; Statement response-policy zone group dot; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy_zone_group_set,
            'zone \'.\';',
            {'zone_name': '.'}
        )

    def test_isc_optview_stmt_response_policy_zone_group_empty_squote_passing(self):
        """ Clause options/view; Statement response-policy zone group empty; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy_zone_group_set,
            'zone \'grey\';',
            {'zone_name': 'grey'}
        )

    def test_isc_optview_stmt_response_policy_zone_group_empty_dquote_passing(self):
        """ Clause options/view; Statement response-policy zone group empty; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy_zone_group_set,
            'zone "www.template.test.";',
            {'zone_name': 'www.template.test.'}
        )

    def test_isc_optview_stmt_response_policy_zone_group_add_soa_passing(self):
        """ Clause options/view; Statement response-policy zone group 'add-soa'; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy_zone_group_set,
            'zone red add-soa yes;',
            {'add_soa': 'yes', 'zone_name': 'red'}
        )

    def test_isc_optview_stmt_response_policy_zone_group_log_passing(self):
        """ Clause options/view; Statement response-policy zone group 'log'; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy_zone_group_set,
            'zone blue log yes;',
            {'log': 'yes', 'zone_name': 'blue'}
        )

    def test_isc_optview_stmt_response_policy_zone_group_max_policy_ttl_passing(self):
        """ Clause options/view; Statement response-policy zone group 'max-policy-ttl'; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy_zone_group_set,
            'zone green max-policy-ttl 1W3D;',
            {'max_policy_ttl': '1W3D',
             'zone_name': 'green'}
        )

    def test_isc_optview_stmt_response_policy_zone_group_min_update_interval_passing(self):
        """ Clause options/view; Statement response-policy zone group 'min-update-interval'; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy_zone_group_set,
            'zone yellow min-update-interval 3H;',
            {'min_update_interval': '3H',
             'zone_name': 'yellow'}
        )

    def test_isc_optview_stmt_response_policy_zone_group_policy_0_arg_passing(self):
        """ Clause options/view; Statement response-policy zone group 'policy' 0-arg; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy_zone_group_set,
            'zone black policy given;',
            {'policy': ['given'], 'zone_name': 'black'}
        )

    def test_isc_optview_stmt_response_policy_zone_group_policy_1_arg_passing(self):
        """ Clause options/view; Statement response-policy zone group 'policy' 1-arg; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy_zone_group_set,
            'zone white policy tcp-only an_unknown_string;',
            {'policy': {'tcp_only': 'an_unknown_string'},
             'zone_name': 'white'}
        )

    def test_isc_optview_stmt_response_policy_zone_group_recursive_only_passing(self):
        """ Clause options/view; Statement response-policy zone group 'recursive-only'; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy_zone_group_set,
            'zone pink recursive-only yes;',
            {'recursive_only': 'yes',
             'zone_name': 'pink'}
        )

    def test_isc_optview_stmt_response_policy_zone_group_nsip_enable_passing(self):
        """ Clause options/view; Statement response-policy zone group 'nsip-enable'; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy_zone_group_set,
            'zone green nsip-enable yes;',
            {'nsip_enable': 'yes',
             'zone_name': 'green'}
        )

    def test_isc_optview_stmt_response_policy_zone_group_nsdname_enable_passing(self):
        """ Clause options/view; Statement response-policy zone group 'nsdname-enable'; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy_zone_group_set,
            'zone purple nsdname-enable yes;',
            {'nsdname_enable': 'yes',
             'zone_name': 'purple'}
        )

    def test_isc_optview_stmt_response_policy_zone_group_complex_passing(self):
        """ Clause options/view; Statement response-policy zone group complex; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy_zone_group_set,
            'zone purple nsip-enable yes policy tcp-only some_string nsdname-enable yes;',
            {'nsdname_enable': 'yes',
             'nsip_enable': 'yes',
             'policy': {'tcp_only': 'some_string'},
             'zone_name': 'purple'}
        )

    # For 'response-policy', global elements pertains to outside the curly '{}' or non-zone-specific attributes.
    # these global elements do not have semicolon separators, until at the end of 'response-policy' statement.
    def test_isc_optview_stmt_response_policy_global_element_add_soa_passing(self):
        """ Clause options/view; Statement response-policy global element 'add-soa'; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy_global_element_set,
            'add-soa yes',
            {'add_soa': 'yes'}
        )

    def test_isc_optview_stmt_response_policy_global_element_break_dnssec_passing(self):
        """ Clause options/view; Statement response-policy global element 'break-dnssec'; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy_global_element_set,
            'break-dnssec yes',
            {'break_dnssec': 'yes'}
        )

    def test_isc_optview_stmt_response_policy_passing(self):
        """ Clause options/view; Statement response-policy; passing """

        test_string = [
            'response-policy { zone white add-soa yes; };',
            'response-policy { zone white log yes; };',
            'response-policy { zone dmz max-policy-ttl 60; };',
            'response-policy { zone dmz min-update-interval 1Y; };',
            'response-policy { zone white policy cname; };',
            'response-policy { zone white policy disabled; };',
            'response-policy { zone brown policy drop; };',
            'response-policy { zone silver policy given; };',
            'response-policy { zone silver policy no-op; };',
            'response-policy { zone purple policy nodata; };',
            'response-policy { zone yellow policy nxdomain; };',
            'response-policy { zone black policy passthru; };',
            'response-policy { zone black policy tcp-only some_string; };',
            'response-policy { zone red recursive-only yes; };',
            'response-policy { zone red nsip-enable yes; };',
            'response-policy { zone red nsdname-enable yes; };',
            'response-policy { zone orange; } break-dnssec yes;',
            'response-policy { zone green; } min-ns-dots 1;',
            """response-policy { 
    zone "172.in-addr.arpa." add-soa no log no max-policy-ttl 4Y min-update-interval 30S 
        policy no-op recursive-only no nsip-enable no nsdname-enable no; 
    zone "168.192.in-addr.arpa." add-soa yes log yes max-policy-ttl 3Y min-update-interval 20S 
        policy cname recursive-only yes nsip-enable yes nsdname-enable yes; 
    zone "example.test." log yes max-policy-ttl 4Y min-update-interval 30S 
        policy no-op recursive-only yes nsip-enable yes nsdname-enable no add-soa no; 
    zone "example2.test." max-policy-ttl 4Y min-update-interval 30S 
        policy no-op recursive-only yes nsip-enable yes nsdname-enable no add-soa yes log yes; 
    zone "172.in-addr.arpa." add-soa no log yes max-policy-ttl 4Y min-update-interval 30S 
        policy no-op recursive-only yes nsip-enable yes nsdname-enable no; 
    } add-soa no break-dnssec no max-policy-ttl 30S min-update-interval 4w min-ns-dots 2 
         nsip-wait-recurse yes nsdname-wait-recurse yes qname-wait-recurse yes recursive-only yes 
         nsip-enable yes nsdname-enable yes dnsrps-enable yes ;""",
        ]
        result = optview_stmt_response_policy.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    # optview_stmt_response_policy
    def test_isc_optview_stmt_response_policy_minimal_passing(self):
        """ Clause options/view; Statement response-policy minimal; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy,
            'response-policy { zone "white"; };',
            {'response_policy': {'zone': [{'zone_name': 'white'}]}}
        )

    # XXXX optview_stmt_response_policy
    def test_isc_optview_stmt_response_policy_minimal_zone_passing(self):
        """ Clause options/view; Statement response-policy minimal zone; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy,
            'response-policy { zone black policy given; };',
            {'response_policy': {'zone': [{'policy': ['given'],
                                           'zone_name': 'black'}]}}
        )

    def test_isc_optview_stmt_response_policy_minimal_all_passing(self):
        """ Clause options/view; Statement response-policy minimal all; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy,
            'response-policy { zone grey log yes; } nsip-enable yes;',
            {'response_policy': {'nsip_enable': 'yes',
                                 'zone': [{'log': 'yes',
                                           'zone_name': 'grey'}]}}
        )

    def test_isc_optview_stmt_response_policy_maximum_all_passing(self):
        """ Clause options/view; Statement response-policy maximum all; passing """
        assert_parser_result_dict_true(
            optview_stmt_response_policy,
            """response-policy {
        zone 172.in-addr.arpa. add-soa yes log yes max-policy-ttl 1H min-update-interval 1D
             policy tcp-only TCP-LABEL recursive-only no nsip-enable no nsdname-enable no ;
        zone 10.in-addr.arpa. add-soa no log no max-policy-ttl 1D min-update-interval 1W
             policy tcp-only TCP-LABEL recursive-only yes nsip-enable yes nsdname-enable yes ;
        zone 168.192.in-addr.arpa. add-soa yes log yes max-policy-ttl 1H min-update-interval 1D
             policy tcp-only TCP-LABEL recursive-only no nsip-enable no nsdname-enable no ;
    }
    add-soa yes
    break-dnssec no
    max-policy-ttl 24H
    min-update-interval 7D
    min-ns-dots 3
   nsip-wait-recurse yes
   nsdname-wait-recurse yes
   qname-wait-recurse yes
   recursive-only yes
   nsip-enable no
   nsdname-enable no
   dnsrps-enable yes
   dnsrps-options { "some options" }; 
""",
            {'response_policy': {'add_soa': 'yes',
                                 'break_dnssec': 'no',
                                 'dnsrps_enable': 'yes',
                                 'dnsrps_options2': {'dnsrps_options': 'some '
                                                                       'options'},
                                 'max_policy_ttl': '24H',
                                 'min_ns_dots': 3,
                                 'min_update_interval': '7D',
                                 'nsdname_enable': 'no',
                                 'nsdname_wait_recurse': 'yes',
                                 'nsip_enable': 'no',
                                 'nsip_wait_recurse': 'yes',
                                 'qname_wait_recurse': 'yes',
                                 'recursive_only': 'yes',
                                 'zone': [{'add_soa': 'yes',
                                           'log': 'yes',
                                           'max_policy_ttl': '1H',
                                           'min_update_interval': '1D',
                                           'nsdname_enable': 'no',
                                           'nsip_enable': 'no',
                                           'policy': {'tcp_only': 'TCP-LABEL'},
                                           'recursive_only': 'no',
                                           'zone_name': '172.in-addr.arpa.'},
                                          {'add_soa': 'no',
                                           'log': 'no',
                                           'max_policy_ttl': '1D',
                                           'min_update_interval': '1W',
                                           'nsdname_enable': 'yes',
                                           'nsip_enable': 'yes',
                                           'policy': {'tcp_only': 'TCP-LABEL'},
                                           'recursive_only': 'yes',
                                           'zone_name': '10.in-addr.arpa.'},
                                          {'add_soa': 'yes',
                                           'log': 'yes',
                                           'max_policy_ttl': '1H',
                                           'min_update_interval': '1D',
                                           'nsdname_enable': 'no',
                                           'nsip_enable': 'no',
                                           'policy': {'tcp_only': 'TCP-LABEL'},
                                           'recursive_only': 'no',
                                           'zone_name': '168.192.in-addr.arpa.'}]}}
        )

    def test_isc_optview_stmt_rfc2308_type1_passing(self):
        """ Clause options/view; Statement rfc2308-type1; passing """
        test_string = [
            'rfc2308-type1 no;'
        ]
        result = optview_stmt_rfc2308_type1.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_rfc2308_type1,
            'rfc2308-type1 yes;',
            {'rfc2308_type1': 'yes'}
        )

    def test_isc_optview_stmt_root_delegation_only_passing(self):
        """ Clause options/view; Statement root-delegation-only; passing """
        test_string = [
            'root-delegation-only;',
            'root-delegation-only exclude { name1; };',
            'root-delegation-only exclude { name1; name2; name3; };',
        ]
        result = optview_stmt_root_delegation_only.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_root_delegation_only,
            'root-delegation-only exclude { name1; name2; name3; };',
            {'root_delegation_only': {'domains': ['name1', 'name2', 'name3']}}
        )

    def test_isc_optview_stmt_rrset_order_group_ut_passing(self):
        """ Clause options/view; Statement rrset-order group unittest; passing """
        test_string = [
            'order cyclic;',
            'order random;',
            'order fixed;',
            'zone 172.in-addr.arpa.;',
            'class IN type A name host.example.com;',
            'class CH type TXT name host.example.com;',
            'name "fixed.example" order fixed;',
            'name "random.example" order random;',
            'name "cyclic.example" order cyclic;',
            'name "none.example" order none;',
            'type NS order random;',
        ]
        result = optview_rrset_order_group_series.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optview_stmt_rrset_order_ut_passing(self):
        """ Clause options/view; Statement rrset-order unittest; passing """
        test_string = [
            'rrset-order { class IN type A name host.example.com; };',
            'rrset-order { class CH type TXT name host.example.com; };',
            """rrset-order { name "fixed.example" order fixed;
    name "random.example" order random;
    name "cyclic.example" order cyclic;
    name "none.example" order none;
    type NS order random;
    order cyclic; };""",
        ]
        result = optview_stmt_rrset_order.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optview_stmt_rrset_order_series_passing(self):
        """ Clause options/view; Statement rrset-order; passing """
        assert_parser_result_dict_true(
            optview_rrset_order_group_series,
            'class IN name host.example.com type A;',
            {'rrset_order': [{'class': 'IN',
                              'name': 'host.example.com',
                              'type': 'A'}]}
        )
        
    def test_isc_optview_stmt_rrset_order_2_passing(self):
        """ Clause options/view; Statement rrset-order; passing """
        assert_parser_result_dict_true(
            optview_stmt_rrset_order,
            """rrset-order {
    name "fixed.example" order fixed;
    name "random.example" order random;
    name "cyclic.example" order cyclic;
    name "none.example" order none;
    type NS order random;
    order cyclic;
    };""",
            {'rrset_order': [{'name': 'fixed.example', 'order': 'fixed'},
                             {'name': 'random.example', 'order': 'random'},
                             {'name': 'cyclic.example', 'order': 'cyclic'},
                             {'name': 'none.example', 'order': 'none'},
                             {'order': 'random', 'type': 'NS'},
                             {'order': 'cyclic'}]}
        )
        
    # optview_stmt_servfail_ttl, \
    def test_isc_optview_stmt_servfail_ttl_passing(self):
        """ Clause options/view; Statement 'servfail-ttl'; passing """
        assert_parser_result_dict_true(
            optview_stmt_servfail_ttl,
            'servfail-ttl 1;',  # default
            {'servfail_ttl': 1}
        )

    # optview_stmt_sortlist
    def test_isc_optview_stmt_sortlist_1_passing(self):
        """ Clause options/view; Statement sortlist; passing """
        test_string = [
            'sortlist { localhost; localnets; };',
            'sortlist { localnets; };',
            """sortlist { 
    { localhost; 
        { localnets; 192.168.1.0/24; 
            { 192.168.2.0/24; 192.168.3.0/24; }; }; }; 
    { 192.168.1.0/24; { 192.168.1.0/24; { 192.168.2.0/24; 192.168.3.0/24; }; }; }; };""",
        ]
        result = optview_stmt_sortlist.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    # optview_stmt_sortlist
    def test_isc_optview_stmt_sortlist_2_passing(self):
        """ Clause options/view; Statement sortlist; passing """
        assert_parser_result_dict_true(
            optview_stmt_sortlist,
            'sortlist { localhost; localnets; };',
            {'sortlist': {'aml': [{'keyword': 'localhost'},
                                  {'keyword': 'localnets'}]}}
        )

    def test_isc_optview_stmt_sortlist_3_passing(self):
        """ Clause options/view; Statement sortlist 2; passing """
        assert_parser_result_dict_true(
            optview_stmt_sortlist,
            """sortlist { 
    { localhost; 
        { localnets; 192.168.1.0/24; 
            { 192.168.2.0/24; 192.168.3.0/24; }; }; }; 
    { 192.168.1.0/24; { 192.168.1.0/24; { 192.168.2.0/24; 192.168.3.0/24; }; }; }; };""",
            {'sortlist': {'aml': [{'aml': [{'keyword': 'localhost'},
                                           {'aml': [{'keyword': 'localnets'},
                                                    {'ip4_addr': '192.168.1.0',
                                                     'prefix': '24'},
                                                    {'aml': [{'ip4_addr': '192.168.2.0',
                                                              'prefix': '24'},
                                                             {'ip4_addr': '192.168.3.0',
                                                              'prefix': '24'}]}]}]},
                                  {'aml': [{'ip4_addr': '192.168.1.0',
                                            'prefix': '24'},
                                           {'aml': [{'ip4_addr': '192.168.1.0',
                                                     'prefix': '24'},
                                                    {'aml': [{'ip4_addr': '192.168.2.0',
                                                              'prefix': '24'},
                                                             {'ip4_addr': '192.168.3.0',
                                                              'prefix': '24'}]}]}]}]}}
        )

    # optview_stmt_stale_answer_client_timeout
    def test_isc_optview_stmt_stale_answer_client_timeout_passing(self):
        """ Clause options/view; Statement 'stale-answer-client-timeout'; passing """
        test_string = [
            'stale-answer-client-timeout off;',  # default
            'stale-answer-client-timeout disabled;',
            'stale-answer-client-timeout 0;',
            'stale-answer-client-timeout 32767;',
        ]
        result = optview_stmt_stale_answer_client_timeout.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_stale_answer_client_timeout,
            'stale-answer-client-timeout off;',
            {'stale_answer_client_timeout': 'off'}
        )

    # optview_stmt_stale_answer_enable
    def test_isc_optview_stmt_stale_answer_enable_passing(self):
        """ Clause options/view; Statement 'stale-answer-enable'; passing """
        assert_parser_result_dict_true(
            optview_stmt_stale_answer_enable,
            'stale-answer-enable false;',
            {'stale_answer_enable': 'False'}
        )

    # optview_stmt_stale_answer_ttl
    def test_isc_optview_stmt_stale_answer_ttl_passing(self):
        """ Clause options/view; Statement 'stale-answer-ttl'; passing """
        test_string = [
            'stale-answer-ttl 30;',  # default
            'stale-answer-ttl 0;',
            'stale-answer-ttl 1;',
        ]
        result = optview_stmt_stale_answer_ttl.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_stale_answer_ttl,
            'stale-answer-ttl 30;',
            {'stale_answer_ttl': 30}
        )

    # optview_stmt_stale_cache_enable
    def test_isc_optview_stmt_stale_cache_enable_passing(self):
        """ Clause options/view; Statement 'stale-cache-enable'; passing """
        assert_parser_result_dict_true(
            optview_stmt_stale_cache_enable,
            'stale-cache-enable false;',
            {'stale_cache_enable': 'False'}
        )

    # optview_stmt_stale_refresh_time
    def test_isc_optview_stmt_stale_refresh_time_passing(self):
        """ Clause options/view; Statement 'stale-refresh-time'; passing """
        test_string = [
            'stale-refresh-time 30;',  # default
            'stale-refresh-time 0;',
            'stale-refresh-time 1;',
        ]
        result = optview_stmt_stale_refresh_time.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_stale_refresh_time,
            'stale-refresh-time 30;',
            {'stale_refresh_time': 30}
        )

    # optview_stmt_suppress_initial_notify
    def test_isc_optview_stmt_suppress_initial_notify_passing(self):
        """ Clause options/view; Statement 'suppress-initial-notify'; passing """
        assert_parser_result_dict_true(
            optview_stmt_suppress_initial_notify,
            'suppress-initial-notify false;',
            {'suppress_initial_notify': 'False'}
        )

    # optview_stmt_synth_from_dnssec
    def test_isc_optview_stmt_synth_from_dnssec_passing(self):
        """ Clause options/view; Statement 'synth-from-dnssec'; passing """
        assert_parser_result_dict_true(
            optview_stmt_synth_from_dnssec,
            'synth-from-dnssec false;',
            {'synth_from_dnssec': 'False'}
        )

    # optview_stmt_trust_anchor_telemetry
    def test_isc_optview_stmt_trust_anchor_telemetry_passing(self):
        """ Clause options/view; Statement 'trust-anchor-telemetry'; passing """
        assert_parser_result_dict_true(
            optview_stmt_trust_anchor_telemetry,
            'trust-anchor-telemetry true;',
            {'trust_anchor_telemetry': 'True'}
        )

    # optview_stmt_v6_bias
    def test_isc_optview_stmt_v6_bias_passing(self):
        """ Clause options/view; Statement 'v6-bias'; passing """
        test_string = [
            'v6-bias 50;',  # default
            'v6-bias 0;',
            'v6-bias 1;',
        ]
        result = optview_stmt_v6_bias.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_stmt_v6_bias,
            'v6-bias 50;',
            {'v6_bias': 50}
        )
    
    # optview_stmt_validate_except
    def test_isc_optview_stmt_validate_except_ut_passing(self):
        """ Clause options/view; Statement 'validate-except' unittest; passing """
        test_string = [
            'validate-except { "corp"; };',
            'validate-except { museum; net; cult; };',
        ]
        result = optview_stmt_validate_except.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optview_stmt_validate_except_passing(self):
        """ Clause options/view; Statement 'validate-except'; passing """
        assert_parser_result_dict_true(
            optview_stmt_validate_except,
            'validate-except { dot; zany; weird-tls;} ;',
            {'validate_except': ['dot', 'zany', 'weird-tls']}
        )

    # optview_stmt_zero_no_soa_ttl_cache
    def test_isc_optview_stmt_zero_no_soa_ttl_cache_passing(self):
        """ Clause options/view; Statement 'zero-no-soa-ttl-cache'; passing """
        assert_parser_result_dict_true(
            optview_stmt_zero_no_soa_ttl_cache,
            'zero-no-soa-ttl-cache true;',
            {'zero_no_soa_ttl_cache': 'True'}
        )

    def test_isc_optview_statements_set_passing(self):
        """ Clause optview; Statement statements_set; passing """
        test_string = [
            'acache-cleaning-interval no;',
            'acache-enable no;',
            'additional-from-auth yes;',
            'additional-from-cache yes;',
            'allow-new-zones 0;',
            'allow-query-cache { localnets; localhost; };',
            'allow-query-cache-on { localnets; localhost; };',
            'allow-recursion { localnets; localhost; };',
            'allow-recursion-on { any; };',
            'attach-cache dmz_view;',
            'auth-nxdomain no;',
            'cache-file "/dev/null";',
            'check-dup-records ignore;',
            'check-integrity no;',
            'check-mx warn;',
            'check-mx-cname fail;',
            'check-names slave ignore;',
            'check-spf fail;',
            'check-srv-cname warn;',
            'check-wildcard yes;',
            'cleaning-interval 480;',
            'deny-answer-addresses { 127.0.0.1; };',
            'deny-answer-aliases { example.test.; };',
            'disable-empty-zone ".";',
            """dns64 64:ff9b::/96 { 
    break-dnssec yes;
    recursive-only no;
    clients { 127.0.0.1; };
    exclude { 127.0.0.1; };
    mapped   { 127.0.0.1; };
    };""",
            'dns64-contact johndoe.example.test;',
            'dnssec-accept-expired no;',
            'dnssec-enable yes;',
            'dnssec-lookaside auto;',
            'dnssec-must-be-secure www.example.com. no;',
            'dnssec-validation auto;',
            'dual-stack-servers port 593 { "bastion1.example.com" port 693; };',
            'empty-contact admin.example.com;',
            'empty-zones-enable no;',
            'fetch-glue no;',
            'files default;',
            'heartbeat-interval 3600;',
            'hostname example.com;',
            'lame-ttl 32;',
            'managed-keys-directory "/var/lib/bind9/managed-keys/public/";',
            'max-cache-size 2048000;',
            'max-cache-ttl 3600;',
            'minimal-responses yes;',
            'preferred-glue aaaa;',
            'query-source address 5.5.5.5 port 53;',
            'query-source-v6 address fe08::08 port *;',
            'rate-limit { qps-scale 5; };',
            'recursion yes;',
            'response-policy { zone white policy given; };',
            'rfc2308-type1 yes;',
            'root-delegation-only exclude { name1; name2; name3; };',
            'rrset-order { class IN type A name "host.example.com" order random; order cyclic; };',
            'sortlist { localhost; localnets; };',
        ]
        result = optview_statements_set.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            optview_statements_set,
            'sortlist { localhost; localnets; };',
            {'sortlist': {'aml': [{'keyword': 'localhost'},
                                  {'keyword': 'localnets'}]}}
        )

    def test_isc_optview_stmt_statements_set_failing(self):
        """ Clause optview; Statement statements_set; failing """
        test_string = [
            'non-existent statements_set "YYYY";',
        ]
        result = optview_statements_set.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_optview_statements_series_experimental_passing(self):
        """ Clause optview; Statement optview_statements_series; passing """
        assert_parser_result_dict_true(
            optview_statements_series,
            'acache-enable no; dns64-contact a.b.c; acache-cleaning-interval no;',
            {'acache_cleaning_interval': 'no',
             'acache_enable': 'no',
             'dns64_contact': {'soa_rname': 'a.b.c'}}
            )

    def test_isc_optview_statements_series_passing(self):
        """ Clause optview; Statement optview_statements_series; passing """
        assert_parser_result_dict_true(
            optview_statements_series,
            'acache-enable no;' +
            'acache-cleaning-interval no;' +
            'additional-from-cache yes;' +
            'allow-query-cache-on { localnets; localhost; };' +
            'allow-query-cache { localnets; localhost; };' +
            'allow-recursion-on { any; };' +
            'allow-recursion { localnets; localhost; };' +
            'auth-nxdomain no;' +
            'check-integrity no;' +
            'allow-new-zones 0;' +
            'attach-cache dmz_view;' +
            'cache-file "/dev/null";' +
            'rate-limit { qps-scale 5; };' +
            'query-source-v6 address fe08::08 port *;' +
            'check-mx warn;' +
            'additional-from-auth yes;' +
            'max-cache-ttl 3600;' +
            'check-wildcard yes;' +
            'heartbeat-interval 3600;' +
            'dnssec-lookaside auto;' +
            'check-mx-cname fail;' +
            'dnssec-enable yes;' +
            'check-spf fail;' +
            'check-srv-cname warn;' +
            'dnssec-must-be-secure "www.example.com." no;' +
            'empty-contact admin.example.com;' +
            'files default;' +
            'check-dup-records ignore;' +
            'hostname example.com;' +
            'check-names slave ignore;' +
            'cleaning-interval 480;' +
            'lame-ttl 32;' +
            'max-cache-size 2048000;' +
            'managed-keys-directory "/var/lib/bind9/managed-keys/public/";' +
            'minimal-responses yes;' +
            'query-source address 5.5.5.5 port 53;' +
            'preferred-glue aaaa;' +
            'dnssec-accept-expired False;' +
            'dnssec-validation auto;' +
            'response-policy { zone white policy given; };' +
            'rfc2308-type1 yes;' +
            'fetch-glue no;' +
            'root-delegation-only exclude { name1; name2; name3; };' +
            'dual-stack-servers port 593 { "bastion1.example.com" port 693; };' +
            'disable-empty-zone ".";' +
            'empty-zones-enable False;' +
            'recursion yes;' +
            'sortlist { localhost; localnets; };',
            {'acache_cleaning_interval': 'no',
             'acache_enable': 'no',
             'additional_from_auth': 'yes',
             'additional_from_cache': 'yes',
             'allow-recursion': {'aml': [{'keyword': 'localnets'},
                                         {'keyword': 'localhost'}]},
             'allow-recursion-on': {'aml': [{'keyword': 'any'}]},
             'allow_new_zones': '0',
             'allow_query_cache': {'aml': [{'keyword': 'localnets'},
                                           {'keyword': 'localhost'}]},
             'allow_query_cache_on': {'aml': [{'keyword': 'localnets'},
                                              {'keyword': 'localhost'}]},
             'attach_cache': 'dmz_view',
             'auth_nxdomain': 'no',
             'cache_file': '/dev/null',
             'check_dup_records': 'ignore',
             'check_integrity': 'no',
             'check_mx': 'warn',
             'check_mx_cname': 'fail',
             'check_names': [{'result_status': 'ignore',
                              'zone_type': 'slave'}],
             'check_spf': 'fail',
             'check_srv_cname': 'warn',
             'check_wildcard': 'yes',
             'cleaning_interval': 480,
             'disable_empty_zone': [{'zone_name': '.'}],
             'dnssec_accept_expired': 'False',
             'dnssec_enable': 'yes',
             'dnssec_lookaside': ['auto'],
             'dnssec_must_be_secure': [{'dnssec_secured': 'no',
                                        'fqdn': '"www.example.com."'}],
             'dnssec_validation': 'auto',
             'dual_stack_servers': {'addrs': [{'domain': '"bastion1.example.com"',
                                               'ip_port': '693'}],
                                    'ip_port': '593'},
             'empty_contact': {'soa_contact_name': 'admin.example.com'},
             'empty_zones_enable': 'False',
             'fetch_glue': 'no',
             'files': {'files_count': 'default'},
             'heartbeat_interval': 3600,
             'hostname': {'name': 'example.com'},
             'lame_ttl': 32,
             'managed_keys_directory': '/var/lib/bind9/managed-keys/public/',
             'max_cache_size': [2048000],
             'max_cache_ttl': '3600',
             'minimal_responses': 'yes',
             'preferred_glue': 'AAAA',
             'query_source': {'ip4_addr': '5.5.5.5', 'ip_port_w': '53'},
             'query_source_v6': {'ip6_addr': 'fe08::08', 'ip_port_w': '*'},
             'rate_limit': [{'qps_scale': 5}],
             'recursion': 'yes',
             'response_policy': {'zone': [{'policy': ['given'],
                                           'zone_name': 'white'}]},
             'rfc2308_type1': 'yes',
             'root_delegation_only': {'domains': ['name1',
                                                  'name2',
                                                  'name3']},
             'sortlist': {'aml': [{'keyword': 'localhost'},
                                  {'keyword': 'localnets'}]}}
        )

    def test_isc_optview_stmt_statements_series_failing(self):
        """ Clause optview; Statement statements_series; failing """
        test_string = [
            'statements_series "YYYY";',
        ]
        result = optview_statements_series.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()
