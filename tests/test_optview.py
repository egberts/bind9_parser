#!/usr/bin/env python3
"""
File: test_optview.py

Description:  Performs unit test on the isc_optview.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue, assertParserResultDictFalse
from bind9_parser.isc_optview import \
    optview_stmt_acache_cleaning_interval,\
    optview_stmt_acache_enable,\
    optview_stmt_additional_from_auth, \
    optview_stmt_additional_from_cache, \
    optview_stmt_allow_new_zones, \
    optview_stmt_allow_query_cache_on, \
    optview_stmt_allow_query_cache, \
    optview_stmt_allow_recursion_on, \
    optview_stmt_allow_recursion, \
    optview_stmt_attach_cache, \
    optview_stmt_auth_nxdomain, \
    optview_stmt_cache_file,\
    optview_stmt_check_dup_records, \
    optview_stmt_check_integrity, \
    optview_stmt_check_mx_cname, \
    optview_stmt_check_mx, \
    optview_stmt_check_names, \
    optview_stmt_check_sibling, \
    optview_stmt_check_spf, \
    optview_stmt_check_srv_cname, \
    optview_stmt_check_wildcard, \
    optview_stmt_cleaning_interval, \
    optview_stmt_dnssec_accept_expired, \
    optview_stmt_dnssec_enable, \
    optview_stmt_dnssec_lookaside, \
    optview_stmt_dnssec_must_be_secure, \
    optview_stmt_dnssec_validation, \
    optview_stmt_dual_stack_servers,\
    optview_stmt_disable_empty_zone,\
    optview_stmt_empty_contact, \
    optview_stmt_empty_zones_enable, \
    optview_stmt_fetch_glue,\
    optview_stmt_files,\
    optview_stmt_heartbeat_interval, \
    optview_stmt_hostname, \
    optview_stmt_lame_ttl, \
    optview_stmt_managed_keys_directory, \
    optview_stmt_max_cache_size, \
    optview_stmt_max_cache_ttl, \
    optview_stmt_max_ncache_ttl, \
    optview_stmt_minimal_responses, \
    optview_stmt_preferred_glue, \
    optview_stmt_query_source_v6, \
    optview_stmt_query_source,\
    optview_stmt_rate_limit, \
    optview_stmt_recursion, \
    optview_stmt_response_policy_element_log, \
    optview_stmt_response_policy_element_policy_type, \
    optview_stmt_response_policy_zone_element_set, \
    optview_stmt_response_policy_zone_group_set, \
    optview_stmt_response_policy_global_element_set, \
    optview_stmt_response_policy, \
    optview_stmt_rfc2308_type1,\
    optview_stmt_root_delegation_only, \
    optview_stmt_rrset_order,\
    optview_stmt_sortlist, \
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
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
            optview_stmt_allow_query_cache_on,
            'allow-query-cache-on { localnets; localhost; };',
            {'allow_query_cache_on': {'aml': [{'addr': 'localnets'},
                                              {'addr': 'localhost'}]}}
        )

    def test_isc_optview_stmt_allow_query_cache_passing(self):
        """ Clause options/view; Statement allow-query-cache; passing """
        test_string = [
            'allow-query-cache { localnets; localhost; };'
        ]
        result = optview_stmt_allow_query_cache.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optview_stmt_allow_query_cache,
            'allow-query-cache { localnets; localhost; };',
            {'allow_query_cache': {'aml': [{'addr': 'localnets'},
                                           {'addr': 'localhost'}]}}
        )

    def test_isc_optview_stmt_allow_recursion_on_passing(self):
        """ Clause options/view; Statement allow-recursion-on; passing """
        test_string = [
            'allow-recursion-on { any; };'
        ]
        result = optview_stmt_allow_recursion_on.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optview_stmt_allow_recursion_on,
            'allow-recursion-on { any; };',
            {'allow-recursion-on': {'aml': [{'addr': 'any'}]}}
        )

    def test_isc_optview_stmt_allow_recursion_passing(self):
        """ Clause options/view; Statement allow-recursion; passing """
        test_string = [
            'allow-recursion { localnets; localhost; };'
        ]
        result = optview_stmt_allow_recursion.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optview_stmt_allow_recursion,
            'allow-recursion { localnets; localhost; };',
            {'allow-recursion': {'aml': [{'addr': 'localnets'},
                                         {'addr': 'localhost'}]}}
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
        assertParserResultDictTrue(
            optview_stmt_attach_cache,
            'attach-cache dmz_view;',
            {'attach_cache': 'dmz_view'}
        )

    def test_isc_optview_stmt_attach_cache_2_failing(self):
        """ Clause options/view; Statement attach-cache 2; failing """
        assertParserResultDictFalse(
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
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
            optview_stmt_cache_file,
            'cache-file "/dev/null";',
            {'cache_file': '"/dev/null"'}
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
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
            optview_stmt_check_names,
            'check-names slave ignore;',
            {'check_names': [{'result_status': 'ignore',
                              'zone_type': 'slave'}]}
        )

    def test_isc_optview_stmt_check_sibling_passing(self):
        """ Clause options/view; Statement check-sibling; passing """
        test_string = [
            'check-sibling ignore;',
            'check-sibling warn;',
            'check-sibling fail;',
        ]
        result = optview_stmt_check_sibling.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optview_stmt_check_sibling,
            'check-sibling fail;',
            {'check_sibling': 'fail'}
        )

    def test_isc_optview_stmt_check_spf_passing(self):
        """ Clause options/view; Statement check-spf; passing """
        test_string = [
            'check-spf ignore;'
        ]
        result = optview_stmt_check_spf.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
            optview_stmt_cleaning_interval,
            'cleaning-interval 480;',
            {'cleaning_interval': 480}
        )

    def test_isc_optview_stmt_dnssec_accept_expired_passing(self):
        """ Clause options/view; Statement dnssec-accept-expired; passing """
        test_string = [
            'dnssec-accept-expired no;'
        ]
        result = optview_stmt_dnssec_accept_expired.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
            optview_stmt_dnssec_lookaside,
            'dnssec-lookaside example-dlv.com trust-anchor prepend_key_name;',
            {
                'dnssec_lookaside': {
                    'trust_anchor_method': {
                        'prepend_key_name': 'prepend_key_name',
                        'rr_set': 'example-dlv.com'}}}
        )
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
            optview_stmt_dnssec_must_be_secure,
            'dnssec-must-be-secure www.example.com. no;',
            {
                'dnssec_must_be_secure': {
                    'accept_secured_answers': 'no',
                    'domain': 'www.example.com.'}}
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
        assertParserResultDictTrue(
            optview_stmt_dnssec_validation,
            'dnssec-validation auto;',
            {'dnssec_validation': 'auto'}
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
        assertParserResultDictTrue(
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

    def test_isc_optview_stmt_disable_empty_zone_passing(self):
        """ Clause options/view; Statement disable-empty-zone; passing """
        test_string = [
            'disable-empty-zone ".";',
            'disable-empty-zone 168.192.in-addr.arpa.;',
            'disable-empty-zone "example.com";',
        ]
        result = optview_stmt_disable_empty_zone.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optview_stmt_disable_empty_zone,
            'disable-empty-zone ".";',
            {'disable_empty_zone': [{'zone_name': '"."'}]}
        )
        assertParserResultDictTrue(
            optview_stmt_disable_empty_zone,
            'disable-empty-zone example.com.;',
            {'disable_empty_zone': [{'zone_name': 'example.com.'}]}
        )

    def test_isc_optview_stmt_empty_contact_passing(self):
        """ Clause options/view; Statement empty-contact; passing """
        test_string = [
            'empty-contact admin.example.com;',
            'empty-contact admin.example.com.;',
        ]
        result = optview_stmt_empty_contact.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
            optview_stmt_fetch_glue,
            'fetch-glue yes;',
            {'fetch_glue': 'yes'}
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
        assertParserResultDictTrue(
            optview_stmt_files,
            'files unlimited;',
            {'files': {'files_count': 'unlimited'}}
        )
        assertParserResultDictTrue(
            optview_stmt_files,
            'files default;',
            {'files': {'files_count': 'default'}}
        )
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
            optview_stmt_heartbeat_interval,
            'heartbeat-interval 3600;',
            {'heartbeat_interval': 3600}
        )

    def test_isc_optview_stmt_hostname_passing(self):
        """ Clause options/view; Statement hostname; passing """
        test_string = [
            'hostname none;',   # 'none', since v9.4.0
            'hostname example.com;',
            'hostname "example.com";',  # no quote support in v9.4.0
        ]
        result = optview_stmt_hostname.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optview_stmt_hostname,
            'hostname none;',
            {'hostname': {'none': 'none'}}
        )
        assertParserResultDictTrue(
            optview_stmt_hostname,
            'hostname example.com;',
            {'hostname': {'name': 'example.com'}}
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
        assertParserResultDictTrue(
            optview_stmt_lame_ttl,
            'lame-ttl 32;',
            {'lame_ttl': 32}
        )

    def test_isc_optview_stmt_managed_keys_directory_passing(self):
        """ Clause options/view; Statement managed-keys-directory; passing """
        test_string = [
            'managed-keys-directory "/var/lib/bind9/managed-keys/public/";'
        ]
        result = optview_stmt_managed_keys_directory.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optview_stmt_managed_keys_directory,
            'managed-keys-directory "/var/lib/bind9/managed-keys/public/";',
            {'managed_keys_directory': '"/var/lib/bind9/managed-keys/public/"'}
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
        assertParserResultDictTrue(
            optview_stmt_max_cache_size,
            'max-cache-size 14m;',
            {'max_cache_size': [14, 'm']}
        )
        assertParserResultDictTrue(
            optview_stmt_max_cache_size,
            'max-cache-size unlimited;',
            {'max_cache_size': ['unlimited']}
        )

    def test_isc_optview_stmt_max_cache_ttl_passing(self):
        """ Clause options/view; Statement max-cache-ttl; passing """
        test_string = [
            'max-cache-ttl 0;',
            'max-cache-ttl 3600;',
            'max-cache-ttl 604800;',  # default value
            'max-cache-ttl 2048000000;',
        ]
        result = optview_stmt_max_cache_ttl.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optview_stmt_max_cache_ttl,
            'max-cache-ttl 3600;',
            {'max_cache_ttl': 3600}
        )

    def test_isc_optview_stmt_max_ncache_ttl_passing(self):
        """ Clause options/view; Statement max-ncache-ttl; passing """
        test_string = [
            'max-ncache-ttl 0;',
            'max-ncache-ttl 10800;',  # default value
            'max-ncache-ttl 604800;',  # maximum value
        ]
        result = optview_stmt_max_ncache_ttl.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optview_stmt_max_ncache_ttl,
            'max-ncache-ttl 10800;',
            {'max_ncache_ttl': 10800}
        )

    def test_isc_optview_stmt_minimal_responses_passing(self):
        """ Clause options/view; Statement minimal-responses; passing """
        test_string = [
            'minimal-responses yes;',
            'minimal-responses no;',
            'minimal-responses True;',
            'minimal-responses False;',
            'minimal-responses 0;',
            'minimal-responses 1;',
        ]
        result = optview_stmt_minimal_responses.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optview_stmt_minimal_responses,
            'minimal-responses no;',
            {'minimal_responses': 'no'}
        )

    def test_isc_optview_stmt_preferred_glue_passing(self):
        """ Clause options/view; Statement preferred-glue; passing """
        test_string = [
            'preferred-glue A;',
            'preferred-glue a;',
            'preferred-glue aaaa;',
            'preferred-glue AAAA;',
            'preferred-glue none;',  # introduced in 9.15.0-ish
            'preferred-glue NONE;',  # introduced in 9.15.0-ish
        ]
        result = optview_stmt_preferred_glue.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optview_stmt_preferred_glue,
            'preferred-glue none;',
            {'preferred_glue': 'none'}
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
        assertParserResultDictTrue(
            optview_stmt_query_source_v6,
            'query-source-v6 address * port 353;',
            {'query_source_v6': {'ip6_addr': '*', 'ip_port_w': '353'}}
        )
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
            optview_stmt_query_source,
            'query-source address * port 353;',
            {'query_source': {'ip4_addr': '*', 'ip_port_w': '353'}}
        )
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
            optview_stmt_rate_limit,
            'rate-limit { exempt-clients { 5.5.5.5; }; slip 5; window 6; responses-per-second 60; };',
            {'rate_limit': [{'addr': '5.5.5.5'},
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
        assertParserResultDictTrue(
            optview_stmt_recursion,
            'recursion yes;',
            {'recursion': 'yes'}
        )

    # XXXX optview_stmt_response_policy

    # Focus on within the curly '{}' braces (per-zone) basis 'zone_element'
    # these zone-specific elements do not have semicolon separator, except at the end
    def test_isc_optview_stmt_response_policy_zone_group_empty_passing(self):
        """ Clause options/view; Statement response-policy zone group empty; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy_zone_group_set,
            'zone grey;',
            {'zone_name': 'grey'}
        )
    def test_isc_optview_stmt_response_policy_zone_group_empty_dot_passing(self):
        """ Clause options/view; Statement response-policy zone group dot; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy_zone_group_set,
            'zone \'.\';',
            {'zone_name': "'.'"}
        )
    def test_isc_optview_stmt_response_policy_zone_group_empty_squote_passing(self):
        """ Clause options/view; Statement response-policy zone group empty; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy_zone_group_set,
            'zone \'grey\';',
            {'zone_name': "'grey'"}
        )
    def test_isc_optview_stmt_response_policy_zone_group_empty_dquote_passing(self):
        """ Clause options/view; Statement response-policy zone group empty; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy_zone_group_set,
            'zone "www.template.test.";',
            {'zone_name': '"www.template.test."'}
        )
    def test_isc_optview_stmt_response_policy_zone_group_add_soa_passing(self):
        """ Clause options/view; Statement response-policy zone group 'add-soa'; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy_zone_group_set,
            'zone red add-soa yes;',
            {'add_soa': ['yes'], 'zone_name': 'red'}
        )
    def test_isc_optview_stmt_response_policy_zone_group_log_passing(self):
        """ Clause options/view; Statement response-policy zone group 'log'; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy_zone_group_set,
            'zone blue log yes;',
            {'log': ['yes'],
             'zone_name': 'blue'}
        )

    def test_isc_optview_stmt_response_policy_zone_group_max_policy_ttl_passing(self):
        """ Clause options/view; Statement response-policy zone group 'max-policy-ttl'; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy_zone_group_set,
            'zone green max-policy-ttl 1W3D;',
            {'max_policy_ttl': '1W3D',
             'zone_name': 'green'}
        )
    def test_isc_optview_stmt_response_policy_zone_group_min_update_interval_passing(self):
        """ Clause options/view; Statement response-policy zone group 'min-update-interval'; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy_zone_group_set,
            'zone yellow min-update-interval 3H;',
            {'min_update_interval': '3H',
             'zone_name': 'yellow'}
        )
    def test_isc_optview_stmt_response_policy_zone_group_policy_0_arg_passing(self):
        """ Clause options/view; Statement response-policy zone group 'policy' 0-arg; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy_zone_group_set,
            'zone black policy given;',
            {'policy_type': ['given'],
             'zone_name': 'black'}
        )
    def test_isc_optview_stmt_response_policy_zone_group_policy_1_arg_passing(self):
        """ Clause options/view; Statement response-policy zone group 'policy' 1-arg; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy_zone_group_set,
            'zone white policy tcp-only an_unknown_string;',
            {'policy_type': [{'tcp_only': 'an_unknown_string'}],
             'zone_name': 'white'}
        )
    def test_isc_optview_stmt_response_policy_zone_group_recursive_only_passing(self):
        """ Clause options/view; Statement response-policy zone group 'recursive-only'; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy_zone_group_set,
            'zone pink recursive-only yes;',
            {'recursive_only': 'yes',
             'zone_name': 'pink'}
        )
    def test_isc_optview_stmt_response_policy_zone_group_nsip_enable_passing(self):
        """ Clause options/view; Statement response-policy zone group 'nsip-enable'; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy_zone_group_set,
            'zone green nsip-enable yes;',
            {'nsip_enable': 'yes',
             'zone_name': 'green'}
        )
    def test_isc_optview_stmt_response_policy_zone_group_nsdname_enable_passing(self):
        """ Clause options/view; Statement response-policy zone group 'nsdname-enable'; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy_zone_group_set,
            'zone purple nsdname-enable yes;',
            {'nsdname_enable': 'yes',
             'zone_name': 'purple'}
        )
    def test_isc_optview_stmt_response_policy_zone_group_complex_passing(self):
        """ Clause options/view; Statement response-policy zone group complex; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy_zone_group_set,
            'zone purple nsip-enable yes policy tcp-only some_string nsdname-enable yes;',
            {'nsdname_enable': 'yes',
             'nsip_enable': 'yes',
             'policy_type': [{'tcp_only': 'some_string'}],
             'zone_name': 'purple'}
        )

    # For 'response-policy', global elements pertains to outside the curly '{}' or non-zone-specific attributes.
    # these global elements do not have semicolon separators, until at the end of 'response-policy' statement.
    def test_isc_optview_stmt_response_policy_global_element_add_soa_passing(self):
        """ Clause options/view; Statement response-policy global element 'add-soa'; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy_global_element_set,
            'add-soa yes',
            {'add_soa': ['yes']}
        )
    def test_isc_optview_stmt_response_policy_global_element_break_dnssec_passing(self):
        """ Clause options/view; Statement response-policy global element 'break-dnssec'; passing """
        assertParserResultDictTrue(
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
    zone "172.in-addr.arpa." add-soa no log no max-policy-ttl 4Y min-update-interval 30S policy no-op recursive-only no nsip-enable no nsdname-enable no; 
    zone "168.192.in-addr.arpa." add-soa yes log yes max-policy-ttl 3Y min-update-interval 20S policy cname recursive-only yes nsip-enable yes nsdname-enable yes; 
    zone "example.test." log yes max-policy-ttl 4Y min-update-interval 30S policy no-op recursive-only yes nsip-enable yes nsdname-enable no add-soa no; 
    zone "example2.test." max-policy-ttl 4Y min-update-interval 30S policy no-op recursive-only yes nsip-enable yes nsdname-enable no add-soa yes log yes; 
    zone "172.in-addr.arpa." add-soa no log yes max-policy-ttl 4Y min-update-interval 30S policy no-op recursive-only yes nsip-enable yes nsdname-enable no; 
    } add-soa no break-dnssec no max-policy-ttl 30S min-update-interval 4w min-ns-dots 2 nsip-wait-recurse yes nsdname-wait-recurse yes qname-wait-recurse yes recursive-only yes nsip-enable yes nsdname-enable yes dnsrps-enable yes dnsrps-options unspecifiedoptions;""",
        ]
        result = optview_stmt_response_policy.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    # optview_stmt_response_policy
    def test_isc_optview_stmt_response_policy_minimal_passing(self):
        """ Clause options/view; Statement response-policy minimal; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy,
            'response-policy { zone "white"; };',
            {'response_policy': {'zone_name': '"white"'}}
        )
    # XXXX optview_stmt_response_policy
    def test_isc_optview_stmt_response_policy_minimal_zone_passing(self):
        """ Clause options/view; Statement response-policy minimal zone; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy,
            'response-policy { zone black policy given; };',
            {'response_policy': {'policy_type': ['given'],
                                 'zone_name': 'black'}}
        )
    def test_isc_optview_stmt_response_policy_minimal_all_passing(self):
        """ Clause options/view; Statement response-policy minimal all; passing """
        assertParserResultDictTrue(
            optview_stmt_response_policy,
            'response-policy { zone grey; } nsip-enable yes;',
            {'response_policy': {'nsip_enable': 'yes', 'zone_name': 'grey'}}
        )

    def test_isc_optview_stmt_rfc2308_type1_passing(self):
        """ Clause options/view; Statement rfc2308-type1; passing """
        test_string = [
            'rfc2308-type1 no;'
        ]
        result = optview_stmt_rfc2308_type1.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
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
        assertParserResultDictTrue(
            optview_stmt_root_delegation_only,
            'root-delegation-only exclude { name1; name2; name3; };',
            {'root_delegation_only': {'domains': ['name1', 'name2', 'name3']}}
        )

    def test_isc_optview_stmt_rrset_order_passing(self):
        """ Clause options/view; Statement rrset-order; passing """
        test_string = [
            'rrset-order { class IN type A name "host.example.com" order random; order cyclic; };'
        ]
        result = optview_stmt_rrset_order.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optview_stmt_rrset_order,
            'rrset-order { class IN type A name "host.example.com" order random; order cyclic; };',
            {'rrset_order': [{'class': 'IN',
                              'name': '"host.example.com"',
                              'order': 'random',
                              'type': 'A'},
                             {'order': 'cyclic'}]}
        )

    # XXXX optview_stmt_sortlist
    def test_isc_optview_stmt_sortlist_passing(self):
        """ Clause options/view; Statement sortlist; passing """
        test_string = [
            'sortlist { localhost; localnets; };',
            'sortlist { localnets; };',
            'sortlist { { localhost; { localnets; 192.168.1.0/24; { 192.168.2.0/24; 192.168.3.0/24; }; }; }; { 192.168.1.0/24; { 192.168.1.0/24; { 192.168.2.0/24; 192.168.3.0/24; }; }; }; };',
        ]
        result = optview_stmt_sortlist.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optview_stmt_sortlist,
            'sortlist { localhost; localnets; };',
            {'sortlist': {'aml': [{'addr': 'localhost'},
                                  {'addr': 'localnets'}]}}
        )
        assertParserResultDictTrue(
            optview_stmt_sortlist,
            'sortlist { { localhost; { localnets; 192.168.1.0/24; { 192.168.2.0/24; 192.168.3.0/24; }; }; }; { 192.168.1.0/24; { 192.168.1.0/24; { 192.168.2.0/24; 192.168.3.0/24; }; }; }; };',
            {
                'sortlist': {
                    'aml': [
                        {
                            'aml': [
                                {'addr': 'localhost'},
                                {'aml': [
                                    {'addr': 'localnets'},
                                    {'addr': '192.168.1.0/24'},
                                    {'aml': [
                                        {'addr': '192.168.2.0/24'},
                                        {'addr': '192.168.3.0/24'}
                                    ]}
                                ]}
                            ]
                        },
                        {
                            'aml': [
                                {'addr': '192.168.1.0/24'},
                                {
                                    'aml': [
                                        {'addr': '192.168.1.0/24'},
                                        {
                                            'aml': [
                                                {'addr': '192.168.2.0/24'},
                                                {'addr': '192.168.3.0/24'}]}]}]}]}}
        )

    def test_isc_optview_statements_set_passing(self):
        """ Clause optview; Statement statements_set; passing """
        test_string = [
            'acache-enable no;',
            'acache-cleaning-interval no;',
            'additional-from-cache yes;',
            'allow-query-cache-on { localnets; localhost; };',
            'allow-query-cache { localnets; localhost; };',
            'allow-recursion-on { any; };',
            'allow-recursion { localnets; localhost; };',
            'auth-nxdomain no;',
            'check-integrity no;',
            'allow-new-zones 0;',
            'attach-cache dmz_view;',
            'cache-file "/dev/null";',
            'rate-limit { qps-scale 5; };',
            'query-source-v6 address fe08::08 port *;',
            'check-mx warn;',
            'additional-from-auth yes;',
            'max-cache-ttl 3600;',
            'check-wildcard yes;',
            'heartbeat-interval 3600;',
            'dnssec-lookaside auto;',
            'check-mx-cname fail;',
            'dnssec-enable yes;',
            'check-spf fail;',
            'check-srv-cname warn;',
            'dnssec-must-be-secure www.example.com. no;',
            'empty-contact admin.example.com;',
            'files default;',
            'check-dup-records ignore;',
            'hostname example.com;',
            'check-names slave ignore;',
            'cleaning-interval 480;',
            'lame-ttl 32;',
            'max-cache-size 2048000;',
            'managed-keys-directory "/var/lib/bind9/managed-keys/public/";',
            'minimal-responses yes;',
            'query-source address 5.5.5.5 port 53;',
            'preferred-glue aaaa;',
            'dnssec-accept-expired False;',
            'check-sibling warn;',
            'dnssec-validation auto;',
            'response-policy { zone white policy given; };',
            'rfc2308-type1 yes;',
            'fetch-glue no;',
            'root-delegation-only exclude { name1; name2; name3; };',
            'dual-stack-servers port 593 { "bastion1.example.com" port 693; };',
            'disable-empty-zone ".";',
            'empty-zones-enable False;',
            'recursion yes;',
            'sortlist { localhost; localnets; };',
        ]
        result = optview_statements_set.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optview_statements_set,
            'sortlist { localhost; localnets; };',
            {'sortlist': {'aml': [{'addr': 'localhost'},
                                  {'addr': 'localnets'}]}}
        )

    def test_isc_optview_stmt_statements_set_failing(self):
        """ Clause optview; Statement statements_set; failing """
        test_string = [
            'non-existant statements_set "YYYY";',
        ]
        result = optview_statements_set.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


    def test_isc_optview_statements_series_passing(self):
        """ Clause optview; Statement optview_statements_series; passing """
        assertParserResultDictTrue(
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
            'dnssec-must-be-secure www.example.com. no;' +
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
            'check-sibling warn;' +
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
             'allow-recursion': {'aml': [{'addr': 'localnets'},
                                         {'addr': 'localhost'}]},
             'allow-recursion-on': {'aml': [{'addr': 'any'}]},
             'allow_new_zones': '0',
             'allow_query_cache': {'aml': [{'addr': 'localnets'},
                                           {'addr': 'localhost'}]},
             'allow_query_cache_on': {'aml': [{'addr': 'localnets'},
                                              {'addr': 'localhost'}]},
             'attach_cache': 'dmz_view',
             'auth_nxdomain': 'no',
             'cache_file': '"/dev/null"',
             'check_dup_records': 'ignore',
             'check_integrity': 'no',
             'check_mx': 'warn',
             'check_mx_cname': 'fail',
             'check_names': [{'result_status': 'ignore',
                              'zone_type': 'slave'}],
             'check_sibling': 'warn',
             'check_spf': 'fail',
             'check_srv_cname': 'warn',
             'check_wildcard': 'yes',
             'cleaning_interval': 480,
             'disable_empty_zone': [{'zone_name': '"."'}],
             'dnssec_accept_expired': 'False',
             'dnssec_enable': 'yes',
             'dnssec_lookaside': ['auto'],
             'dnssec_must_be_secure': {'accept_secured_answers': 'no',
                                       'domain': 'www.example.com.'},
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
             'managed_keys_directory': '"/var/lib/bind9/managed-keys/public/"',
             'max_cache_size': [2048000],
             'max_cache_ttl': 3600,
             'minimal_responses': 'yes',
             'preferred_glue': 'AAAA',
             'query_source': {'ip4_addr': '5.5.5.5', 'ip_port_w': '53'},
             'query_source_v6': {'ip6_addr': 'fe08::08', 'ip_port_w': '*'},
             'rate_limit': [{'qps_scale': 5}],
             'recursion': 'yes',
             'response_policy': {'policy_type': ['given'],
                                 'zone_name': 'white'},
             'rfc2308_type1': 'yes',
             'root_delegation_only': {'domains': ['name1',
                                                  'name2',
                                                  'name3']},
             'sortlist': {'aml': [{'addr': 'localhost'},
                                  {'addr': 'localnets'}]}}
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
