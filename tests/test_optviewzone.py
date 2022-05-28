#!/usr/bin/env python3
"""
File: test_optviewzone.py

Description:  Performs unit test on the isc_optviewzone.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue, assertParserResultDictFalse
from bind9_parser.isc_optviewzone import \
    optviewzone_stmt_allow_notify, \
    optviewzone_stmt_allow_query_on, \
    optviewzone_stmt_allow_query, \
    optviewzone_stmt_allow_transfer, \
    optviewzone_stmt_allow_update_on, \
    optviewzone_stmt_allow_update_forwarding, \
    optviewzone_stmt_allow_update, \
    optviewzone_stmt_allow_v6_synthesis, \
    optviewzone_stmt_alt_transfer_source_v6, \
    optviewzone_stmt_alt_transfer_source, \
    optviewzone_stmt_auto_dnssec, \
    optviewzone_stmt_check_sibling, \
    optviewzone_stmt_dialup, \
    optviewzone_stmt_dnskey_sig_validity, \
    optviewzone_stmt_dnssec_dnskey_kskonly, \
    optviewzone_stmt_dnssec_policy, \
    optviewzone_stmt_dnssec_secure_to_insecure, \
    optviewzone_stmt_dnssec_update_mode, \
    forwarders_ip46_addr_prefix_port_element, \
    forwarders_ip46_addr_prefix_port_series, \
    optviewzone_stmt_forwarders, \
    optviewzone_stmt_forward, \
    optviewzone_stmt_ixfr_from_differences, \
    optviewzone_stmt_ixfr_tmp_file, \
    optviewzone_stmt_key_directory, \
    optviewzone_stmt_dnssec_loadkeys_interval, \
    optviewzone_stmt_maintain_ixfr_base, \
    optviewzone_stmt_masterfile_format, \
    optviewzone_stmt_masterfile_style, \
    optviewzone_stmt_max_ixfr_ratio, \
    optviewzone_stmt_max_journal_size, \
    optviewzone_stmt_max_records, \
    optviewzone_stmt_max_refresh_time, \
    optviewzone_stmt_max_retry_time, \
    optviewzone_stmt_max_transfer_time_in, \
    optviewzone_stmt_max_transfer_time_out, \
    optviewzone_stmt_max_transfer_idle_in, \
    optviewzone_stmt_max_transfer_idle_out, \
    optviewzone_stmt_min_refresh_time, \
    optviewzone_stmt_min_retry_time, \
    optviewzone_stmt_multi_master, \
    optviewzone_stmt_notify_delay,\
    optviewzone_stmt_notify_source_v6, \
    optviewzone_stmt_notify_source, \
    optviewzone_stmt_notify, \
    optviewzone_stmt_provide_ixfr, \
    optviewzone_stmt_request_ixfr, \
    optviewzone_stmt_request_nsid, \
    optviewzone_stmt_sig_validity_interval, \
    optviewzone_stmt_transfer_source_v6, \
    optviewzone_stmt_transfer_format, \
    optviewzone_stmt_transfer_source, \
    optviewzone_stmt_use_alt_transfer_source, \
    optviewzone_stmt_zone_statistics, \
    optviewzone_statements_set, \
    optviewzone_statements_series


class TestOptionsViewZone(unittest.TestCase):
    """ Clause Options/View/Zone; only under 'options', 'view', and 'zone' clause """

    def test_isc_optviewzone_stmt_allow_notify_passing(self):
        """ Clause options/view/zone; Statement allow-notify; passing """
        test_string = [
            'allow-notify { localhost; localnets; };',
        ]
        result = optviewzone_stmt_allow_notify.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzone_stmt_allow_notify_2_passing(self):
        """ Clause options/view/zone; Statement allow-notify 2; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_allow_notify,
            'allow-notify { localhost; localnets; };',
            {'allow_notify': {'aml': [{'keyword': 'localhost'},
                                      {'keyword': 'localnets'}]}}
        )

    def test_isc_optviewzone_stmt_allow_query_on_passing(self):
        """ Clause options/view/zone; Statement allow-query-on; passing """

        test_string = [
            'allow-query-on { any; };',
        ]
        result = optviewzone_stmt_allow_query_on.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzone_stmt_allow_query_on_2_passing(self):
        """ Clause options/view/zone; Statement allow-query-on 2; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_allow_query_on,
            'allow-query-on { any; };',
            {'allow_query_on': {'aml': [{'keyword': 'any'}]}}
        )

    def test_isc_optviewzone_stmt_allow_query_passing(self):
        """ Clause options/view/zone; Statement allow-query; passing """
        test_string = [
            'allow-query { any; };',
        ]
        result = optviewzone_stmt_allow_query.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzone_stmt_allow_query_2_passing(self):
        """ Clause options/view/zone; Statement allow-query 2; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_allow_query,
            'allow-query { any; };',
            {'allow_query': {'aml': [{'keyword': 'any'}]}}
        )

    def test_isc_optviewzone_stmt_allow_transfer_passing(self):
        """ Clause options/view/zone; Statement allow-transfer; passing """
        test_string = [
            'allow-transfer { localhost; localnets; };',
        ]
        result = optviewzone_stmt_allow_transfer.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzone_stmt_allow_transfer_2_passing(self):
        """ Clause options/view/zone; Statement allow-transfer 2; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_allow_transfer,
            'allow-transfer { localhost; localnets; };',
            {'allow_transfer': {'aml': [{'keyword': 'localhost'},
                                           {'keyword': 'localnets'}]}}
        )

    def test_isc_optviewzone_stmt_allow_transfer_port_passing(self):
        """ Clause options/view/zone; Statement allow-transfer port; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_allow_transfer,
            'allow-transfer port 53 { localhost; localnets; };',
            {'allow_transfer': {'aml': [{'keyword': 'localhost'},
                                        {'keyword': 'localnets'}],
                                'ip_port': '53'}}
        )

    def test_isc_optviewzone_stmt_allow_transfer_transport_passing(self):
        """ Clause options/view/zone; Statement allow-transfer transport; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_allow_transfer,
            'allow-transfer transport mystring { localhost; localnets; };',
            {'allow_transfer': {'aml': [{'keyword': 'localhost'},
                                        {'keyword': 'localnets'}],
                                'fqdn_name': 'mystring'}}
        )

    def test_isc_optviewzone_stmt_allow_transfer_port_transport_passing(self):
        """ Clause options/view/zone; Statement allow-transfer port/transport; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_allow_transfer,
            'allow-transfer port 53 transport mystring { localhost; localnets; };',
            {'allow_transfer': {'aml': [{'keyword': 'localhost'},
                                        {'keyword': 'localnets'}],
                                'fqdn_name': 'mystring',
                                'ip_port': '53'}}
        )

    def test_isc_optviewzone_stmt_allow_transfer_localnet_passing(self):
        """ Clause options/view/zone; Statement allow-transfer; passing """
        test_string = [
            'allow-transfer { localhost; localnets; };',
        ]
        result = optviewzone_stmt_allow_transfer.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzone_stmt_allow_transfer_localnet2_passing(self):
        """ Clause options/view/zone; Statement allow-transfer; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_allow_transfer,
            'allow-transfer { localhost; localnets; };',
            {'allow_transfer': {'aml': [{'keyword': 'localhost'},
                                        {'keyword': 'localnets'}]}}
        )

    def test_isc_optviewzone_stmt_allow_update_on_passing(self):
        """ Clause options/view/zone; Statement allow-update; passing """
        test_string = [
            'allow-update-on { localhost; localnets; };',
        ]
        result = optviewzone_stmt_allow_update_on.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzone_stmt_allow_update_on_2_passing(self):
        """ Clause options/view/zone; Statement allow-update; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_allow_update_on,
            'allow-update-on { localhost; localnets; };',
            {'allow_update_on': {'aml': [{'keyword': 'localhost'},
                                         {'keyword': 'localnets'}]}}
        )

    def test_isc_optviewzone_stmt_allow_update_forwarding_passing(self):
        """ Clause options/view/zone; Statement allow-update-forwarding; passing """
        test_string = [
            'allow-update-forwarding { localhost; localnets; };',
        ]
        result = optviewzone_stmt_allow_update_forwarding.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_allow_update_forwarding,
            'allow-update-forwarding { localhost; localnets; };',
            {'allow_update_forwarding': {'aml': [{'keyword': 'localhost'},
                                                 {'keyword': 'localnets'}]}}
        )

    def test_isc_optviewzone_stmt_allow_update_passing(self):
        """ Clause options/view/zone; Statement allow-update; passing """
        test_string = [
            'allow-update { localhost; localnets; };',
        ]
        result = optviewzone_stmt_allow_update.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_allow_update,
            'allow-update { localhost; localnets; };',
            {'allow_update': {'aml': [{'keyword': 'localhost'},
                                      {'keyword': 'localnets'}]}}
        )

    def test_isc_optviewzone_stmt_allow_v6_synthesis_passing(self):
        """ Clause options/view/zone; Statement allow-v6-synthesis; passing """
        test_string = [
            'allow-v6-synthesis { localhost; localnets; };',
        ]
        result = optviewzone_stmt_allow_v6_synthesis.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_allow_v6_synthesis,
            'allow-v6-synthesis { localhost; localnets; };',
            {'allow_v6_synthesis': {'aml': [{'keyword': 'localhost'},
                                            {'keyword': 'localnets'}]}}
        )

    def test_isc_optviewzone_stmt_alt_transfer_source_v6_passing(self):
        """ Clause options/view/zone; Statement alt-transfer-source-v6; passing """
        test_string = [
            'alt-transfer-source-v6 *;',
            'alt-transfer-source-v6 * port *;',
            'alt-transfer-source-v6 * port * dscp 7;',
            'alt-transfer-source-v6 * dscp 7;',
            'alt-transfer-source-v6 * port 53 dscp 7;',
            'alt-transfer-source-v6 * port 53;',
            'alt-transfer-source-v6 fe0f::e;',
            'alt-transfer-source-v6 fe0f::e port *;',
            'alt-transfer-source-v6 fe0f::e port * dscp 7;',
            'alt-transfer-source-v6 fe0f::e dscp 7;',
            'alt-transfer-source-v6 fe0f::e port 53 dscp 7;',
            'alt-transfer-source-v6 fe0f::e port 53;',
        ]
        result = optviewzone_stmt_alt_transfer_source_v6.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_alt_transfer_source_v6,
            'alt-transfer-source-v6 fe0f::6 port 56;',
            {'alt_transfer_source_v6': {'ip6_addr': 'fe0f::6',
                                        'ip_port_w': '56'}}
        )

    def test_isc_optviewzone_stmt_alt_transfer_source_passing(self):
        """ Clause options/view/zone; Statement alt-transfer-source; passing """
        test_string = [
            'alt-transfer-source *;',
            'alt-transfer-source * port *;',
            'alt-transfer-source * port * dscp 7;',
            'alt-transfer-source * dscp 7;',
            'alt-transfer-source * port 53 dscp 7;',
            'alt-transfer-source * port 53;',
            'alt-transfer-source 2.2.2.2;',
            'alt-transfer-source 2.2.2.2 port *;',
            'alt-transfer-source 2.2.2.2 port * dscp 7;',
            'alt-transfer-source 2.2.2.2 dscp 7;',
            'alt-transfer-source 2.2.2.2 port 53 dscp 7;',
            'alt-transfer-source 2.2.2.2 port 53;',
        ]
        result = optviewzone_stmt_alt_transfer_source.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_alt_transfer_source,
            'alt-transfer-source 2.3.4.5 port * dscp 7;',
            {'alt_transfer_source': {'dscp_port': 7,
                                     'ip4_addr': '2.3.4.5',
                                     'ip_port_w': '*'}}
        )

    def test_isc_optviewzone_stmt_auto_dnssec_passing(self):
        """ Clause options/view/zone; Statement auto-dnssec; passing """
        test_string = [
            'auto-dnssec off;',
            'auto-dnssec maintain;',
            'auto-dnssec allow;',
        ]
        result = optviewzone_stmt_auto_dnssec.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_auto_dnssec,
            'auto-dnssec maintain;',
            {'auto_dnssec': 'maintain'}
        )

    def test_isc_optviewzone_stmt_check_sibling_passing(self):
        """ Clause options/view; Statement check-sibling; passing """
        test_string = [
            'check-sibling ignore;',
            'check-sibling warn;',
            'check-sibling fail;',
        ]
        result = optviewzone_stmt_check_sibling.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_check_sibling,
            'check-sibling fail;',
            {'check_sibling': 'fail'}
        )

    def test_isc_optviewzone_stmt_dialup_passing(self):
        """ Clause options/view/zone; Statement dialup; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_dialup,
            'dialup no;',
            {'dialup': 'no'}
        )

    def test_isc_optviewzone_stmt_dnskey_sig_validity(self):
        """ Clause options/view/zone; Statement 'dnskey-sig-validity'; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_dnskey_sig_validity,
            'dnskey-sig-validity 3660;',
            {'dnskey_sig_validity': 3660}
        )

    def test_isc_optviewzone_stmt_dnssec_dnskey_kskonly(self):
        """ Clause options/view/zone; Statement 'dnssec-dnskey-kskonly'; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_dnssec_dnskey_kskonly,
            'dnssec-dnskey-kskonly yes;',
            {'dnssec_dnskey_kskonly': 'yes'}
        )

    def test_isc_optviewzone_stmt_dnssec_loadkeys_interval_passing(self):
        """ Clause options/view/zone; Statement dnssec-loadkeys-interval; passing """
        test_string = [
            'dnssec-loadkeys-interval 3600;'
        ]
        result = optviewzone_stmt_dnssec_loadkeys_interval.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_dnssec_loadkeys_interval,
            'dnssec-loadkeys-interval 3600;',
            {'dnssec_loadkeys_interval': 3600}
        )

    def test_isc_optviewzone_stmt_dnssec_policy(self):
        """ Clause options/view/zone; Statement 'dnssec-policy'; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_dnssec_policy,
            'dnssec-policy my-policy;',
            {'dnssec_policy': 'my-policy'}
        )

    def test_isc_optviewzone_stmt_dnssec_secure_to_insecure(self):
        """ Clause options/view/zone; Statement 'dnssec-secure-to-insecure'; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_dnssec_secure_to_insecure,
            'dnssec-secure-to-insecure yes;',
            {'dnssec_secure_to_insecure': 'yes'}
        )

    def test_isc_optviewzone_stmt_dnssec_update_mode(self):
        """ Clause options/view/zone; Statement 'dnssec-update-mode'; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_dnssec_update_mode,
            'dnssec-update-mode no-resign;',
            {'dnssec_update_mode': 'no-resign'}
        )

    def test_isc_optviewzone_forwarders_group_element(self):
        """ Clause options/view/zone; Statement 'forwarders' group; passing"""
        assertParserResultDictTrue(
            forwarders_ip46_addr_prefix_port_element,
            '1.1.1.1 port 53;',
            {'ip_addr': '1.1.1.1', 'ip_port': '53'}
        )
        
    def test_isc_optviewzone_forwarders_group_series(self):
        """ Clause options/view/zone; Statement 'forwarders' group series 2-element; passing"""
        assertParserResultDictTrue(
            forwarders_ip46_addr_prefix_port_series,
            '1.1.1.1 port 53; ffa1::1 port 123 dscp 2;',
            {'forwarder': [{'ip_addr': '1.1.1.1', 'ip_port': '53'},
                           {'dscp_port': 2,
                            'ip_addr': 'ffa1::1',
                            'ip_port': '123'}]}
        )
        
    def test_isc_optviewzone_stmt_forwarders_passing(self):
        """ Clause options/view/zone; Statement forwarders; passing """
        test_string = [
            'forwarders { 1.1.1.1; };',
            'forwarders { 1.1.1.2 port 53; };',
            'forwarders { 1.1.1.3 port 54 dscp 6; };',
            'forwarders { 1.1.1.4 dscp 5; };',
            'forwarders { fe01::1; };',
            'forwarders { fe01::2 port 55; };',
            'forwarders { fe01::3 port 57 dscp 6; };',
            'forwarders { fe01::4 dscp 5; };',
            'forwarders port 53 { 1.1.1.1; };',
            'forwarders port 53  dscp 1 { 1.1.1.2 port 53; };',
            'forwarders dscp 2 { 1.1.1.3 port 54 dscp 6; };',
            'forwarders port 54 { fe01::1; };',
            'forwarders port 55 dscp 3 { fe01::2 port 55; };',
            'forwarders dscp 4 { fe01::3 port 57 dscp 6; };',
        ]
        result = optviewzone_stmt_forwarders.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzone_stmt_forwarders_passing_exact(self):
        """ Clause options/view/zone; Statement forwarders; exact passing """

        assertParserResultDictTrue(
            optviewzone_stmt_forwarders,
            'forwarders port 44  dscp 4 { 2.2.2.2 port 53; fe08::8 dscp 3; };',
            {'forwarders': {'dscp_port': 4,
                            'forwarder': [{'ip_addr': '2.2.2.2',
                                           'ip_port': '53'},
                                          {'dscp_port': 3,
                                           'ip_addr': 'fe08::8'}],
                            'ip_port': '44'}}
        )

    def test_isc_optviewzone_stmt_forward_passing(self):
        """ Clause options/view/zone; Statement forward; passing """
        test_string = [
            'forward first;',
            'forward only;',
        ]
        result = optviewzone_stmt_forward.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_forward,
            'forward only;',
            {'forward': 'only'}
        )

    def test_isc_optviewzone_stmt_ixfr_from_differences_passing(self):
        """ Clause options/view/zone; Statement ixfr-from-differences; passing """
        test_string = [
            'ixfr-from-differences master;',
            'ixfr-from-differences slave;',
            'ixfr-from-differences yes;',
            'ixfr-from-differences no;',
        ]
        result = optviewzone_stmt_ixfr_from_differences.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_ixfr_from_differences,
            'ixfr-from-differences master;',
            {'ixfr_from_differences': 'master'}
        )

    def test_isc_optviewzone_stmt_ixfr_tmp_file_passing(self):
        """ Clause options/view/zone; Statement ixfr-tmp-file; passing """
        test_string = [
            'ixfr-tmp-file "/tmp/junk.dat";'
        ]
        result = optviewzone_stmt_ixfr_tmp_file.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_ixfr_tmp_file,
            'ixfr-tmp-file "/tmp/junk.dat";',
            {'ixfr_tmp_file': '/tmp/junk.dat'}
        )

    def test_isc_optviewzone_stmt_key_directory_passing(self):
        """ Clause options/view/zone; Statement key-directory; passing """
        test_string = [
            'key-directory "/tmp/keydir/";'
        ]
        result = optviewzone_stmt_key_directory.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzone_stmt_key_directory_dict_passing(self):
        assertParserResultDictTrue(
            optviewzone_stmt_key_directory,
            'key-directory "/tmp/keydir/";',
            {'key_directory': '/tmp/keydir/'}
        )

    def test_isc_optviewzone_stmt_maintain_ixfr_base_passing(self):
        """ Clause options/view/zone; Statement maintain-ixfr-base; passing """
        test_string = [
            'maintain-ixfr-base yes;'
        ]
        result = optviewzone_stmt_maintain_ixfr_base.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_maintain_ixfr_base,
            'maintain-ixfr-base no;',
            {'maintain_ixfr_base': 'no'}
        )

    def test_isc_optviewzone_stmt_masterfile_format_passing(self):
        """ Clause options/view/zone; Statement masterfile-format; passing """
        test_string = [
            'masterfile-format raw;',
            'masterfile-format text;',
            # 'masterfile-format map;',  # removed in v9.19
        ]
        result = optviewzone_stmt_masterfile_format.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_masterfile_format,
            'masterfile-format text;',
            {'masterfile_format': 'text'}
        )

    def test_isc_optviewzone_stmt_masterfile_style_passing(self):
        """ Clause options/view/zone; Statement masterfile-style; passing """
        test_string = [
            'masterfile-style full;',
            'masterfile-style relative;',
        ]
        result = optviewzone_stmt_masterfile_style.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_masterfile_style,
            'masterfile-style full;',
            {'masterfile_style': 'full'}
        )

    def test_isc_optviewzone_stmt_max_ixfr_ratio_ut_passing(self):
        """ Clause options/view/zone; Statement 'max-ixfr-ratio' unittest; passing """
        test_string = [
            'max-ixfr-ratio 0%;',
            'max-ixfr-ratio 80%;',
            'max-ixfr-ratio 1000%;',
            'max-ixfr-ratio unlimited;'
        ]
        result = optviewzone_stmt_max_ixfr_ratio.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzone_stmt_max_ixfr_ratio_passing(self):
        """ Clause options/view/zone; Statement 'max-ixfr-ratio'; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_max_ixfr_ratio,
            'max-ixfr-ratio 1000%;',
            {'max-ixfr-ratio': 1000}
        )

    def test_isc_optviewzone_stmt_max_journal_size_passing(self):
        """ Clause options/view/zone; Statement max-journal-size; passing """
        test_string = [
            'max-journal-size 30000;'
        ]
        result = optviewzone_stmt_max_journal_size.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_max_journal_size,
            'max-journal-size 3M;',
            {'max_journal_size': [3, 'M']}
        )

    def test_isc_optviewzone_stmt_max_records_passing(self):
        """ Clause options/view/zone; Statement max-records; passing """
        test_string = [
            'max-records 3600;'
        ]
        result = optviewzone_stmt_max_records.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_max_records,
            'max-records 3600;',
            {'max_records': 3600}
        )

    def test_isc_optviewzone_stmt_max_refresh_time_passing(self):
        """ Clause options/view/zone; Statement max-refresh-time; passing """
        test_string = [
            'max-refresh-time 3600;'
        ]
        result = optviewzone_stmt_max_refresh_time.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_max_refresh_time,
            'max-refresh-time 3600;',
            {'max_refresh_time': 3600}
        )

    def test_isc_optviewzone_stmt_max_retry_time_passing(self):
        """ Clause options/view/zone; Statement max-retry-time; passing """
        test_string = [
            'max-retry-time 3600;'
        ]
        result = optviewzone_stmt_max_retry_time.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_max_retry_time,
            'max-retry-time 3600;',
            {'max_retry_time': 3600}
        )

    def test_isc_optviewzone_stmt_max_transfer_time_in_passing(self):
        """ Clause options/view/zone; Statement max-transfer-time-in; passing """
        test_string = [
            'max-transfer-time-in 3600;'
        ]
        result = optviewzone_stmt_max_transfer_time_in.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_max_transfer_time_in,
            'max-transfer-time-in 3600;',
            {'max_transfer_time_in': 3600}
        )

    def test_isc_optviewzone_stmt_max_transfer_time_out_passing(self):
        """ Clause options/view/zone; Statement max-transfer-time-out; passing """
        test_string = [
            'max-transfer-time-out 3600;'
        ]
        result = optviewzone_stmt_max_transfer_time_out.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_max_transfer_time_out,
            'max-transfer-time-out 3600;',
            {'max_transfer_time_out': 3600}
        )

    def test_isc_optviewzone_stmt_max_transfer_idle_in_passing(self):
        """ Clause options/view/zone; Statement max-transfer-idle-in; passing """
        test_string = [
            'max-transfer-idle-in 3600;'
        ]
        result = optviewzone_stmt_max_transfer_idle_in.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_max_transfer_idle_in,
            'max-transfer-idle-in 3600;',
            {'max_transfer_idle_in': 3600}
        )

    def test_isc_optviewzone_stmt_max_transfer_idle_out_passing(self):
        """ Clause options/view/zone; Statement max-transfer-idle-out; passing """
        test_string = [
            'max-transfer-idle-out 3600;'
        ]
        result = optviewzone_stmt_max_transfer_idle_out.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_max_transfer_idle_out,
            'max-transfer-idle-out 3600;',
            {'max_transfer_idle_out': 3600}
        )

    def test_isc_optviewzone_stmt_min_refresh_time_passing(self):
        """ Clause options/view/zone; Statement min-refresh-time; passing """
        test_string = [
            'min-refresh-time 3600;'
        ]
        result = optviewzone_stmt_min_refresh_time.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_min_refresh_time,
            'min-refresh-time 3600;',
            {'min_refresh_time': 3600}
        )

    def test_isc_optviewzone_stmt_min_retry_time_passing(self):
        """ Clause options/view/zone; Statement min-retry-time; passing """
        test_string = [
            'min-retry-time 3600;'
        ]
        result = optviewzone_stmt_min_retry_time.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzone_stmt_min_retry_time_failing(self):
        """ Clause options/view/zone; Statement min-retry-time; failing """
        assertParserResultDictFalse(
            optviewzone_stmt_min_retry_time,
            'min-retry-time 3H;',
            {'min_retry_time': 3600}
        )

    def test_isc_optviewzone_stmt_multi_master_passing(self):
        """ Clause options/view/zone; Statement multi-master; passing """
        test_string = [
            'multi-master yes;'
        ]
        result = optviewzone_stmt_multi_master.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_multi_master,
            'multi-master no;',
            {'multi_master': 'no'}
        )

    def test_isc_optviewzone_stmt_notify(self):
        test_data = [
            'notify explicit;',
            'notify primary-only;',
            'notify master-only;',
            'notify yes;',
            'notify no;',
        ]
        result = optviewzone_stmt_notify.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzone_stmt_notify_source_v6_passing(self):
        """ Clause options/view/zone; Statement notify-source-v6; passing """
        test_string = [
            'notify-source-v6 *;',
            'notify-source-v6 * port 53;',
            'notify-source-v6 * port *;',
            'notify-source-v6 * port 153 dscp 1;',
            'notify-source-v6 * port * dscp 1;',
            'notify-source-v6 * dscp 1;',
            'notify-source-v6 fe11::1;',
            'notify-source-v6 fe11::1 port *;',
            'notify-source-v6 fe11::1 port 253;',
            'notify-source-v6 fe11::1 port * dscp 2;',
            'notify-source-v6 fe11::1 port 353 dscp 2;',
            'notify-source-v6 fe11::1 dscp 3;',
        ]
        result = optviewzone_stmt_notify_source_v6.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_notify_source_v6,
            'notify-source-v6 fe11::123 port * dscp 5;',
            {'notify_source_v6': {'ip6_addr': 'fe11::123',
                                  'dscp_port': 5,
                                  'ip_port_w': '*'}}
        )

    def test_isc_optviewzone_stmt_notify_source_passing(self):
        """ Clause options/view/zone; Statement notify-source; passing """
        test_string = [
            'notify-source *;',
            'notify-source * port 53;',
            'notify-source * port *;',
            'notify-source * port 153 dscp 1;',
            'notify-source * port * dscp 1;',
            'notify-source * dscp 1;',
            'notify-source 1.1.1.1;',
            'notify-source 2.2.2.2 port *;',
            'notify-source 3.3.3.3 port 253;',
            'notify-source 4.4.4.4 port * dscp 2;',
            'notify-source 5.5.5.5 port 353 dscp 2;',
            'notify-source 6.6.6.6 dscp 3;',
        ]
        result = optviewzone_stmt_notify_source.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzone_stmt_notify_source_2_passing(self):
        """ Clause options/view/zone; Statement notify-source 2; passing """
        assertParserResultDictTrue(
            optviewzone_stmt_notify_source,
            'notify-source * port 153 dscp 1;',
            {'notify_source': {'dscp_port': 1,
                               'ip4_addr-w': '*',
                               'ip4_port_w': '153'}}
        )

    def test_isc_optviewzone_stmt_notify_passing(self):
        """ Clause options/view/zone; Statement notify; passing """
        test_string = [
            'notify explicit;',
            'notify master-only;',
            'notify yes;',
            'notify no;',
        ]
        result = optviewzone_stmt_notify.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_notify,
            'notify master-only;',
            {'notify': 'master-only'}
        )

    def test_isc_optviewzone_stmt_notify_delay_passing(self):
        """ Clause options/view/zone; Statement 'notify-delay'; passing """
        test_string = [
            'notify-delay 0;',  # minimum
            'notify-delay 60;',  # default
            'notify-delay 1024;'  # maximum
        ]
        result = optviewzone_stmt_notify_delay.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_notify_delay,
            'notify-delay 60;',  # default
            {'notify_delay': 60}
        )

    #     optviewzone_stmt_provide_ixfr, \
    def test_isc_optviewzone_stmt_provide_ixfr_passing(self):
        """ Clause options/view/zone; Statement provide-ixfr; passing """
        test_string = [
            'provide-ixfr yes;'
        ]
        result = optviewzone_stmt_provide_ixfr.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_provide_ixfr,
            'provide-ixfr no;',
            {'provide_ixfr': 'no'}
        )

    def test_isc_optviewzone_stmt_request_ixfr_passing(self):
        """ Clause options/view/zone; Statement request-ixfr; passing """
        test_string = [
            'request-ixfr yes;'
        ]
        result = optviewzone_stmt_request_ixfr.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_request_ixfr,
            'request-ixfr no;',
            {'request_ixfr': 'no'}
        )

    def test_isc_optviewzone_stmt_request_nsid_passing(self):
        """ Clause options/view/zone; Statement request-nsid; passing """
        test_string = [
            'request-nsid yes;'
        ]
        result = optviewzone_stmt_request_nsid.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_request_nsid,
            'request-nsid no;',
            {'request_nsid': 'no'}
        )

    def test_isc_optviewzone_stmt_sig_validity_interval_passing(self):
        """ Clause options/view/zone; Statement sig-validity-interval; passing """
        test_string = [
            'sig-validity-interval 7;'
        ]
        result = optviewzone_stmt_sig_validity_interval.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_sig_validity_interval,
            'sig-validity-interval 30;',
            {'sig_validity_interval': 30}
        )

    def test_isc_optviewzone_stmt_transfer_source_v6_passing(self):
        """ Clause options/view/zone; Statement transfer-source-v6; passing """
        test_string = [
            'transfer-source-v6 fe12::1;',
            'transfer-source-v6 fe12::2 port 53;',
            'transfer-source-v6 fe12::3 port *;',
            'transfer-source-v6 fe12::4 port 53 dscp 1;',
            'transfer-source-v6 fe12::5 port * dscp 1;',
            'transfer-source-v6 fe12::6 dscp 2;',
            'transfer-source-v6 *;',
            'transfer-source-v6 * port 53;',
            'transfer-source-v6 * port *;',
            'transfer-source-v6 * port 53 dscp 1;',
            'transfer-source-v6 * port * dscp 1;',
            'transfer-source-v6 * dscp 2;',
        ]
        result = optviewzone_stmt_transfer_source_v6.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_transfer_source_v6,
            'transfer-source-v6 fe12::5 port * dscp 1;',
            {'transfer_source_v6': {'ip6_addr': 'fe12::5',
                                    'dscp_port': 1,
                                    'ip_port_w': '*'}}
        )

    def test_isc_optviewzone_stmt_transfer_format_passing(self):
        """ Clause options/view/zone; Statement transfer_format; passing """
        test_string = [
            'transfer-format one-answer;',
            'transfer-format many-answers;',
        ]
        result = optviewzone_stmt_transfer_format.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_transfer_format,
            'transfer-format one-answer;',
            {'transfer_format': 'one-answer'}
        )

    def test_isc_optviewzone_stmt_transfer_source_passing(self):
        """ Clause options/view/zone; Statement transfer-source; passing """
        test_string = [
            'transfer-source 1.1.1.1;',
            'transfer-source 2.2.2.2 port 53;',
            'transfer-source 3.3.3.3 port *;',
            'transfer-source 4.4.4.4 port 53 dscp 1;',
            'transfer-source 5.5.5.5 port * dscp 1;',
            'transfer-source 6.6.6.6 dscp 2;',
            'transfer-source *;',
            'transfer-source * port 53;',
            'transfer-source * port *;',
            'transfer-source * port 53 dscp 1;',
            'transfer-source * port * dscp 1;',
            'transfer-source * dscp 2;',
        ]
        result = optviewzone_stmt_transfer_source.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_transfer_source,
            'transfer-source 4.4.4.4 port 53 dscp 1;',
            {'transfer_source': {'ip4_addr': '4.4.4.4',
                                 'dscp_port': 1,
                                 'ip_port_w': '53'}}
        )

    def test_isc_optviewzone_stmt_use_alt_transfer_source_passing(self):
        """ Clause options/view/zone; Statement use-alt-transfer-source; passing """
        test_string = [
            'use-alt-transfer-source yes;'
        ]
        result = optviewzone_stmt_use_alt_transfer_source.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_use_alt_transfer_source,
            'use-alt-transfer-source no;',
            {'use_alt_transfer_source': 'no'}
        )

    def test_isc_optviewzone_stmt_zone_statistics_passing(self):
        """ Clause options/view/zone; Statement zone-statistics; passing """
        test_string = [
            'zone-statistics yes;'
        ]
        result = optviewzone_stmt_zone_statistics.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_stmt_zone_statistics,
            'zone-statistics no;',
            {'zone_statistics': 'no'}
        )

    def test_isc_optviewzone_statements_set_passing(self):
        """ Clause optviewzone; Statement statements_set; passing """
        test_string = [
            'use-alt-transfer-source yes;',
            'transfer-format many-answers;',
            'zone-statistics yes;',
            'transfer-source 4.4.4.4 port 53 dscp 1;',
            'min-refresh-time 3600;',
            'max-transfer-idle-out 3600;',
            'transfer-source-v6 fe12::4 port 53 dscp 1;',
            'max-journal-size 30000;',
            'notify master-only;',
            'masterfile-format text;',
            'max-refresh-time 3600;',
            'maintain-ixfr-base yes;',
            'dnssec-loadkeys-interval 3600;',
            'ixfr-tmp-file "/tmp/junk.dat";',
            'notify-source 3.3.3.3 port 253;',
            'max-retry-time 3600;',
            'notify-source-v6 * port 53;',
            'sig-validity-interval 7;',
            'forwarders port 53 { 1.1.1.1; };',
            'multi-master yes;',
            'provide-ixfr yes;',
            'dialup yes;',
            'ixfr-from-differences slave;',
            'max-transfer-time-in 3600;',
            'key-directory "/tmp/keydir/";',
            'min-retry-time 3600;',
            'request-nsid yes;',
            'alt-transfer-source *;',
            'forward only;',
            'max-transfer-idle-in 3600;',
            'alt-transfer-source-v6 * port 53 dscp 7;',
            'request-ixfr yes;',
            'auto-dnssec maintain;',
            'max-transfer-time-out 3600;',
            'allow-v6-synthesis { localhost; localnets; };',
            'allow-v6-synthesis { localhost; localnets; };',
            'allow-update { localhost; localnets; };',
            'allow-update-forwarding { localhost; localnets; };',
            'allow-notify { localhost; localnets; };',
            'allow-update-on { any; };',
            'allow-update { localhost; localnets; };',
            'allow-transfer { localhost; localnets; };',
            'allow-transfer transport "transport_string" { localhost; localnets; };',
            'allow-transfer port 53 { localhost; localnets; };',
            'allow-transfer port 54 transport "transport_string" { localhost; localnets; };',
            'allow-transfer transport "transport_string" port 55 { localhost; localnets; };',
            'allow-update-on { any; };',
            'allow-update { localhost; localnets; };',
            'allow-query-on { any; };',
            'allow-query { any; };',
        ]
        result = optviewzone_statements_set.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            optviewzone_statements_set,
            'allow-update { localhost; localnets; };',
            {'allow_update': {'aml': [{'keyword': 'localhost'},
                                      {'keyword': 'localnets'}]}}
        )

    def test_isc_optviewzone_stmt_statements_set_failing(self):
        """ Clause optviewzone; Statement statements_set; failing """
        test_string = [
            'statements_set "YYYY";',
        ]
        result = optviewzone_statements_set.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_optviewzone_statements_series_passing2(self):
        """ Clause optviewzone; Statement optviewzone_statements_series 2; passing """
        assertParserResultDictTrue(
            optviewzone_statements_series,
            'use-alt-transfer-source yes;' +
            'transfer-format many-answers;' +
            'zone-statistics yes;' +
            'transfer-source 4.4.4.4 port 53 dscp 1;' +
            'min-refresh-time 3600;' +
            'max-transfer-idle-out 3600;' +
            'transfer-source-v6 fe12::4 port 53 dscp 1;' +
            'max-journal-size 30000;' +
            'notify master-only;' +
            'masterfile-format text;' +
            'max-refresh-time 3600;' +
            'maintain-ixfr-base yes;' +
            'dnssec-loadkeys-interval 3600;' +
            'ixfr-tmp-file "/tmp/junk.dat";' +
            'notify-source 3.3.3.3 port 253;' +
            'check-sibling warn;' +
            'max-retry-time 3600;' +
            'notify-source-v6 * port 53;' +
            'sig-validity-interval 7;' +
            'forwarders port 53 { 1.1.1.1; };' +
            'multi-master yes;' +
            'provide-ixfr yes;' +
            'dialup yes;' +
            'ixfr-from-differences slave;' +
            'max-transfer-time-in 3600;' +
            'key-directory "/tmp/keydir/";' +
            'min-retry-time 3600;' +
            'request-nsid yes;' +
            'alt-transfer-source *;' +
            'forward only;' +
            'max-transfer-idle-in 3600;' +
            'alt-transfer-source-v6 * port 53 dscp 7;' +
            'request-ixfr yes;' +
            'auto-dnssec maintain;' +
            'max-transfer-time-out 3600;' +
            'allow-v6-synthesis { localhost; localnets; };' +
            'allow-v6-synthesis { localhost; localnets; };' +
            'allow-update { localhost; localnets; };' +
            'allow-update-forwarding { localhost; localnets; };' +
            'allow-notify { localhost; localnets; };' +
            'allow-update-on { any; };' +
            'allow-update { localhost; localnets; };' +
            'allow-transfer { localhost; localnets; };' +
            'allow-update-on { any; };' +
            'allow-update { localhost; localnets; };' +
            'allow-query-on { any; };' +
            'allow-query { any; };',
            {'allow_notify': {'aml': [{'keyword': 'localhost'},
                                      {'keyword': 'localnets'}]},
             'allow_query': {'aml': [{'keyword': 'any'}]},
             'allow_query_on': {'aml': [{'keyword': 'any'}]},
             'allow_transfer': {'aml': [{'keyword': 'localhost'},
                                        {'keyword': 'localnets'}]},
             'allow_update': {'aml': [{'keyword': 'localhost'},
                                      {'keyword': 'localnets'}]},
             'allow_update_forwarding': {'aml': [{'keyword': 'localhost'},
                                                 {'keyword': 'localnets'}]},
             'allow_update_on': {'aml': [{'keyword': 'any'}]},
             'allow_v6_synthesis': {'aml': [{'keyword': 'localhost'},
                                            {'keyword': 'localnets'}]},
             'alt_transfer_source': ['*'],
             'alt_transfer_source_v6': {'dscp_port': 7, 'ip_port_w': '53'},
             'auto_dnssec': 'maintain',
             'check_sibling': 'warn',
             'dialup': 'yes',
             'dnssec_loadkeys_interval': 3600,
             'forward': 'only',
             'forwarders': {'forwarder': [{'ip_addr': '1.1.1.1'}],
                            'ip_port': '53'},
             'ixfr_from_differences': 'slave',
             'ixfr_tmp_file': '/tmp/junk.dat',
             'key_directory': '/tmp/keydir/',
             'maintain_ixfr_base': 'yes',
             'masterfile_format': 'text',
             'max_journal_size': [30000],
             'max_refresh_time': 3600,
             'max_retry_time': 3600,
             'max_transfer_idle_in': 3600,
             'max_transfer_idle_out': 3600,
             'max_transfer_time_in': 3600,
             'max_transfer_time_out': 3600,
             'min_refresh_time': 3600,
             'min_retry_time': 3600,
             'multi_master': 'yes',
             'notify': 'master-only',
             'notify_source': {'ip4_addr-w': '3.3.3.3', 'ip4_port_w': '253'},
             'notify_source_v6': {'ip6_addr': '*', 'ip_port_w': '53'},
             'provide_ixfr': 'yes',
             'request_ixfr': 'yes',
             'request_nsid': 'yes',
             'sig_validity_interval': 7,
             'transfer_format': 'many-answers',
             'transfer_source': {'dscp_port': 1,
                                 'ip4_addr': '4.4.4.4',
                                 'ip_port_w': '53'},
             'transfer_source_v6': {'dscp_port': 1,
                                    'ip6_addr': 'fe12::4',
                                    'ip_port_w': '53'},
             'use_alt_transfer_source': 'yes',
             'zone_statistics': 'yes'}
        )

    def test_isc_optviewzone_stmt_statements_series_failing(self):
        """ Clause optviewzone; Statement statements_series; failing """
        test_string = [
            'statements_series "YYYY";',
        ]
        result = optviewzone_statements_series.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()
