#!/usr/bin/env python3
"""
File: test_zone.py

Description:  Performs unit test on the isc_zone.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue, assertParserResultDictFalse
from bind9_parser.isc_zone import \
    zone_stmt_delegation_only,\
    zone_stmt_check_names,\
    zone_stmt_file,\
    zone_stmt_in_view, \
    zone_stmt_inline_signing,\
    zone_stmt_ixfr_base,\
    zone_stmt_ixfr_from_differences,\
    zone_stmt_journal,\
    zone_masters_set,\
    zone_masters_series,\
    zone_multiple_stmt_masters,\
    zone_stmt_masters,\
    zone_stmt_pubkey,\
    zone_stmt_server_addresses,\
    zone_stmt_server_names,\
    zone_stmt_type,\
    zone_update_policy_name_and_rr_type_fields,\
    zone_update_policy_rr_type_series,\
    zone_update_policy_matchtype,\
    zone_update_policy_matchtype_krb5_self,\
    zone_stmt_update_policy_nonlocal,\
    zone_stmt_update_policy_nonlocal_series, \
    zone_stmt_update_policy,\
    zone_stmt_use_id_pool,\
    zone_statements_set,\
    zone_statements_series


class TestZone(unittest.TestCase):
    """ Clause zone; things found only under 'zone' clause """
    def test_isc_zone_stmt_check_names_passing(self):
        """ Clause zone; Statement check-names; passing """
        test_string = [
            'check-names fail;',
            'check-names warn;',
            'check-names ignore;',
        ]
        result = zone_stmt_check_names.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            zone_stmt_check_names,
            'check-names fail;',
            {'check_names': 'fail'}
        )

    def test_isc_zone_stmt_check_names_failing(self):
        """ Clause zone; Statement check-names; failing """
        test_string = [
            'check-names warning;',
            'check-names failed;',
            'check-names ignored;',
        ]
        result = zone_stmt_check_names.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_zone_stmt_delegation_only_passing(self):
        """ Clause zone; Statement delegation-only; passing """
        test_string = [
            'delegation-only yes;',
        ]
        result = zone_stmt_delegation_only.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            zone_stmt_delegation_only,
            'delegation-only no;',
            {'delegation-only': 'no'}
        )

    def test_isc_zone_stmt_delegation_only_failing(self):
        """ Clause zone; Statement delegation-only; failing """
        test_string = [
            'delegation-only Nah;',
        ]
        result = zone_stmt_delegation_only.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_zone_stmt_file_passing(self):
        """ Clause zone; Statement file; passing """
        test_string = [
            'file "/var/lib/bind9/public/masters/db.example.org";',
            'file \'/var/lib/bind9/internal/dynamic/db.local\';',
        ]
        result = zone_stmt_file.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            zone_stmt_file,
            'file \'/var/lib/bind9/public/slaves/db.example.org\';',
            {'file': '\'/var/lib/bind9/public/slaves/db.example.org\''}
        )

    def test_isc_zone_stmt_file_failing(self):
        """ Clause zone; Statement file; failing """
        test_string = [
            'file "/etc/junk-file.txt"',
        ]
        result = zone_stmt_file.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_zone_stmt_in_view_passing(self):
        """ Clause zone; Statement in_view; passing """
        test_string = [
            'in-view dmz_view;',
        ]
        result = zone_stmt_in_view.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            zone_stmt_in_view,
            'in-view dmz_view;',
            {'in_view': 'dmz_view'}
        )

    def test_isc_zone_stmt_in_view_failing(self):
        """ Clause zone; Statement in_view; failing """
        test_string = [
            'in-view /var/tmp;',
        ]
        result = zone_stmt_in_view.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_zone_stmt_zone_stmt_inline_signing_passing(self):
        """ Clause zone; Statement zone_stmt_inline_signing; passing """
        test_string = [
            'inline-signing no;',
        ]
        result = zone_stmt_inline_signing.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            zone_stmt_inline_signing,
            'inline-signing no;',
            {'inline-signing': 'no'}
        )

    def test_isc_zone_stmt_inline_signing_failing(self):
        """ Clause zone; Statement inline_signing; failing """
        test_string = [
            'inline_signing "YYYY";',
        ]
        result = zone_stmt_inline_signing.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


    def test_isc_zone_stmt_ixfr_base_passing(self):
        """ Clause zone; Statement ixfr-base; passing """
        test_string = [
            'ixfr-base ixfr_file_basename;',
        ]
        result = zone_stmt_ixfr_base.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            zone_stmt_ixfr_base,
            'ixfr-base custom_file_basename_goes_here;',
            {'ixfr_base': 'custom_file_basename_goes_here'}
        )

    def test_isc_zone_stmt_ixfr_base_failing(self):
        """ Clause zone; Statement ixfr_base; failing """
        test_string = [
            'ixfr-base /tmp/should_not_use/subdirectory/here";',
        ]
        result = zone_stmt_ixfr_base.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


    def test_isc_zone_stmt_ixfr_from_differences_passing(self):
        """ Clause zone; Statement ixfr-from-differences; passing """
        test_string = [
            'ixfr-from-differences yes;',
        ]
        result = zone_stmt_ixfr_from_differences.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            zone_stmt_ixfr_from_differences,
            'ixfr-from-differences False;',
            {'ixfr_from_differences': 'False'}
        )

    def test_isc_zone_stmt_ixfr_from_differences_failing(self):
        """ Clause zone; Statement ixfr_from_differences; failing """
        test_string = [
            'ixfr-from-differences "YYYY";',
        ]
        result = zone_stmt_ixfr_from_differences.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


    def test_isc_zone_stmt_journal_passing(self):
        """ Clause zone; Statement journal; passing """
        test_string = [
            'journal /var/lib/logging/deep/in/somewhere/journal.log;',
        ]
        result = zone_stmt_journal.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            zone_stmt_journal,
            'journal /var/lib/logging/deep/in/somewhere/journal.log;',
            {'journal': '/var/lib/logging/deep/in/somewhere/journal.log'}
        )

    def test_isc_zone_stmt_journal_failing(self):
        """ Clause zone; Statement journal; failing """
        test_string = [
            'journal "/subdire\nctory/should/not/be/used/here";',
        ]
        result = zone_stmt_journal.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_zone_stmt_masters_set_passing(self):
        """ Clause zone; Set, masters; passing """
        assertParserResultDictTrue(
            zone_masters_set,
            'another_bastion_host_group key priv_dns_chan_key0;',
            {'key_id': 'priv_dns_chan_key0',
             'master_name': 'another_bastion_host_group'}
        )
        assertParserResultDictTrue(
            zone_masters_set,
            'fe02::1 key priv_dns_chan_key0;',
            {'ip6': 'fe02::1', 'key_id': 'priv_dns_chan_key0'}
        )
        assertParserResultDictTrue(
            zone_masters_set,
            '4.4.4.4 key priv_dns_chan_key0;',
            {'ip4': '4.4.4.4', 'key_id': 'priv_dns_chan_key0'}
        )

#    @unittest.skip("skipping zone's masters_series passing")
    def test_isc_zone_stmt_masters_series_passing(self):
        """ Clause zone; Series, masters; passing """
        assertParserResultDictTrue(
            zone_masters_series,
            'another_bastion_host_group key priv_dns_chan_key0; 5.5.5.5 port 6553 key secret_dmz_key;',
            {'masters_group': [{'key_id': 'priv_dns_chan_key0',
                                'master_name': 'another_bastion_host_group'},
                               {'ip4': '5.5.5.5',
                                'key_id': 'secret_dmz_key'}]}
        )

    def test_isc_zone_stmt_masters_passing(self):
        """ Clause zone; Statement masters; passing """
        test_string = [
            'masters port 553 dscp 7 { red_masters key priv_dns_chan_key1; };',
            'masters port 563 dscp 7 { ffe1::1 port 5583; };',
            'masters port 573 dscp 6 { 12.13.14.15 port 5553 key priv_dns_chan_key2; };',
        ]
        result = zone_stmt_masters.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_zone_stmt_masters_dict_passing(self):
        assertParserResultDictTrue(
            zone_stmt_masters,
            'masters port 553 dscp 7 { red_masters key priv_dns_chan_key1; };',
            {'masters': {'dscp_port': 7,
                         'ip_port': 553,
                         'masters_group': [{'key_id': 'priv_dns_chan_key1',
                                           'master_name': 'red_masters'}],
                         }
             }
        )

    def test_isc_zone_stmt_masters_failing(self):
        """ Clause zone; Statement masters; failing """
        test_string = [
            'masters "YYYY";',
        ]
        result = zone_stmt_masters.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

#  TODO: Need to investigate on the de-introduction of 'masters' statement for 'zone clause'.

    def test_isc_zone_statements_series_multiple_masters_passing(self):
        """ Clause zone; Statement, multiple masters; passing """
        # Only one masters statement is allowed in zone clause, so get the last one
        assertParserResultDictFalse(
            zone_statements_series,
            'masters dmz_masters port 7552 dscp 5 { yellow_masters key priv_dns_chan_key5; }; ' +
            'masters bastion_hosts port 1024 dscp 6 { fe08::1 port 77; };',
            {'masters': [{'dscp_port': 6,
                          'ip_port': 1025,
                          'master_id': 'bastion_hosts',
                          'master_list': [{'addr': 'fe08::1',
                                           'ip_port': 77}]}]}
        )

    def test_isc_zone_stmt_pubkey_passing(self):
        """ Clause zone; Statement pubkey; passing """
        test_string = [
            'pubkey 53 251;',
            'pubkey 53 251 7;',
            'pubkey 53 251 7 "asdfasddfasdfasdf";',
        ]
        result = zone_stmt_pubkey.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            zone_stmt_pubkey,
            'pubkey 53 251 7 "asdfasddfasdfasdf";',
            {'pubkey': {'algorithms': 7,
                        'flags': 53,
                        'key_secret': 'asdfasddfasdfasdf',
                        'protocol': 251}}
        )

    def test_isc_zone_stmt_pubkey_failing(self):
        """ Clause zone; Statement pubkey; failing """
        test_string = [
            'pubkey "YYYY";',
        ]
        result = zone_stmt_pubkey.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


    def test_isc_zone_stmt_server_addresses_passing(self):
        """ Clause zone; Statement server-addresses; passing """
        test_string = [
            'server-addresses { 7.7.7.7; fe77::1; };',
        ]
        result = zone_stmt_server_addresses.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            zone_stmt_server_addresses,
            'server-addresses { fb03::7 port 9553; 9.9.9.9; };',
            {'server_addresses': [{'addr': 'fb03::7', 'ip_port': 9553},
                                   {'addr': '9.9.9.9'}]}
        )

    def test_isc_zone_stmt_server_addresses_failing(self):
        """ Clause zone; Statement server-addresses; failing """
        test_string = [
            'server-addresses "YYYY";',
        ]
        result = zone_stmt_server_addresses.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_zone_stmt_server_names_passing(self):
        """ Clause zone; Statement server-names; passing """
        test_string = [
            'server-names { "example.com"; };',
        ]
        result = zone_stmt_server_names.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            zone_stmt_server_names,
            'server-names { "bastion.example.com"; "hidden.example.com"; };',
            {'server_names': ['bastion.example.com', 'hidden.example.com']}
        )
        assertParserResultDictTrue(
            zone_stmt_server_names,
            'server-names { "www.example.com"; };',
            {'server_names': ['www.example.com']}
        )

    def test_isc_zone_stmt_server_names_failing(self):
        """ Clause zone; Statement server-names; failing """
        test_string = [
            'server-names "YYYY";',
        ]
        result = zone_stmt_server_names.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


    def test_isc_zone_stmt_type_passing(self):
        """ Clause zone; Statement type; passing """
        test_string = [
            'type delegation-only;',
            'type forward;',
            'type hint;',
            'type in-view;',
            'type master;',
            'type primary;',   # same as 'master' type
            'type redirect;',
            'type slave;',
            'type secondary;',  # same as 'slave' type
            'type static-stub;',
            'type stub;',
        ]
        result = zone_stmt_type.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            zone_stmt_type,
            'type delegation-only;',
            {'type': 'delegation-only'}
        )

    def test_isc_zone_stmt_type_failing(self):
        """ Clause zone; Statement type; failing """
        test_string = [
            'type "YYYY";',
        ]
        result = zone_stmt_type.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])



    def test_isc_zone_stmt_update_policy_rr_type_series_passing(self):
        """ Clause zone; Statement update_policy_rr_type_series; passing """
        test_string = [
            'any',
            'wks hinfo txt',
            'SRV',
            'any',
            '*',
        ]
        result = zone_update_policy_rr_type_series.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            zone_update_policy_rr_type_series,
            'wks hinfo txt',
            {'rr_types': ['WKS', 'HINFO', 'TXT']}
        )

    def test_isc_zone_stmt_update_policy_rr_type_failing(self):
        """ Clause zone; Statement update-policy-nonlocal; failing """
        test_string = [
            'text',
            'address',
        ]
        result = zone_update_policy_rr_type_series.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_zone_stmt_update_policy_name_and_rr_type_fields_passing(self):
        """ Clause zone; Statement update_policy_name_and_rr_type_fields; passing """
        test_string = [
            'domain_name *',
            'example.com any',
            'acme.net MX TXT NS',
            'global.gov *',
        ]
        result = zone_update_policy_name_and_rr_type_fields.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_zone_stmt_update_policy_name_and_rr_type_fields_dict_passing(self):
        assertParserResultDictTrue(
            zone_update_policy_name_and_rr_type_fields,
            'www.example.com mx ns caa wks hinfo txt',
            {'impacting_zone': 'www.example.com',
             'rr_types': ['MX', 'NS', 'CAA', 'WKS', 'HINFO', 'TXT']}
        )


    def test_isc_zone_stmt_update_policy_matchtype_krb5_self_dict_passing(self):
        assertParserResultDictTrue(
            zone_update_policy_matchtype_krb5_self,
            'krb5-self www.example.com mx ns caa wks hinfo txt',
            { 'impacting_realm': 'www.example.com',
              'policy': 'krb5-self',
              'rr_types': ['MX', 'NS', 'CAA', 'WKS', 'HINFO', 'TXT']}
        )

    def test_isc_zone_stmt_update_policy_matchtype_passing(self):
        """ Clause zone; Statement update_policy_matchtype; passing """
        test_string = [
            '8to6-self example1.com mx',
            'external "example1.com" CAA',
            'krb5-self "example3.com" srv',
            'krb5-subdomain example4.com TXT',
            'ms-self example5.com hinfo',
            'ms-subdomain example6.com X25',
            'name example7.com a',
            'self example8.com PTR',
            'selfsub example9.com cname',
            'selfwildcard example10.com openpgpkey',
            'tcp-self example11.com wks',
            'wildcard example12.com nsec',
            'zonesub nsec3',
            'subdomain tlsa',
        ]
        result = zone_update_policy_matchtype.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_zone_stmt_update_policy_matchtype_dict_passing(self):
        assertParserResultDictTrue(
            zone_update_policy_matchtype,
            'krb5-self www.example.com mx ns caa wks hinfo txt',
            {'impacting_realm': 'www.example.com',
             'policy': 'krb5-self',
             'rr_types': ['MX', 'NS', 'CAA', 'WKS', 'HINFO', 'TXT']}
        )

    def test_isc_zone_stmt_update_policy_nonlocal_passing(self):
        """ Clause zone; Statement update_policy_nonlocal; passing """
        test_string = [
            'grant local-ddns zonesub any;',
            'deny local-dyndns subdomain wks hinfo txt;',
            'deny local-dyndns subdomain SRV;',
        ]
        result = zone_stmt_update_policy_nonlocal.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_zone_stmt_update_policy_nonlocal_krb5_self_passing(self):
        assertParserResultDictTrue(
            zone_stmt_update_policy_nonlocal,
            'grant "zero_dmz" krb5-self example.com nsec nsec3 wks mx;',
            {'impacting_realm': 'example.com',
             'permission': 'grant',
             'policy': 'krb5-self',
             'requestor_domain': '"zero_dmz"',
             'rr_types': ['NSEC', 'NSEC3', 'WKS', 'MX']}
        )

    def test_isc_zone_stmt_update_policy_nonlocal_failing(self):
        """ Clause zone; Statement update-policy-nonlocal; failing """
        test_string = [
            'local;',
            'global;',
        ]
        result = zone_stmt_update_policy_nonlocal.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_zone_stmt_use_id_pool_passing(self):
        """ Clause zone; Statement use-id-pool; passing """
        test_string = [
            'use-id-pool yes;',
        ]
        result = zone_stmt_use_id_pool.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            zone_stmt_use_id_pool,
            'use-id-pool no;',
            {'use_id_pool': 'no'}
        )

    def test_isc_zone_stmt_use_id_pool_failing(self):
        """ Clause zone; Statement use-id-pool; failing """
        test_string = [
            'use-id-pool "YYYY";',
        ]
        result = zone_stmt_use_id_pool.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_zone_statements_set_passing(self):
        """ Clause zone; Statement statements_set; passing """
        test_string = [
            'check-names fail;',
            'delegation-only yes;',
            'file "/var/lib/bind9/public/masters/db.example.org";',
            'in-view dmz_view;',
            'inline-signing no;',
            'ixfr-base custom_file_basename_goes_here;',
            'ixfr-from-differences yes;',
            'journal "/tmp/junk";',
            'masters dmz_masters port 7553 dscp 5 { yellow_masters key priv_dns_chan_key5; };',
            'pubkey 53 251 7 "asdfasddfasdfasdf";',
            'server-addresses { fb03::7 port 9553; 9.9.9.9; };',
            'server-names { "example.com"; };',
            'type forward;',
            'update-policy {deny rogue-master.example.com zonesub any;};',
            'update-policy {grant local-ddns zonesub any; };',
            'update-policy {grant hidden-master.ADMIN.EXAMPLE.COM ms-self EXAMPLE.COM A AAAA;};',
            'use-id-pool yes;',
        ]
        result = zone_statements_set.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_zone_statements_set_dict_passing(self):
        assertParserResultDictTrue(
            zone_statements_set,
            'check-names fail;',
            {'check_names': 'fail'}
        )

    def test_isc_zone_stmt_statements_set_failing(self):
        """ Clause zone; Statement statements_set; failing """
        test_string = [
            'statements_set "YYYY";',
        ]
        result = zone_statements_set.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


    def test_isc_zone_statements_series_passing(self):
        """ Clause zone; Statement zone_statements_series; passing """
        assertParserResultDictTrue(
            zone_statements_series,
            'check-names fail;'
            'delegation-only yes;'
            'file "/var/lib/bind9/public/masters/db.example.org";'
            'in-view dmz_view;'
            'inline-signing no;'
            'ixfr-base custom_file_basename_goes_here;'
            'ixfr-from-differences yes;'
            'journal "/tmp/x";'
            'masters dmz_masters port 7553 dscp 5 { yellow_masters key priv_dns_chan_key5; };'
            'pubkey 53 251 7 "asdfasddfasdfasdf";'
            'server-addresses { fb03::7 port 9553; 9.9.9.9; };'
            'server-names { "example.com"; };'
            'type forward;'
            'update-policy {grant hidden-master.ADMIN.EXAMPLE.COM ms-self EXAMPLE.COM A AAAA;};'
            'use-id-pool yes;'
        ,
            {'check_names': 'fail',
             'delegation-only': 'yes',
             'file': '"/var/lib/bind9/public/masters/db.example.org"',
             'in_view': 'dmz_view',
             'inline-signing': 'no',
             'ixfr_base': 'custom_file_basename_goes_here',
             'ixfr_from_differences': 'yes',
             'journal': '"/tmp/x"',
             'masters': [{'dscp_port': 5,
                          'ip_port': 7553,
                          'master_id': 'dmz_masters',
                          'master_list': [{'addr': 'yellow_masters',
                                           'key_id': 'priv_dns_chan_key5'}]}],
             'pubkey': {'algorithms': 7,
                        'flags': 53,
                        'key_secret': 'asdfasddfasdfasdf',
                        'protocol': 251},
             'server_addresses': [{'addr': 'fb03::7', 'ip_port': 9553},
                                  {'addr': '9.9.9.9'}],
             'server_names': ['example.com'],
             'type': 'forward',
             'update_policy': [{'impacting_realm': 'EXAMPLE.COM',
                                'permission': 'grant',
                                'policy': 'ms-self',
                                'requestor_domain': 'hidden-master.ADMIN.EXAMPLE.COM',
                                'rr_types': ['A', 'AAAA']}],
             'use_id_pool': 'yes'}
        )

    def test_isc_zone_stmt_statements_series_failing(self):
        """ Clause zone; Statement statements_series; failing """
        test_string = [
            'statements_series "YYYY";',
        ]
        result = zone_statements_series.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_zone_stmt_statements_github_issue1(self):
        """ Clause zone; Statement statements_series; failing """
        test_string = [
"""
type slave;
file "slaves/my.slave.internal.zone.db";
masters { 127.0.0.1; } ;
// put slave zones in the slaves/ directory so named can update them
""",
# masters { /* put master nameserver IPs here */ 127.0.0.1; } ;
        ]
        result = zone_statements_series.runTests(test_string,
                                                 failureTests=False)
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()
