#!/usr/bin/env python3
"""
File: test_options.py

Description:  Performs unit test on the isc_options.py source file.
"""

import unittest
from bind9_parser.isc_utils import unit_test_booleans, assertParserResultDict,\
    assertParserResultDictTrue, assertParserResultDictFalse, algorithm_name_list_series
from bind9_parser.isc_options import \
    options_stmt_acache_cleaning_interval,options_stmt_acache_enable,\
    options_stmt_answer_cookie, options_stmt_automatic_interface_scan,\
    options_stmt_avoid_v4_udp_ports,\
    options_stmt_avoid_v6_udp_ports, options_stmt_bindkeys_file,\
    options_stmt_blackhole, \
    options_stmt_coresize, options_stmt_datasize,\
    options_stmt_deallocate_on_exit, options_stmt_deny_answer_addresses,\
    options_stmt_deny_answer_aliases, options_stmt_directory,\
    options_stmt_disable_algorithms, options_multiple_stmt_disable_algorithms,\
    options_stmt_disable_ds_digests,\
    options_multiple_stmt_disable_ds_digests,\
    options_stmt_dnstap_identity, \
    options_stmt_dnstap_output,\
    options_stmt_dnstap_version,\
    options_stmt_dscp,\
    options_stmt_dump_file,\
    options_stmt_fake_iquery, options_stmt_flush_zones_on_shutdown,\
    options_stmt_has_old_clients,\
    options_stmt_hostname_statistics, options_stmt_hostname_statistics_max,\
    options_stmt_interface_interval, options_stmt_listen_on,\
    options_multiple_stmt_listen_on, \
    options_stmt_listen_on_v6, options_stmt_match_mapped_addresses,\
    options_stmt_max_rsa_exponent_size, options_stmt_memstatistics,\
    options_stmt_memstatistics_file, options_stmt_multiple_cnames,\
    options_stmt_named_xfer, options_stmt_pid_file,\
    options_stmt_port, options_stmt_prefetch,\
    options_stmt_querylog, options_stmt_random_device,\
    options_stmt_recursing_file, options_stmt_recursive_clients,\
    options_stmt_resolver_query_timeout, options_stmt_secroots_file,\
    options_stmt_serial_query_rate, options_stmt_server_id_name,\
    options_stmt_server_id, options_stmt_session_keyalg,\
    options_stmt_session_keyname, options_stmt_session_keyfile,\
    options_stmt_stacksize, options_stmt_statistics_file,\
    options_stmt_tcp_clients, options_stmt_tcp_listen_queue,\
    options_tkey_dhkey_tag, options_stmt_tkey_dhkey,\
    options_multiple_stmt_tkey_dhkey,\
    options_stmt_tkey_domain, options_stmt_tkey_gssapi_credential,\
    options_stmt_tkey_gssapi_keytab, options_stmt_transfers_in,\
    options_stmt_transfers_out, options_stmt_transfers_per_ns,\
    options_version_string, options_stmt_version,\
    options_statements_set, options_statements_series


class TestOptions(unittest.TestCase):
    """ Clause options """

    def test_isc_options_all_booleans(self):
        """ Clause options; all boolean statements; passing mode """
        test_syntax_boolean = [
            [ 'acache-enable', options_stmt_acache_enable, ],
            [ 'answer-cookie', options_stmt_answer_cookie, ],
            [ 'automatic-interface-scan', options_stmt_automatic_interface_scan, ],
            [ 'deallocate-on-exit', options_stmt_deallocate_on_exit, ],
            [ 'fake-iquery', options_stmt_fake_iquery, ],
            [ 'flush-zones-on-shutdown', options_stmt_flush_zones_on_shutdown, ],
            [ 'has-old-clients', options_stmt_has_old_clients, ],
            [ 'hostname-statistics', options_stmt_hostname_statistics, ],
            [ 'hostname-statistics-max', options_stmt_hostname_statistics_max, ],
            [ 'match-mapped-addresses', options_stmt_match_mapped_addresses, ],
            [ 'memstatistics', options_stmt_memstatistics, ],
            [ 'multiple-cnames', options_stmt_multiple_cnames, ],
            [ 'querylog', options_stmt_querylog, ],
        ]
        unit_test_booleans(self, test_syntax_boolean)

    def test_isc_options_stmt_acache_cleaning_interval_passing(self):
        """ Clause options; Statement acache-cleaning-interface; passing mode """
        assertParserResultDict(
            options_stmt_acache_cleaning_interval,
            'acache-cleaning-interval 15;',
            {'acache_cleaning_interval':  15}
            )
        assertParserResultDictTrue(options_stmt_acache_cleaning_interval,
                                   'acache-cleaning-interval 123;',
                                   {'acache_cleaning_interval': 123})

    def test_isc_options_stmt_avoid_v4_udp_ports_3port_passing(self):
        """ Clause options; Statement avoid-v4-udp-ports 3-port; passing mode """
        assertParserResultDict(
            options_stmt_avoid_v4_udp_ports,
            'avoid-v4-udp-ports { 15; 43; 50; };',
            {'avoid_v4_udp_ports': ['15', '43', '50']})

    def test_isc_options_stmt_avoid_v4_udp_ports_2port_passing(self):
        """ Clause options; Statement avoid-v4-udp-ports 2-port; passing mode """
        assertParserResultDictTrue(
            options_stmt_avoid_v4_udp_ports,
            'avoid-v4-udp-ports { 54; 123; };',
            {'avoid_v4_udp_ports': ['54', '123']}
            )

    def test_isc_options_stmt_avoid_v6_udp_ports_3port_passing(self):
        """ Clause options; Statement avoid-v6-udp-ports 3-port; passing mode """
        assertParserResultDict(
            options_stmt_avoid_v6_udp_ports,
            'avoid-v6-udp-ports { 15; 43; 50; };',
            {'avoid_v6_udp_ports': ['15', '43', '50']},
            True)

    def test_isc_options_stmt_avoid_v6_udp_ports_2port_passing(self):
        """ Clause options; Statement avoid-v6-udp-ports 2-port; passing mode """
        assertParserResultDictTrue(
            options_stmt_avoid_v6_udp_ports,
            'avoid-v6-udp-ports { 54; 123; };',
            {'avoid_v6_udp_ports': ['54', '123']})

    def test_isc_options_stmt_bindkeys_file(self):
        """ Clause options; Statement bindkeys-file; passing mode """
        assertParserResultDict(
            options_stmt_bindkeys_file,
            'bindkeys-file "/dev/null";',
            {'bindkeys_file': '/dev/null'},
            True)

    def test_isc_options_stmt_blackhole_passing(self):
        """ Clause options; Statement blackhole; passing mode """
        assertParserResultDictTrue(
            options_stmt_blackhole,
            'blackhole { 127.0.0.1; { localhost; localnets; }; !{ any; }; { none; }; };',
            {'blackhole': {'aml': [{'ip4_addr': '127.0.0.1'},
                                   {'aml': [{'keyword': 'localhost'},
                                            {'keyword': 'localnets'}]},
                                   {'aml': [{'keyword': 'any'}], 'not': '!'},
                                   {'aml': [{'keyword': 'none'}]}]}})
        assertParserResultDictTrue(options_stmt_blackhole,
                                   'blackhole { 127.0.0.1; };',
                                   {
                                       'blackhole': {
                                           'aml': [
                                               {'ip4_addr': '127.0.0.1'}
                                           ]
                                       }
                                   })

    def test_isc_options_stmt_coresize_passing(self):
        assertParserResultDictTrue(
            options_stmt_coresize,
            'coresize 256G;',
            {'coresize': [256, 'G']})

    def test_isc_options_stmt_datasize_passing(self):
        assertParserResultDictTrue(options_stmt_datasize,
                                   'datasize 256G;',
                                   {'datasize': [256, 'G']})

    def test_isc_options_stmt_deny_answer_addresses_passing(self):
        assertParserResultDictTrue(
            options_stmt_deny_answer_addresses,
            'deny-answer-addresses { 128.0.0.1; };',
            {
                'deny_answer_addresses': {
                    'aml': [
                        {'ip4_addr': '128.0.0.1'}
                    ]
                }})

    def test_isc_options_stmt_deny_answer_addresses2_passing(self):
        assertParserResultDictTrue(
            options_stmt_deny_answer_addresses,
            'deny-answer-addresses { 127.0.0.1/8; 192.168.0.0/16; 10.0.0.0/8; 172.16.0.0/12; }' +
            ' except-from { "example.test"; "home.arpa"; };',
            {'deny_answer_addresses': {'aml': [{'ip4_addr': '127.0.0.1',
                                                'prefix': '8'},
                                               {'ip4_addr': '192.168.0.0',
                                                'prefix': '16'},
                                               {'ip4_addr': '10.0.0.0',
                                                'prefix': '8'},
                                               {'ip4_addr': '172.16.0.0',
                                                'prefix': '12'}],
                                       'except_from': [{'fqdn': 'example.test'},
                                                       {'fqdn': 'home.arpa'}]}}
        )

    def test_isc_options_stmt_deny_answer_addresses3_passing(self):
        assertParserResultDictTrue(
            options_stmt_deny_answer_addresses,
            'deny-answer-addresses { any; };',
            {'deny_answer_addresses': {'aml': [{'keyword': 'any'}]}}
        )

    def test_isc_options_stmt_deny_answer_addresses4_passing(self):
        assertParserResultDictTrue(
            options_stmt_deny_answer_addresses,
            'deny-answer-addresses { 192.0.2.0/24; };',
            {'deny_answer_addresses': {'aml': [{'ip4_addr': '192.0.2.0',
                                                'prefix': '24'}]}}
        )

    def test_isc_options_stmt_deny_answer_addresses5_passing(self):
        assertParserResultDictTrue(
            options_stmt_deny_answer_addresses,
            'deny-answer-addresses { 192.0.2.0/24; } except-from { "example.test"; "test.example"; };',
            {'deny_answer_addresses': {'aml': [{'ip4_addr': '192.0.2.0',
                                                'prefix': '24'}],
                                       'except_from': [{'fqdn': 'example.test'},
                                                       {'fqdn': 'test.example'}]}}
        )

    # Reference: https://superuser.com/a/1332837/415567
    def test_isc_options_stmt_deny_answer_addresses6_passing(self):
        assertParserResultDictTrue(
            options_stmt_deny_answer_addresses,
            """
deny-answer-addresses {
    0.0.0.0; 
    10.0.0.0/8;
    172.16.0.0/12;
    192.168.0.0/16;
    169.254.0.0/16;
    ::/80;
    fe80::/10;
    64:ff9b::/96;
} except-from { "Your.Domain"; };""",
            {'deny_answer_addresses': {'aml': [{'ip4_addr': '0.0.0.0'},
                                               {'ip4_addr': '10.0.0.0',
                                                'prefix': '8'},
                                               {'ip4_addr': '172.16.0.0',
                                                'prefix': '12'},
                                               {'ip4_addr': '192.168.0.0',
                                                'prefix': '16'},
                                               {'ip4_addr': '169.254.0.0',
                                                'prefix': '16'},
                                               {'ip6_addr': '::',
                                                'prefix': '80'},
                                               {'ip6_addr': 'fe80::',
                                                'prefix': '10'},
                                               {'ip6_addr': '64:ff9b::',
                                                'prefix': '96'}],
                                       'except_from': [{'fqdn': 'Your.Domain'}]}}
        )

    def test_isc_options_stmt_deny_answer_aliases_passing(self):
        assertParserResultDictTrue(
            options_stmt_deny_answer_aliases,
            'deny-answer-aliases { "example.test"; };',
            {'deny_answer_aliases': {'name_list': ['example.test']}}
        )

    def test_isc_options_stmt_deny_answer_aliases_failing(self):
        assertParserResultDictFalse(
            options_stmt_deny_answer_aliases,
            # it is missing a semicolon between 'test.example' and 'home.arpa'
            'deny-answer-aliases { "test.example" "home.arpa."; } except-from { "172.in-addr.arpa."; };',
            {'deny_answer_aliases': {'except_from': [{'fqdn': '172.in-addr.arpa.'}],
                                     'name_list': ['test.example',
                                                   'home.arpa.']}}
        )

    def test_isc_options_stmt_directory_passing(self):
        assertParserResultDictTrue(options_stmt_directory,
                                   'directory "/etc/bind/";',
                                   {'directory': '/etc/bind/'})

        assertParserResultDictTrue(options_stmt_directory,
                                   'directory \'/etc/bind/\';',
                                   {'directory': '/etc/bind/'})

    def test_isc_options_stmt_disable_algorithms_passing(self):
        assertParserResultDictTrue(
            options_stmt_disable_algorithms,
            'disable-algorithms . { sha512; cbc32; };',
            {'disable_algorithms': [{'algorithm_name': ['sha512', 'cbc32'],
                                     'domain_name': '.'}]}
        )

    def test_isc_options_stmt_disable_algorithms_2_passing(self):
        assertParserResultDictTrue(
            options_stmt_disable_algorithms,
            'disable-algorithms "example.com." { sha512; };',
            {'disable_algorithms': [{'algorithm_name': ['sha512'],
                                     'domain_name': 'example.com.'}]}
        )

    def test_isc_options_stmt_disable_algorithms_3_passing(self):
        assertParserResultDictTrue(
            options_stmt_disable_algorithms,
            'disable-algorithms \'172.in-addr.arpa.\' { aes256; sha-1; rsa; };',
            {'disable_algorithms': [{'algorithm_name': ['aes256',
                                                        'sha-1',
                                                        'rsa'],
                                     'domain_name': '172.in-addr.arpa.'}]}
        )

    def test_isc_options_stmt_disable_algorithms_4_passing(self):
        assertParserResultDictTrue(
            options_multiple_stmt_disable_algorithms,
            'disable-algorithms example.com { sha512; cbc32; }; disable-algorithms yahoo.com { cbc128; };',
            {'disable_algorithms': [{'algorithm_name': ['sha512', 'cbc32'],
                                     'domain_name': 'example.com'},
                                    {'algorithm_name': ['cbc128'],
                                     'domain_name': 'yahoo.com'},
                                    [{'algorithm_name': ['sha512',
                                                         'cbc32'],
                                      'domain_name': 'example.com'},
                                     {'algorithm_name': ['cbc128'],
                                      'domain_name': 'yahoo.com'}]]}
        )

    def test_isc_options_stmt_part_disable_ds_digests_1_passing(self):
        assertParserResultDictTrue(
            options_stmt_disable_ds_digests,
            'disable-ds-digests example.com { hmac; cbc32; };',
            {'disable_ds_digests': [{'algorithm_name': ['hmac', 'cbc32'],
                                     'domain_name': 'example.com'}]}
            )

    def test_isc_options_stmt_part_disable_ds_digests_passing(self):
        assertParserResultDictTrue(
            options_multiple_stmt_disable_ds_digests,
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

    def test_isc_options_stmt_dnstap_identity(self):
        assertParserResultDictTrue(
            options_stmt_dnstap_identity,
            'dnstap-identity "example.com.";',
            {'dnstap_identity': 'example.com.'}
        )

    def test_isc_options_stmt_dnstap_output(self):
        assertParserResultDictTrue(
            options_stmt_dnstap_output,
            'dnstap-output file "dir/file" size 1G suffix timestamp versions 5;',
            {'quoted_path_name': 'dir/file', 'size': 1, 'versions': 5}
        )

    def test_isc_options_stmt_dnstap_version_file_passing(self):
        assertParserResultDictTrue(
            options_stmt_dnstap_version,
            'dnstap-version "dir/file";',
            {'dnstap-version': 'dir/file'}
        )

    def test_isc_options_stmt_dnstap_version_none_passing(self):
        assertParserResultDictTrue(
            options_stmt_dnstap_version,
            'dnstap-version none;',
            {'dnstap-version': 'none'}
        )

    def test_isc_options_stmt_dnstap_dscp_passing(self):
        assertParserResultDictTrue(
            options_stmt_dscp,
            'dscp 11;',
            {'dscp': '11'}
        )

    def test_isc_options_stmt_dump_file_passing(self):
        assertParserResultDictTrue(options_stmt_dump_file, 'dump-file "/tmp/crapola";', {'dump_file': '/tmp/crapola'})

    def test_isc_options_stmt_interface_interval_passing(self):
        assertParserResultDictTrue(options_stmt_interface_interval,
                                   'interface-interval 3600;',
                                   {'interface_interval': 3600})

    def test_isc_options_stmt_listen_on1_passing(self):
        assertParserResultDictTrue(
            options_stmt_listen_on,
            'listen-on port 553 { 127.0.0.1;};',
            {
                'listen_on': [
                    {
                        'aml': [
                            {'ip4_addr': '127.0.0.1'}
                        ],
                        'ip_port': '553'
                    },
                ]
            }
        )

    def test_isc_options_stmt_listen_on2_passing(self):
        assertParserResultDictTrue(
            options_multiple_stmt_listen_on,
            'listen-on port 553 { 127.0.0.1;}; listen-on port 1553 { 192.168.1.1; };',
            {'listen_on': [{'aml': [{'ip4_addr': '127.0.0.1'}],
                            'ip_port': '553'},
                           {'aml': [{'ip4_addr': '192.168.1.1'}],
                            'ip_port': '1553'}]}
        )

    def test_isc_options_stmt_listen_on3_passing(self):
        assertParserResultDictTrue(
            options_stmt_listen_on,
            'listen-on { ! 10.0.1.1; any;};',
            {'listen_on': [{'aml': [{'ip4_addr': '10.0.1.1', 'not': '!'},
                                    {'keyword': 'any'}]}]}
        )

    def test_isc_options_stmt_listen_on_v6_passing(self):
        assertParserResultDictTrue(
            options_stmt_listen_on_v6,
            'listen-on-v6 { 3231::1;};',
            {
                'listen_on_v6': [
                    {'aml': [
                        {'ip6_addr': '3231::1'}]}]}
        )

    def test_isc_options_stmt_mapped_addresses_passing(self):
        assertParserResultDictTrue(
            options_stmt_match_mapped_addresses,
            'match-mapped-addresses yes;',
            {'match_mapped_addresses': 'yes'})

    def test_isc_options_stmt_max_rsa_exponent_size_passing(self):
        assertParserResultDictTrue(
            options_stmt_max_rsa_exponent_size,
            'max-rsa-exponent-size 2048;',
            {'max_rsa_exponent_size': 2048})

    def test_isc_options_stmt_memstatistics_file_passing(self):
        assertParserResultDictTrue(
            options_stmt_memstatistics_file,
            'memstatistics-file "/tmp/junk-stat.dat";',
            {'memstatistics_file': '/tmp/junk-stat.dat'})

    def test_isc_options_stmt_pid_file_passing(self):
        assertParserResultDictTrue(
            options_stmt_pid_file,
            'pid-file "/tmp/junk-pid.dat";',
            {'pid_file_path_name': '/tmp/junk-pid.dat'})

    def test_isc_options_stmt_port_passing(self):
        assertParserResultDictTrue(
            options_stmt_port,
            'port 32111;',
            {'ip_port': '32111'})

    def test_isc_options_stmt_prefetch_passing(self):
        assertParserResultDictTrue(
            options_stmt_prefetch,
            'prefetch 55555 3600;',
            {'prefetch': {'expiry_ttl': 55555, 'threshold_ttl': 3600}})

    def test_isc_options_stmt_random_device_passing(self):
        assertParserResultDictTrue(
            options_stmt_random_device,
            'random-device "/dev/null";',
            {'random_device_path_name': '/dev/null'})

    def test_isc_options_stmt_recursing_file_passing(self):
        assertParserResultDictTrue(
            options_stmt_recursing_file,
            'recursing-file "/tmp/recursing-file.dat";',
            {'recursing_file_path_name': '/tmp/recursing-file.dat'})

    def test_isc_options_stmt_recursive_clients_passing(self):
        assertParserResultDictTrue(
            options_stmt_recursive_clients,
            'recursive-clients 100;',
            {'recursive_clients': 100})

    def test_isc_options_stmt_resolver_query_timeout_passing(self):
        assertParserResultDictTrue(
            options_stmt_resolver_query_timeout,
            'resolver-query-timeout 3608;',
            {'resolver_query_timeout': 3608})

    def test_isc_options_stmt_serial_query_rate_passing(self):
        assertParserResultDictTrue(
            options_stmt_serial_query_rate,
            'serial-query-rate 3608;',
            {'serial_query_rate': 3608})

    def test_isc_options_stmt_server_id_passing(self):
        assertParserResultDictTrue(
            options_stmt_server_id,
            'server-id "example.com";',
            {'server_id_name': 'example.com'})
        assertParserResultDictTrue(
            options_stmt_server_id,
            'server-id \'example.net\';',
            {'server_id_name': 'example.net'})
        assertParserResultDictTrue(
            options_stmt_server_id,
            "server-id 'example.pro.';",
            {'server_id_name': 'example.pro.'})  # ending period is allowed in FQDN here
        assertParserResultDictTrue(
            options_stmt_server_id,
            "server-id\texample.info;",
            {'server_id_name': 'example.info'})
        assertParserResultDictTrue(
            options_stmt_server_id,
            "\tserver-id\t \'example.biz\'\t;\t",
            {'server_id_name': 'example.biz'})

    def test_isc_options_stmt_stacksize_passing(self):
        assertParserResultDictTrue(
            options_stmt_stacksize,
            'stacksize 3608K;',
            {'stacksize': [3608, 'K']})

    def test_isc_options_stmt_statistics_file_passing(self):
        assertParserResultDictTrue(
            options_stmt_statistics_file,
            'statistics-file "/tmp/stat.dat";',
            {'statistics_file_path_name': '/tmp/stat.dat'})

    def test_isc_options_stmt_tcp_clients_passing(self):
        assertParserResultDictTrue(
            options_stmt_tcp_clients,
            'tcp-clients 3609;',
            {'tcp_clients': 3609})

    def test_isc_options_stmt_tcp_listen_queue_passing(self):
        assertParserResultDictTrue(
            options_stmt_tcp_listen_queue,
            'tcp-listen-queue 3623;',
            {'tcp_listen_queue': 3623})

    def test_isc_clause_options_tkkey_dhkey_passing(self):
        assertParserResultDictTrue(
            options_stmt_tkey_dhkey,
            'tkey-dhkey "www-site-1.example.com" 17;',
            {'tkey_dhkey': [{'host_name': 'www-site-1.example.com', 'key_tag': 17}]}
        )

    def test_isc_clause_options_tkey_dhkey_pasing(self):
        assertParserResultDictTrue(
            options_multiple_stmt_tkey_dhkey,
            'tkey-dhkey "www-site-1.example.com" 17; tkey-dhkey "www-site-2.example.com" 44317;',
            {'tkey_dhkey': [{'host_name': 'www-site-1.example.com',
                             'key_tag': 17},
                            {'host_name': 'www-site-2.example.com',
                             'key_tag': 44317}]}
        )

    def test_isc_clause_options_tkey_domain_passing(self):
        assertParserResultDictTrue(
            options_stmt_tkey_domain,
            'tkey-domain "example.com";',
            {'tkey_domain': 'example.com'}
            )

    def test_isc_clause_options_tkey_gssapi_credential_passing(self):
        assertParserResultDictTrue(
            options_stmt_tkey_gssapi_credential,
            'tkey-gssapi-credential "ADMIN@EXAMPLE.COM";',

            {'tkey_gssapi_credential': {'primary': 'ADMIN',
                                        'principal': 'ADMIN@EXAMPLE.COM',
                                        'realm': 'EXAMPLE.COM'}}
        )

    def test_isc_clause_options_transfers_in_passing(self):
        assertParserResultDictTrue(
            options_stmt_transfers_in,
            'transfers-in 3611;',
            {'transfers_in': 3611})

    def test_isc_clause_options_transfers_out_passing(self):
        assertParserResultDictTrue(
            options_stmt_transfers_out,
            'transfers-out 4773;',
            {'transfers_out': 4773})

    def test_isc_clause_options_transfer_per_ns_passing(self):
        assertParserResultDictTrue(
            options_stmt_transfers_per_ns,
            'transfers-per-ns 5935;',
            {'transfers_per_ns': 5935})

    def test_isc_clause_options_version_passing(self):
        # assertParserResultDictTrue(options_stmt_version, 'version 1.0.15;', {'version_string': '1.0.15'})
        assertParserResultDictTrue(options_stmt_version, 'version "1.0.15";', {'version_string': '1.0.15'})
        assertParserResultDictTrue(options_stmt_version, "version '1.0.15';", {'version_string': '1.0.15'})

        # Multiline test
        print("\nMulti-line tests:")

        assertParserResultDictFalse(options_stmt_version, "version = '1.0.15';", {})

    def test_isc_options_all_statement_set_passing(self):
        """ Clause options; Statement Set All; passing mode """
        test_data = [
            'version 5;',
        ]
        result = options_statements_set.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_options_all_statements_set_failing(self):
        """ Clause options; Statement Set All; failing mode """
        test_data = [
            'also-notify localhost;',
        ]
        result = options_statements_set.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_options_statments_set_passing(self):
        assertParserResultDictTrue(options_statements_set, 'version a;', {'version_string': 'a'})

    def test_isc_options_statements_series_passing(self):
        assertParserResultDictTrue(options_statements_series, 'version a; version b;', {'version_string': 'b'})

# options_all_statements_series

    def test_isc_options_all_statement_series_passing(self):
        """ Clause options; Statement Series All; passing mode """
        test_data = [
            'version 5; automatic-interface-scan yes;',
            'avoid-v4-udp-ports { 51; 49; 50; }; version 5; automatic-interface-scan yes;',
            ]
        result = options_statements_series.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_options_all_statements_series_failing(self):
        """ Clause options; Statement Series All; failing mode """
        test_data = [
            'also-notify localhost;',
        ]
        result = options_statements_series.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()
