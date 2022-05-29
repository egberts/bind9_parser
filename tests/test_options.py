#!/usr/bin/env python3
"""
File: test_options.py

Description:  Performs unit test on the isc_options.py source file.
"""

import unittest
from bind9_parser.isc_utils import unit_test_booleans, assert_parser_result_dict,\
    assert_parser_result_dict_true, assert_parser_result_dict_false
from bind9_parser.isc_options import \
    options_stmt_acache_cleaning_interval,options_stmt_acache_enable,\
    options_stmt_answer_cookie, options_stmt_automatic_interface_scan,\
    options_stmt_avoid_v4_udp_ports,\
    options_stmt_avoid_v6_udp_ports, options_stmt_bindkeys_file,\
    options_stmt_blackhole, \
    options_stmt_coresize, options_stmt_datasize,\
    options_stmt_deallocate_on_exit, options_stmt_deny_answer_addresses,\
    options_stmt_deny_answer_aliases, options_stmt_directory,\
    options_stmt_dnstap_identity, \
    options_stmt_dnstap_output,\
    options_stmt_dnstap_version,\
    options_stmt_dscp,\
    options_stmt_dump_file,\
    options_stmt_fake_iquery, options_stmt_flush_zones_on_shutdown,\
    options_stmt_geoip_directory,\
    options_stmt_has_old_clients, \
    options_stmt_http_listener_clients, \
    options_stmt_http_port,\
    options_stmt_http_streams_per_connection, \
    options_stmt_https_port,\
    options_stmt_hostname_statistics, options_stmt_hostname_statistics_max,\
    options_stmt_interface_interval, options_stmt_keep_response_order,\
    options_stmt_listen_on, options_multiple_stmt_listen_on, \
    options_stmt_listen_on_v6, options_stmt_match_mapped_addresses,\
    options_stmt_max_cache_ttl, options_stmt_max_clients_per_query,\
    options_stmt_max_rsa_exponent_size, options_stmt_memstatistics,\
    options_stmt_memstatistics_file, options_stmt_multiple_cnames,\
    options_stmt_named_xfer, options_stmt_nocookie_udp_size, options_stmt_pid_file,\
    options_stmt_port, options_stmt_prefetch,\
    options_stmt_querylog, options_stmt_random_device,\
    options_stmt_recursing_file, options_stmt_recursive_clients,\
    options_stmt_resolver_query_timeout, options_stmt_reuseport, options_stmt_secroots_file,\
    options_stmt_serial_query_rate, \
    options_stmt_server_id, options_stmt_session_keyalg,\
    options_stmt_session_keyname, options_stmt_session_keyfile,\
    options_stmt_stacksize, \
    options_stmt_statistics_file, \
    options_stmt_startup_notify_rate, \
    options_stmt_tcp_advertised_timeout, \
    options_stmt_tcp_idle_timeout, \
    options_stmt_tcp_initial_timeout, \
    options_stmt_tcp_keepalive_timeout, \
    options_stmt_tcp_receive_buffer, \
    options_stmt_tcp_send_buffer, \
    options_stmt_tkey_gssapi_credential, \
    options_stmt_tls_port, \
    options_stmt_transfer_message_size, \
    options_stmt_udp_receive_buffer, \
    options_stmt_udp_send_buffer, \
    options_stmt_use_v4_udp_ports, \
    options_stmt_use_v6_udp_ports, \
    options_stmt_statistics_file,\
    options_stmt_tcp_clients, options_stmt_tcp_listen_queue,\
    options_stmt_tkey_dhkey,\
    options_multiple_stmt_tkey_dhkey,\
    options_stmt_tkey_domain, \
    options_stmt_tkey_gssapi_keytab, options_stmt_transfers_in,\
    options_stmt_transfers_out, options_stmt_transfers_per_ns,\
    options_stmt_version,\
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
            [ 'reuseport', options_stmt_reuseport, ],
        ]
        unit_test_booleans(self, test_syntax_boolean)

    def test_isc_options_stmt_acache_cleaning_interval_passing(self):
        """ Clause options; Statement acache-cleaning-interface; passing mode """
        assert_parser_result_dict(
            options_stmt_acache_cleaning_interval,
            'acache-cleaning-interval 15;',
            {'acache_cleaning_interval':  15}
            )
        assert_parser_result_dict_true(options_stmt_acache_cleaning_interval,
                                   'acache-cleaning-interval 123;',
                                       {'acache_cleaning_interval': 123})

    def test_isc_options_stmt_avoid_v4_udp_ports_3port_passing(self):
        """ Clause options; Statement avoid-v4-udp-ports 3-port; passing mode """
        assert_parser_result_dict(
            options_stmt_avoid_v4_udp_ports,
            'avoid-v4-udp-ports { 15; 43; 50; };',
            {'avoid_v4_udp_ports': ['15', '43', '50']})

    def test_isc_options_stmt_avoid_v4_udp_ports_2port_passing(self):
        """ Clause options; Statement avoid-v4-udp-ports 2-port; passing mode """
        assert_parser_result_dict_true(
            options_stmt_avoid_v4_udp_ports,
            'avoid-v4-udp-ports { 54; 123; };',
            {'avoid_v4_udp_ports': ['54', '123']}
            )

    def test_isc_options_stmt_avoid_v6_udp_ports_3port_passing(self):
        """ Clause options; Statement avoid-v6-udp-ports 3-port; passing mode """
        assert_parser_result_dict(
            options_stmt_avoid_v6_udp_ports,
            'avoid-v6-udp-ports { 15; 43; 50; };',
            {'avoid_v6_udp_ports': ['15', '43', '50']},
            True)

    def test_isc_options_stmt_avoid_v6_udp_ports_2port_passing(self):
        """ Clause options; Statement avoid-v6-udp-ports 2-port; passing mode """
        assert_parser_result_dict_true(
            options_stmt_avoid_v6_udp_ports,
            'avoid-v6-udp-ports { 54; 123; };',
            {'avoid_v6_udp_ports': ['54', '123']})

    def test_isc_options_stmt_bindkeys_file(self):
        """ Clause options; Statement bindkeys-file; passing mode """
        assert_parser_result_dict(
            options_stmt_bindkeys_file,
            'bindkeys-file "/dev/null";',
            {'bindkeys_file': '/dev/null'},
            True)

    def test_isc_options_stmt_blackhole_passing(self):
        """ Clause options; Statement blackhole; passing mode """
        assert_parser_result_dict_true(
            options_stmt_blackhole,
            'blackhole { 127.0.0.1; { localhost; localnets; }; !{ any; }; { none; }; };',
            {'blackhole': {'aml': [{'ip4_addr': '127.0.0.1'},
                                   {'aml': [{'keyword': 'localhost'},
                                            {'keyword': 'localnets'}]},
                                   {'aml': [{'keyword': 'any'}], 'not': '!'},
                                   {'aml': [{'keyword': 'none'}]}]}})
        assert_parser_result_dict_true(options_stmt_blackhole,
                                   'blackhole { 127.0.0.1; };',
                                       {
                                       'blackhole': {
                                           'aml': [
                                               {'ip4_addr': '127.0.0.1'}
                                           ]
                                       }
                                   })

    def test_isc_options_stmt_coresize_passing(self):
        assert_parser_result_dict_true(
            options_stmt_coresize,
            'coresize 256G;',
            {'coresize': [256, 'G']})

    def test_isc_options_stmt_datasize_passing(self):
        assert_parser_result_dict_true(options_stmt_datasize,
                                   'datasize 256G;',
                                       {'datasize': [256, 'G']})

    def test_isc_options_stmt_deny_answer_addresses_passing(self):
        assert_parser_result_dict_true(
            options_stmt_deny_answer_addresses,
            'deny-answer-addresses { 128.0.0.1; };',
            {
                'deny_answer_addresses': {
                    'aml': [
                        {'ip4_addr': '128.0.0.1'}
                    ]
                }})

    def test_isc_options_stmt_deny_answer_addresses2_passing(self):
        assert_parser_result_dict_true(
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
        assert_parser_result_dict_true(
            options_stmt_deny_answer_addresses,
            'deny-answer-addresses { any; };',
            {'deny_answer_addresses': {'aml': [{'keyword': 'any'}]}}
        )

    def test_isc_options_stmt_deny_answer_addresses4_passing(self):
        assert_parser_result_dict_true(
            options_stmt_deny_answer_addresses,
            'deny-answer-addresses { 192.0.2.0/24; };',
            {'deny_answer_addresses': {'aml': [{'ip4_addr': '192.0.2.0',
                                                'prefix': '24'}]}}
        )

    def test_isc_options_stmt_deny_answer_addresses5_passing(self):
        assert_parser_result_dict_true(
            options_stmt_deny_answer_addresses,
            'deny-answer-addresses { 192.0.2.0/24; } except-from { "example.test"; "test.example"; };',
            {'deny_answer_addresses': {'aml': [{'ip4_addr': '192.0.2.0',
                                                'prefix': '24'}],
                                       'except_from': [{'fqdn': 'example.test'},
                                                       {'fqdn': 'test.example'}]}}
        )

    # Reference: https://superuser.com/a/1332837/415567
    def test_isc_options_stmt_deny_answer_addresses6_passing(self):
        assert_parser_result_dict_true(
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
        assert_parser_result_dict_true(
            options_stmt_deny_answer_aliases,
            'deny-answer-aliases { "example.test"; };',
            {'deny_answer_aliases': {'name_list': ['example.test']}}
        )

    def test_isc_options_stmt_deny_answer_aliases_failing(self):
        assert_parser_result_dict_false(
            options_stmt_deny_answer_aliases,
            # it is missing a semicolon between 'test.example' and 'home.arpa'
            'deny-answer-aliases { "test.example" "home.arpa."; } except-from { "172.in-addr.arpa."; };',
            {'deny_answer_aliases': {'except_from': [{'fqdn': '172.in-addr.arpa.'}],
                                     'name_list': ['test.example',
                                                   'home.arpa.']}}
        )

    def test_isc_options_stmt_directory_passing(self):
        assert_parser_result_dict_true(options_stmt_directory,
                                   'directory "/etc/bind/";',
                                       {'directory': '/etc/bind/'})

        assert_parser_result_dict_true(options_stmt_directory,
                                   'directory \'/etc/bind/\';',
                                       {'directory': '/etc/bind/'})

    def test_isc_options_stmt_dnstap_dscp_passing(self):
        assert_parser_result_dict_true(
            options_stmt_dscp,
            'dscp 11;',
            {'dscp': 11}
        )

    def test_isc_options_stmt_dnstap_identity(self):
        assert_parser_result_dict_true(
            options_stmt_dnstap_identity,
            'dnstap-identity "example.test.";',
            {'dnstap_identity': 'example.test.'}
        )

    def test_isc_options_stmt_dnstap_output(self):
        assert_parser_result_dict_true(
            options_stmt_dnstap_output,
            'dnstap-output file "dir/file" size 1G suffix timestamp versions 5;',
            {'dnstap-output': {'path': 'dir/file', 'size': 1, 'versions': 5}}
        )

    def test_isc_options_stmt_dnstap_version_file_passing(self):
        assert_parser_result_dict_true(
            options_stmt_dnstap_version,
            'dnstap-version "dir/file";',
            {'dnstap-version': 'dir/file'}
        )

    def test_isc_options_stmt_dnstap_version_none_passing(self):
        assert_parser_result_dict_true(
            options_stmt_dnstap_version,
            'dnstap-version none;',
            {'dnstap-version': 'none'}
        )

    def test_isc_options_stmt_dump_file_passing(self):
        assert_parser_result_dict_true(options_stmt_dump_file, 'dump-file "/tmp/crapola";', {'dump_file': '/tmp/crapola'})

    def test_isc_options_stmt_geoip_directory(self):
        """ Clause options; Statement geoip-directory; passing mode """
        assert_parser_result_dict(
            options_stmt_geoip_directory,
            'geoip-directory "/dev/null";',
            {'geoip_directory': '/dev/null'},
            True)

    def test_isc_options_stmt_geoip_ut_directory(self):
        """ Clause options; Statement geoip-directory unittest; passing mode """
        test_data = [
            'geoip-directory none;',
            'geoip-directory "dir/file";',
            'geoip-directory "/dir/file with spaces";',
        ]
        result = options_stmt_geoip_directory.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_options_stmt_http_listener_clients(self):
        """ Clause options; Statement http-listener-clients passing mode """
        assert_parser_result_dict(
            options_stmt_http_listener_clients,
            'http-listener-clients 5;',
            {'http_listener_clients': 5},
            True)

    def test_isc_options_stmt_http_listener_clients_ut(self):
        """ Clause options; Statement http-listener-clients unittest; passing mode """
        test_data = [
            'http-listener-clients 5;',
            'http-listener-clients 0;',
            'http-listener-clients 10000;',
        ]
        result = options_stmt_http_listener_clients.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_options_stmt_http_port(self):
        """ Clause options; Statement http-port passing mode """
        assert_parser_result_dict(
            options_stmt_http_port,
            'http-port 5;',
            {'http_port': 5},
            True)

    def test_isc_options_stmt_http_streams_per_connection(self):
        """ Clause options; Statement http-port passing mode """
        assert_parser_result_dict(
            options_stmt_http_streams_per_connection,
            'http-streams-per-connection 5;',
            {'http_streams_per_connection': 5},
            True)

    def test_isc_options_stmt_https_port(self):
        """ Clause options; Statement https-port passing mode """
        assert_parser_result_dict(
            options_stmt_https_port,
            'https-port 5;',
            {'https_port': 5},
            True)

    def test_isc_options_stmt_interface_interval_passing(self):
        assert_parser_result_dict_true(options_stmt_interface_interval,
                                   'interface-interval 3600;',
                                       {'interface_interval': 3600})

    def test_isc_options_stmt_keep_response_order_passing(self):
        """ Clause options; Statement 'keep-response-order'; passing mode """
        assert_parser_result_dict_true(
            options_stmt_keep_response_order,
            'keep-response-order { 127.0.0.1; { localhost; localnets; }; !{ any; }; { none; }; };',
            {'keep-response-order': {'aml': [{'ip4_addr': '127.0.0.1'},
                                             {'aml': [{'keyword': 'localhost'},
                                                      {'keyword': 'localnets'}]},
                                             {'aml': [{'keyword': 'any'}],
                                              'not': '!'},
                                             {'aml': [{'keyword': 'none'}]}]}}
        )

    def test_isc_options_stmt_keep_response_order_2_passing(self):
        """ Clause options; Statement 'keep-response-order'; passing mode """
        assert_parser_result_dict_true(
            options_stmt_keep_response_order,
            'keep-response-order { ! 127.0.0.1; };',
            {'keep-response-order': {'aml': [{'ip4_addr': '127.0.0.1',
                                              'not': '!'}]}}
        )

    def test_isc_options_stmt_listen_on_ut_passing(self):
        test_data = [
            'listen-on port 553 { 127.0.0.1; };',
            'listen-on port 553 tls TLS_STRING { 127.0.0.1; };',
            'listen-on port 553 http HTTP_STRING { 127.0.0.1; };',
            'listen-on port 553 dscp 5 http HTTP_STRING { 127.0.0.1; };',
            'listen-on port 553 tls TLS_STRING http HTTP_STRING { 127.0.0.1; };',
            'listen-on port 553 dscp 6 tls TLS_STRING http HTTP_STRING { 127.0.0.1; };',
            'listen-on port 553 dscp 4 { 127.0.0.1; };',
        ]
        result = options_stmt_listen_on.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_options_stmt_listen_on1_passing(self):
        assert_parser_result_dict_true(
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
        assert_parser_result_dict_true(
            options_multiple_stmt_listen_on,
            'listen-on port 553 { 127.0.0.1;}; listen-on port 1553 { 192.168.1.1; };',
            {'listen_on': [{'aml': [{'ip4_addr': '127.0.0.1'}],
                            'ip_port': '553'},
                           {'aml': [{'ip4_addr': '192.168.1.1'}],
                            'ip_port': '1553'}]}
        )

    def test_isc_options_stmt_listen_on3_passing(self):
        assert_parser_result_dict_true(
            options_stmt_listen_on,
            'listen-on { ! 10.0.1.1; any;};',
            {'listen_on': [{'aml': [{'ip4_addr': '10.0.1.1', 'not': '!'},
                                    {'keyword': 'any'}]}]}
        )

    def test_isc_options_stmt_listen_on_v6_passing(self):
        assert_parser_result_dict_true(
            options_stmt_listen_on_v6,
            'listen-on-v6 { 3231::1;};',
            {
                'listen_on_v6': [
                    {'aml': [
                        {'ip6_addr': '3231::1'}]}]}
        )

    def test_isc_options_stmt_mapped_addresses_passing(self):
        assert_parser_result_dict_true(
            options_stmt_match_mapped_addresses,
            'match-mapped-addresses yes;',
            {'match_mapped_addresses': 'yes'})

    def test_isc_options_stmt_max_cache_ttl_passing(self):
        assert_parser_result_dict_true(
            options_stmt_max_cache_ttl,
            'max-cache-ttl 1W1D7H;',
            {'max_cache_ttl': '1W1D7H'}
            )

    def test_isc_options_stmt_max_clients_per_query_passing(self):
        assert_parser_result_dict_true(
            options_stmt_max_clients_per_query,
            'max-clients-per-query 300;',
            {'max_clients_per_query': 300}
            )

    def test_isc_options_stmt_max_rsa_exponent_size_passing(self):
        assert_parser_result_dict_true(
            options_stmt_max_rsa_exponent_size,
            'max-rsa-exponent-size 2048;',
            {'max_rsa_exponent_size': 2048})

    def test_isc_options_stmt_memstatistics_file_passing(self):
        assert_parser_result_dict_true(
            options_stmt_memstatistics_file,
            'memstatistics-file "/tmp/junk-stat.dat";',
            {'memstatistics_file': '/tmp/junk-stat.dat'})

    def test_isc_options_stmt_named_xfer_passing(self):
        assert_parser_result_dict_true(options_stmt_named_xfer,
                                   'named-xfer "/etc/bind/";',
                                       {'named_xfer': '/etc/bind/'})

        assert_parser_result_dict_true(options_stmt_named_xfer,
                                   'named-xfer \'/etc/bind/\';',
                                       {'named_xfer': '/etc/bind/'})

    def test_isc_options_stmt_nocookie_udp_size_passing(self):
        assert_parser_result_dict_true(
            options_stmt_nocookie_udp_size,
            'nocookie-udp-size 2048;',
            {'nocookie_udp_size': 2048})

    def test_isc_options_stmt_pid_file_passing(self):
        assert_parser_result_dict_true(
            options_stmt_pid_file,
            'pid-file "/tmp/junk-pid.dat";',
            {'pid_file': '/tmp/junk-pid.dat'}
        )

    def test_isc_options_stmt_port_passing(self):
        assert_parser_result_dict_true(
            options_stmt_port,
            'port 32111;',
            {'ip_port': '32111'})

    def test_isc_options_stmt_prefetch_passing(self):
        assert_parser_result_dict_true(
            options_stmt_prefetch,
            'prefetch 55555 3600;',
            {'prefetch': {'expiry_ttl': 55555, 'threshold_ttl': 3600}})

    def test_isc_options_stmt_random_device_passing(self):
        assert_parser_result_dict_true(
            options_stmt_random_device,
            'random-device "/dev/null";',
            {'random_device': '/dev/null'}
        )

    def test_isc_options_stmt_recursing_file_passing(self):
        assert_parser_result_dict_true(
            options_stmt_recursing_file,
            'recursing-file "/tmp/recursing-file.dat";',
            {'recursing_file': '/tmp/recursing-file.dat'})

    def test_isc_options_stmt_recursive_clients_passing(self):
        assert_parser_result_dict_true(
            options_stmt_recursive_clients,
            'recursive-clients 100;',
            {'recursive_clients': 100})

    def test_isc_options_stmt_resolver_query_timeout_passing(self):
        assert_parser_result_dict_true(
            options_stmt_resolver_query_timeout,
            'resolver-query-timeout 3608;',
            {'resolver_query_timeout': 3608})

    def test_isc_options_stmt_reuseport_passing(self):
        assert_parser_result_dict_true(
            options_stmt_reuseport,
            'reuseport yes;',
            {'reuseport': 'yes'})

    def test_isc_options_stmt_secroots_file_passing(self):
        assert_parser_result_dict_true(
            options_stmt_secroots_file,
            'secroots-file "/etc/bind/";',
            {'secroots_file': '/etc/bind/'})

    def test_isc_options_stmt_serial_query_rate_passing(self):
        assert_parser_result_dict_true(
            options_stmt_serial_query_rate,
            'serial-query-rate 3608;',
            {'serial_query_rate': 3608})

    def test_isc_options_stmt_server_id_passing(self):
        assert_parser_result_dict_true(
            options_stmt_server_id,
            'server-id "example.test";',
            {'server_id_name': 'example.test'})
        assert_parser_result_dict_true(
            options_stmt_server_id,
            'server-id \'example.net\';',
            {'server_id_name': 'example.net'})
        assert_parser_result_dict_true(
            options_stmt_server_id,
            "server-id 'example.pro.';",
            {'server_id_name': 'example.pro.'})  # ending period is allowed in FQDN here
        assert_parser_result_dict_true(
            options_stmt_server_id,
            "server-id\texample.info;",
            {'server_id_name': 'example.info'})
        assert_parser_result_dict_true(
            options_stmt_server_id,
            "\tserver-id\t \'example.biz\'\t;\t",
            {'server_id_name': 'example.biz'})

    def test_isc_options_stmt_session_keyalg_ut_passing(self):
        test_data = [
            'session-keyalg HMAC-MD5;',
            'session-keyalg hmac-sha1;',
            'session-keyalg hmac-sha224;',
            'session-keyalg hmac-sha256;',  # default
            'session-keyalg HmAc-ShA384;',
            'session-keyalg hmac-sha512;',
        ]
        result = options_stmt_session_keyalg.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_options_stmt_session_keyalg_passing(self):
        assert_parser_result_dict_true(
            options_stmt_session_keyalg,
            'session-keyalg hmac-sha512;',
            {'session_keyalg': 'hmac-sha512'})

    def test_isc_options_stmt_session_keyname_passing(self):
        assert_parser_result_dict_true(
            options_stmt_session_keyname,
            'session-keyname local-ddns;',  # default
            {'session_keyname': 'local-ddns'})

    def test_isc_options_stmt_session_keyfile_passing(self):
        assert_parser_result_dict_true(
            options_stmt_session_keyfile,
            'session-keyfile "dir/file";',  # default
            {'session_keyfile': 'dir/file'})

    def test_isc_options_stmt_stacksize_passing(self):
        assert_parser_result_dict_true(
            options_stmt_stacksize,
            'stacksize 3608K;',
            {'stacksize': [3608, 'K']})

    # options_stmt_startup_notify_rate, \
    def test_isc_options_stmt_startup_notify_rate_passing(self):
        assert_parser_result_dict_true(
            options_stmt_startup_notify_rate,
            'startup-notify-rate 20;',  # default
            {'startup_notify_rate': 20}
        )

    def test_isc_options_stmt_statistics_file_passing(self):
        assert_parser_result_dict_true(
            options_stmt_statistics_file,
            'statistics-file "/tmp/stat.dat";',
            {'statistics_file': '/tmp/stat.dat'})

    # options_stmt_tcp_advertised_timeout
    def test_isc_options_stmt_tcp_advertised_timeout_passing(self):
        assert_parser_result_dict_true(
            options_stmt_tcp_advertised_timeout,
            'tcp-advertised-timeout 300;',  # default
            {'tcp_advertised_timeout': 300}
        )

    def test_isc_options_stmt_tcp_clients_passing(self):
        assert_parser_result_dict_true(
            options_stmt_tcp_clients,
            'tcp-clients 3609;',
            {'tcp_clients': 3609})

    # options_stmt_tcp_idle_timeout
    def test_isc_options_stmt_tcp_idle_timeout_passing(self):
        assert_parser_result_dict_true(
            options_stmt_tcp_idle_timeout,
            'tcp-idle-timeout 300;',  # default
            {'tcp_idle_timeout': 300}
        )

    # options_stmt_tcp_initial_timeout
    def test_isc_options_stmt_tcp_initial_timeout_passing(self):
        assert_parser_result_dict_true(
            options_stmt_tcp_initial_timeout,
            'tcp-initial-timeout 300;',  # default
            {'tcp_initial_timeout': 300}
        )

    def test_isc_options_stmt_tcp_listen_queue_passing(self):
        assert_parser_result_dict_true(
            options_stmt_tcp_listen_queue,
            'tcp-listen-queue 3623;',
            {'tcp_listen_queue': 3623})

    # options_stmt_tcp_keepalive_timeout
    def test_isc_options_stmt_tcp_keepalive_timeout_passing(self):
        assert_parser_result_dict_true(
            options_stmt_tcp_keepalive_timeout,
            'tcp-keepalive-timeout 300;',  # default
            {'tcp_keepalive_timeout': 300}
        )

    # options_stmt_tcp_receive_buffer
    def test_isc_options_stmt_tcp_receive_buffer_passing(self):
        assert_parser_result_dict_true(
            options_stmt_tcp_receive_buffer,
            'tcp-receive-buffer 300;',  # default
            {'tcp_receive_buffer': 300}
        )

    # options_stmt_tcp_send_buffer
    def test_isc_options_stmt_tcp_send_buffer_passing(self):
        assert_parser_result_dict_true(
            options_stmt_tcp_send_buffer,
            'tcp-send-buffer 300;',  # default
            {'tcp_send_buffer': 300}
        )

    def test_isc_options_tkey_dhkey_passing(self):
        assert_parser_result_dict_true(
            options_stmt_tkey_dhkey,
            'tkey-dhkey "www-site-1.example.test" 17;',
            {'tkey_dhkey': [{'host_name': 'www-site-1.example.test', 'key_tag': 17}]}
        )

    def test_isc_options_tkey_dhkey_2_passing(self):
        assert_parser_result_dict_true(
            options_multiple_stmt_tkey_dhkey,
            'tkey-dhkey "www-site-1.example.test" 17; tkey-dhkey "www-site-2.example.test" 44317;',
            {'tkey_dhkey': [{'host_name': 'www-site-1.example.test',
                             'key_tag': 17},
                            {'host_name': 'www-site-2.example.test',
                             'key_tag': 44317}]}
        )

    def test_isc_options_tkey_domain_passing(self):
        assert_parser_result_dict_true(
            options_stmt_tkey_domain,
            'tkey-domain "example.test";',
            {'tkey_domain': 'example.test'}
        )

    def test_isc_options_tkey_gsspai_keytab_passing(self):
        assert_parser_result_dict_true(
            options_stmt_tkey_gssapi_keytab,
            'tkey-gssapi-keytab "dir/file";',
            {'tkey_gssapi_keytab': 'dir/file'}
        )

    # options_stmt_tkey_gssapi_credential
    def test_isc_options_stmt_tkey_gssapi_credential_ut_passing(self):
        test_data = [
            'tkey-gssapi-credential "changepw/kdc1.example.test@EXAMPLE.TEST";',
            'tkey-gssapi-credential "clntconfig/admin@EXAMPLE.TEST";',
            'tkey-gssapi-credential "ftp/boston.example.test@EXAMPLE.TEST";',
            'tkey-gssapi-credential "host/boston.example.test@EXAMPLE.TEST";',
            'tkey-gssapi-credential "K/M@EXAMPLE.TEST";',
            'tkey-gssapi-credential "kadmin/history@EXAMPLE.TEST";',
            'tkey-gssapi-credential "kadmin/kdc1.example.test@EXAMPLE.TEST";',
            'tkey-gssapi-credential "kadmin/kdc1.example.test@EXAMPLE.TEST";',
            'tkey-gssapi-credential "krbtgt/EXAMPLE.TEST@EXAMPLE.TEST";',
            'tkey-gssapi-credential "krbtgt/EAST.EXAMPLE.TEST@WEST.EXAMPLE.TEST";',
            'tkey-gssapi-credential "nfs/boston.example.test@EXAMPLE.TEST";',
            'tkey-gssapi-credential "root/boston.example.test@EXAMPLE.TEST";',
            'tkey-gssapi-credential "OPERATOR/ns8.example.test@TEST.EXAMPLE";',
            'tkey-gssapi-credential "ADMIN/ns9.example.test@TEST.EXAMPLE";',
            'tkey-gssapi-credential "DNS/ns10.example.test@EXAMPLE.TEST";',
        ]
        result = options_stmt_tkey_gssapi_credential.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    # options_stmt_tkey_gssapi_credential
    def test_isc_options_tkey_gssapi_credential_passing(self):
        assert_parser_result_dict_true(
            options_stmt_tkey_gssapi_credential,
            'tkey-gssapi-credential "DNS/ns10.example.test@EXAMPLE.TEST";',
            {'tkey_gssapi_credential': {'instance': 'ns10.example.test',
                                        'primary': 'DNS',
                                        'principal': 'DNS/ns10.example.test@EXAMPLE.TEST',
                                        'realm': 'EXAMPLE.TEST'}}
        )

    def test_isc_options_tkey_gssapi_credential_2_passing(self):
        assert_parser_result_dict_true(
            options_stmt_tkey_gssapi_credential,
            'tkey-gssapi-credential "ADMIN/master.example.test@EXAMPLE.TEST";',
            {'tkey_gssapi_credential': {'instance': 'master.example.test',
                                        'primary': 'ADMIN',
                                        'principal': 'ADMIN/master.example.test@EXAMPLE.TEST',
                                        'realm': 'EXAMPLE.TEST'}}
        )

    # options_stmt_tkey_gssapi_credential
    def test_isc_options_stmt_tkey_gssapi_credential_ut_failing(self):
        test_data = [
            'tkey-gssapi-credential "ABC/admin@master.example.test@EXAMPLE.TEST;',  # two '@'s
            'tkey-gssapi-credential "krb5_credential@example.test";',
            'tkey-gssapi-credential "krb5_credential/example.test";',
        ]
        result = options_stmt_tkey_gssapi_credential.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    # options_stmt_tls_port
    def test_isc_options_stmt_tls_port_passing(self):
        assert_parser_result_dict_true(
            options_stmt_tls_port,
            'tls-port 853;',  # default
            {'tls_port': 853}
        )

    def test_isc_options_transfers_in_passing(self):
        assert_parser_result_dict_true(
            options_stmt_transfers_in,
            'transfers-in 3611;',
            {'transfers_in': 3611})

    # options_stmt_transfer_message_size
    def test_isc_options_stmt_transfer_message_size_passing(self):
        assert_parser_result_dict_true(
            options_stmt_transfer_message_size,
            'transfer-message-size 20480;',  # default
            {'transfer_message_size': 20480}
        )

    def test_isc_options_transfers_out_passing(self):
        assert_parser_result_dict_true(
            options_stmt_transfers_out,
            'transfers-out 4773;',
            {'transfers_out': 4773})

    def test_isc_options_transfer_per_ns_passing(self):
        assert_parser_result_dict_true(
            options_stmt_transfers_per_ns,
            'transfers-per-ns 5935;',
            {'transfers_per_ns': 5935})

    # options_stmt_udp_receive_buffer
    def test_isc_options_stmt_udp_receive_buffer_passing(self):
        assert_parser_result_dict_true(
            options_stmt_udp_receive_buffer,
            'udp-receive-buffer 300;',  # default
            {'udp_receive_buffer': 300}
        )

    # options_stmt_udp_send_buffer
    def test_isc_options_stmt_udp_send_buffer_passing(self):
        assert_parser_result_dict_true(
            options_stmt_udp_send_buffer,
            'udp-send-buffer 300;',  # default
            {'udp_send_buffer': 300}
        )

    # options_stmt_use_v4_udp_ports
    def test_isc_options_stmt_use_v4_udp_ports_passing(self):
        test_data = [
            'use-v4-udp-ports { range 443 1023; };',
            'use-v4-udp-ports { range 1024 45535; };',
        ]
        result = options_stmt_use_v4_udp_ports.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            options_stmt_use_v4_udp_ports,
            'use-v4-udp-ports { range 1024 45535; };',
            {'use_v4_udp_ports': {'port_end': 45535, 'port_start': 1024}}
        )

    # options_stmt_use_v6_udp_ports
    def test_isc_options_stmt_use_v6_udp_ports_passing(self):
        test_data = [
            'use-v6-udp-ports { range 443 1023; };',
            'use-v6-udp-ports { range 1024 45535; };',
        ]
        result = options_stmt_use_v6_udp_ports.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            options_stmt_use_v6_udp_ports,
            'use-v6-udp-ports { range 1024 45535; };',
            {'use_v6_udp_ports': {'port_end': 45535, 'port_start': 1024}}
        )

    def test_isc_options_version_passing(self):
        # assertParserResultDictTrue(options_stmt_version, 'version 1.0.15;', {'version_string': '1.0.15'})
        assert_parser_result_dict_true(options_stmt_version, 'version "1.0.15";', {'version_string': '1.0.15'})
        assert_parser_result_dict_true(options_stmt_version, "version '1.0.15';", {'version_string': '1.0.15'})

        # Multiline test
        print("\nMulti-line tests:")

        assert_parser_result_dict_false(options_stmt_version, "version = '1.0.15';", {})

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
        assert_parser_result_dict_true(options_statements_set, 'version a;', {'version_string': 'a'})

    def test_isc_options_statements_series_passing(self):
        assert_parser_result_dict_true(options_statements_series, 'version a; version b;', {'version_string': 'b'})

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
