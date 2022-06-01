#!/usr/bin/env python3
"""
File: test_clauses.py

Description:  Performs unit test on the isc_clauses.py source file.
"""

import unittest
from bind9_parser.isc_utils import assert_parser_result_dict_true, assert_parser_result_dict_false
from bind9_parser.isc_clauses import \
    optional_clause_stmt_set,\
    optional_clause_stmt_series,\
    mandatory_clause_stmt_set,\
    clause_statements
#   TODO add v9.15.0 new clause_stmt_catalog_zones


class TestClauseALL(unittest.TestCase):
    """ Clause, All """

    def test_isc_clause_clause_stmt_optional_set_passing1(self):
        """ Clause, All; Statements group; optional clause 1; passing """
        test_data = [
            'acl MY_BASTION_HOSTS { 4.4.4.4; 3.3.3.3; 2.2.2.2; 1.1.1.1; };',
        ]
        result = optional_clause_stmt_set.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_clause_clause_stmt_optional_set_dict_passing1(self):
        """ Clause, All; Statements group; optional clause dict 1; passing """
        test_string = 'acl MY_BASTION_HOSTS { 4.4.4.4; 3.3.3.3; 2.2.2.2; 1.1.1.1; };'
        assert_parser_result_dict_true(
            optional_clause_stmt_set,
            test_string,
            {'acl': [{'acl_name': 'MY_BASTION_HOSTS',
                      'aml_series': [{'aml': [{'ip4_addr': '4.4.4.4'},
                                              {'ip4_addr': '3.3.3.3'},
                                              {'ip4_addr': '2.2.2.2'},
                                              {'ip4_addr': '1.1.1.1'}]}]}]}
        )

    def test_isc_clause_clause_stmt_optional_set_passing(self):
        """ Clause, All; Statements group; passing """
        test_string = 'acl MY_BASTION_HOSTS { 4.4.4.4; 3.3.3.3; 2.2.2.2; 1.1.1.1; };'
        expected_result = {
            'acl': [{'acl_name': 'MY_BASTION_HOSTS',
                     'aml_series': [{'aml': [
                         {'ip4_addr': '4.4.4.4'},
                         {'ip4_addr': '3.3.3.3'},
                         {'ip4_addr': '2.2.2.2'},
                         {'ip4_addr': '1.1.1.1'}]}]}]}
        assert_parser_result_dict_true(optional_clause_stmt_set, test_string, expected_result)

    def test_isc_clause_stmt_multiplezone_passing(self):
        """ Clause, All; Zone Statements group; passing """
        test_string = """
    zone "." {
      type hint;
      file "root.servers";
    };
    zone "example.com" in{
      type master;
      file "master/master.example.com";
      allow-transfer {192.168.23.1;192.168.23.2;};
    };
    zone "localhost" in{
      type master;
      file "master.localhost";
      allow-update{none;};
    };
    zone "0.0.127.in-addr.arpa" in{
      type master;
      file "localhost.rev";
      allow-update{none;};
    };
    zone "0.168.192.IN-ADDR.ARPA" in{
      type master;
      file "192.168.0.rev";
    };"""
        assert_parser_result_dict_true(
            optional_clause_stmt_series,
            test_string,
            {'zones': [{'file': 'root.servers',
                        'type': 'hint',
                        'zone_name': '.'},
                       {'allow_transfer': {'aml': [{'ip4_addr': '192.168.23.1'},
                                                   {'ip4_addr': '192.168.23.2'}]},
                        'class': 'in',
                        'file': 'master/master.example.com',
                        'type': 'master',
                        'zone_name': 'example.com'},
                       {'allow_update': {'aml': [{'keyword': 'none'}]},
                        'class': 'in',
                        'file': 'master.localhost',
                        'type': 'master',
                        'zone_name': 'localhost'},
                       {'allow_update': {'aml': [{'keyword': 'none'}]},
                        'class': 'in',
                        'file': 'localhost.rev',
                        'type': 'master',
                        'zone_name': '0.0.127.in-addr.arpa'},
                       {'class': 'in',
                        'file': '192.168.0.rev',
                        'type': 'master',
                        'zone_name': '0.168.192.IN-ADDR.ARPA'}]}
        )

    def test_isc_clause_optional_clause_stmt_series_passing(self):
        """ Clause, All; All Statements group; passing """
        assert_parser_result_dict_true(
            optional_clause_stmt_series, """
    acl MY_BASTION_HOSTS { 4.4.4.4; 3.3.3.3; 2.2.2.2; 1.1.1.1; };
    controls { inet 128.0.0.9 port 8006 allow { 128.0.0.10; 128.0.0.11;} read-only yes; };
    dlz your_IBM_2 { database "RSDMS"; search no; };
    dyndb "example-ldap" "/usr/lib64/bind/ldap.so" { 
        uri "ldap://ldap.example.com"; 
        base "cn=dns, dc=example,dc=com"; 
        auth_method "none"; };
    key dyndns { algorithm hmac-sha512; secret ABCDEFG; };
    logging { channel salesfolks { file "/tmp/sales.log" size 5M; severity info; print-time no;};
              channel accounting { file "/tmp/acct.log" size 30M; severity info; print-time no; };
              channel badguys { file "/tmp/alert" size 255G; severity debug 77; print-time yes;}; };
    managed-keys { www1.www.example.com initial-key 1 1 1 "ASBASDASD"; };
    masters bastion_host_group { bastion_hosts22; hidden_bastion; };
    zone red { file "/var/lib/bind9/public/masters/db.example.com"; };
    server 3.4.5.6 { bogus yes; edns no; edns-udp-size 102; edns-version 2;
                     keys my_key_name_to_private_dns; max-udp-size 32768; notify-source *; notify-source-v6 *;
                     padding 53; provide-ixfr yes; query-source *; query-source address *; query-source-v6 *;
                     request-expire yes; request-ixfr yes; request-nsid yes; send-cookie yes; tcp-keepalive yes;
                     tcp-only yes; transfer-format one-answer; transfer-source *; transfer-source-v6 *; transfers 36; };
    trusted-keys { abc 1 1 1 "ASBASDASD";};
    zone green { file "/var/lib/bind9/public/masters/db.green.com"; };
    masters dmz_masters port 7553 dscp 5 { 10.0.0.1 key priv_dns_chan_key5; };""",
            {'acl': [{'acl_name': 'MY_BASTION_HOSTS',
                      'aml_series': [{'aml': [{'ip4_addr': '4.4.4.4'},
                                              {'ip4_addr': '3.3.3.3'},
                                              {'ip4_addr': '2.2.2.2'},
                                              {'ip4_addr': '1.1.1.1'}]}]}],
             'controls': [{'inet': {'allow': {'aml': [{'ip4_addr': '128.0.0.10'},
                                                      {'ip4_addr': '128.0.0.11'}]},
                                    'control_server_addr': '128.0.0.9',
                                    'ip_port_w': '8006',
                                    'read-only': 'yes'}}],
             'dlz': [{'db_args': 'RSDMS',
                      'dlz_name': 'your_IBM_2',
                      'search': 'no'}],
             'dyndb': [{'db_name': '"example-ldap"',
                        'driver_parameters': 'uri '
                                             '"ldap://ldap.example.com"; \n'
                                             '        base "cn=dns, '
                                             'dc=example,dc=com"; \n'
                                             '        auth_method '
                                             '"none"; ',
                        'module_filename': '/usr/lib64/bind/ldap.so'}],
             'key': [{'algorithm': 'hmac-sha512',
                      'key_id': 'dyndns',
                      'secret': 'ABCDEFG'}],
             'logging': {'channels': [{'channel_name': 'salesfolks',
                                       'path_name': '/tmp/sales.log',
                                       'print_time': 'no',
                                       'severity': ['info'],
                                       'size_spec': [5, 'M']},
                                      {'channel_name': 'accounting',
                                       'path_name': '/tmp/acct.log',
                                       'print_time': 'no',
                                       'severity': ['info'],
                                       'size_spec': [30, 'M']},
                                      {'channel_name': 'badguys',
                                       'path_name': '/tmp/alert',
                                       'print_time': 'yes',
                                       'severity': {'debug': {'debug_level': 77}},
                                       'size_spec': [255, 'G']}]},
             'managed_keys': [{'algorithm_id': 1,
                               'flags': 1,
                               'key_secret': '"ASBASDASD"',
                               'protocol_id': 1,
                               'rr_domain': 'www1.www.example.com'}],
             'primaries': [{'dscp_port': 5,
                            'ip_port': '7553',
                            'primary_id': 'dmz_masters',
                            'primary_list': [{'ip4_addr': '10.0.0.1',
                                              'key_id': 'priv_dns_chan_key5'}]}],
             'server': [{'configs': {'bogus': 'yes',
                                     'edns': 'no',
                                     'edns_udp_size': 102,
                                     'edns_version': 2,
                                     'keys': 'my_key_name_to_private_dns',
                                     'max_udp_size': 32768,
                                     'notify_source': {'ip4_addr': '*'},
                                     'notify_source_v6': {'ip6_addr_w': '*'},
                                     'padding': 53,
                                     'provide_ixfr': 'yes',
                                     'query_source': {'ip4_addr_w': '*'},
                                     'query_source_v6': {'ip6_addr_w': '*'},
                                     'request_expire': 'yes',
                                     'request_ixfr': 'yes',
                                     'request_nsid': 'yes',
                                     'send_cookie': 'yes',
                                     'tcp_keepalive': 'yes',
                                     'tcp_only': 'yes',
                                     'transfer_format': 'one-answer',
                                     'transfer_source': {'ip4_addr_w': '*'},
                                     'transfer_source_v6': {'ip6_addr': '*'},
                                     'transfers': 36},
                         'ip_addr': '3.4.5.6'}],
             'trusted_keys': [{'algorithm_id': '1',
                               'domain': 'abc',
                               'key_id': '1',
                               'protocol_type': '1',
                               'pubkey_base64': 'ASBASDASD'}],
             'zones': [{'file': '/var/lib/bind9/public/masters/db.example.com',
                        'zone_name': 'red'},
                       {'file': '/var/lib/bind9/public/masters/db.green.com',
                        'zone_name': 'green'}]}
            )

    def test_isc_clause_mandatory_clause_passing(self):
        """ Clause, All; All Statements group; passing """
        assert_parser_result_dict_true(
            mandatory_clause_stmt_set, """
    options {
        allow-new-zones yes;
        allow-notify { 127.0.0.1; };
        allow-query { any; };
        allow-query-cache { none; };
        allow-query-cache-on { 127.0.0.1; };
        allow-query-on { 127.0.0.1; };
        allow-recursion { 127.0.0.1; };
        allow-recursion-on { 127.0.0.1; };
        allow-transfer port 855 { 127.0.0.1; };
        allow-update { 127.0.0.1; };
        allow-update-forwarding { 127.0.0.1; };
        also-notify port 856 { 127.0.0.1 key ABC_KEY tls SSLv3; };
        alt-transfer-source * port *;
        alt-transfer-source * port * dscp 1;
        alt-transfer-source-v6 * port * dscp 2;
        answer-cookie no;
        attach-cache ABC_CACHE;
        auth-nxdomain no;
        auto-dnssec off;
        automatic-interface-scan no;
        avoid-v4-udp-ports { 1; 2; 3; };
        avoid-v6-udp-ports { 4; 5; 6; };
        bindkeys-file "dir/file";
        blackhole { 127.0.0.1; };
        check-dup-records ignore;
        check-dup-records warn;
        check-integrity no;
        check-mx fail;
        check-mx-cname ignore;
        check-names primary ignore;
        check-sibling fail;
        check-spf warn;
        check-srv-cname fail;
        check-wildcard no;
        clients-per-query 10;
        cookie-algorithm aes;
        cookie-secret "cookie_secret";
        coresize default;
        datasize 1G;
        deny-answer-addresses { 127.0.0.1; } except-from { "172.in-addr.arpa."; };
        deny-answer-aliases { "example.test"; "test.example"; } except-from { "172.in-addr.arpa."; };
        dialup notify-passive;
        directory "dir/file";
        disable-algorithms "aaaaaaaaaaaaaaaaa" { AES512; SHA512; };
        disable-ds-digests "." { RSASHA512; };
        disable-empty-zone "127.in-addr.arpa";
        dns64 64:ff9b::/96 { 
            break-dnssec yes;
            recursive-only no;
            clients { 127.0.0.1; };
            exclude { 127.0.0.1; };
            mapped   { 127.0.0.1; };
            };

        dns64-contact dns64.contact.string.content;
        dns64-server dns64.server.string.content;
        dnskey-sig-validity 3;
        dnsrps-enable no;
        dnskey-sig-validity 3;
        dnsrps-enable no;
        dnssec-accept-expired no;
        dnssec-dnskey-kskonly no;
        dnssec-loadkeys-interval 1;
        dnssec-must-be-secure "home.arpa." yes;
        dnssec-must-be-secure "example.test." yes;
        dnssec-policy my_policy;
        dnssec-secure-to-insecure no;
        dnssec-update-mode no-resign;
        dnssec-validation auto;
        dnstap { all; response; }; 
        dnstap-identity none;
        dnstap-output file "dir/file" size unlimited versions 5 suffix timestamp;
        dnstap-version none;
        dscp 14;
        dump-file "dir/file";
        edns-udp-size 512;
        empty-contact "empty-contact-string-content";
        empty-server "empty-server-string-content";
        empty-zones-enable no;
        fetch-quota-params 5 1.0 1.0 1.0;
        fetches-per-server 5 drop;
        fetches-per-zone 4 drop;
        files unlimited;
        flush-zones-on-shutdown no;
        forward only;
        forwarders port 753 { 127.0.0.1; };
        geoip-directory none;
        heartbeat-interval 60;
        hostname none;
        http-listener-clients 5;
        http-port 80;
        http-streams-per-connection 5;
        https-port 443;
        interface-interval 60;
        ipv4only-contact "ipv4only-contact-string-content";
        ipv4only-enable no;
        ipv4only-server "ipv4only-contact-string-content";
        ixfr-from-differences primary;
        keep-response-order { 127.0.0.1; };
        key-directory "dir/file";
        lame-ttl 60;
        listen-on port 53 tls TLS_NAME http HTTP_NAME { 127.0.0.1; };
        listen-on-v6 port 53 tls TLS_NAME http HTTP_NAME { ::1; };
        lmdb-mapsize 1M;
        lock-file "dir/file";
        managed-keys-directory "dir/file";
        masterfile-format text;
        masterfile-style relative;
        match-mapped-addresses no;
        max-cache-size unlimited;
        max-cache-ttl 1H;
        max-clients-per-query 60;
        max-ixfr-ratio unlimited;
        max-journal-size 11M;
        max-ncache-ttl 1H;
        max-records 5;
        max-recursion-depth 3;
        max-recursion-queries 4;
        max-refresh-time 60;
        max-retry-time 60;
        max-rsa-exponent-size 512;
        max-stale-ttl 16;
        max-transfer-idle-in 5;
        max-transfer-idle-out 5;
        max-transfer-time-in 5;
        max-transfer-time-out 5;
        max-udp-size 5;
        max-zone-ttl unlimited;
        memstatistics no;
        memstatistics-file "dir/file";
        message-compression no;
        min-cache-ttl 1D;
        min-ncache-ttl 2d;
        min-refresh-time 1W;
        min-retry-time 1;
        minimal-any no;
        minimal-responses no-auth-recursive;
        multi-master no;
        new-zones-directory "dir/file";
        no-case-compress { example.test; };
        nocookie-udp-size 512;
        notify primary-only;
        notify-delay 60;
        notify-rate 60;
        notify-source * port * dscp 4;
        notify-source-v6 * port * dscp 5;
        notify-to-soa no;
        nsec3-test-zone no;
        nta-lifetime 60m;
        nta-recheck 24h;
        nxdomain-redirect redirect.example.test.;
        parental-source 127.0.0.1 port 12388;
        parental-source-v6 ffe2::1 port 12389;
        pid-file none;
        port 53;
        preferred-glue AAAA;
        prefetch 30 60;
        provide-ixfr no;
        qname-minimization relaxed;
        query-source address 127.0.0.1;
        query-source-v6 address fec2::1;
        querylog no;
        random-device none;
        rate-limit { all-per-second 60; };
        recursing-file "dir/file";
        recursion no;
        recursive-clients 60;
        request-expire no;
        request-ixfr no;
        request-nsid no;
        require-server-cookie no;
        reserved-sockets 30;
        resolver-nonbackoff-tries 25;
        resolver-query-timeout 24;
        resolver-retry-interval 23;
        response-padding { 127.0.0.1; } block-size 512;
        response-policy { 
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
                 nsip-enable yes nsdname-enable yes dnsrps-enable yes ;
        reuseport no;
        root-delegation-only exclude { name1; name2; name3; };
        root-key-sentinel no;
        rrset-order { name "fixed.example" order fixed;
            name "random.example" order random;
            name "cyclic.example" order cyclic;
            name "none.example" order none;
            type NS order random;
            order cyclic; };
        secroots-file "dir/file";
        send-cookie no;
        serial-query-rate 5;
        serial-update-method unixtime;
        server-id hostname;
        servfail-ttl 1;
        session-keyalg hmac-md5;
        session-keyfile "dir/file";
        session-keyname "session_keyname";
        sig-signing-nodes 5;
        sig-signing-signatures 5;
        sig-signing-type 6;
        sig-validity-interval 5;
        sortlist { 
            { localhost; 
                { localnets; 192.168.1.0/24; 
                    { 192.168.2.0/24; 192.168.3.0/24; }; }; }; 
            { 192.168.1.0/24; { 192.168.1.0/24; { 192.168.2.0/24; 192.168.3.0/24; }; }; }; };
        stacksize default;
        stale-answer-client-timeout disabled;
        stale-answer-enable no;
        stale-answer-ttl 60;
        stale-cache-enable no;
        stale-refresh-time 8;
        startup-notify-rate 5;
        statistics-file "dir/file";
        suppress-initial-notify no;
        synth-from-dnssec no;
        tcp-advertised-timeout 60;
        tcp-clients 60;
        tcp-idle-timeout 60;
        tcp-initial-timeout 60;
        tcp-keepalive-timeout 60;
        tcp-listen-queue 60;
        tcp-receive-buffer 60;
        tcp-send-buffer 60;
        tkey-dhkey "dhkey_string_content" 60;
        tkey-domain "172.in-addr.arpa.";
        tkey-gssapi-credential "kadmin/kdc1.example.test@EXAMPLE.TEST";
        tkey-gssapi-keytab "directory/file";
        tls-port 60;
        transfer-format many-answers;
        transfer-message-size 60;
        transfer-source 127.0.0.1 port 60 dscp 12;
        transfer-source-v6 ffec::1 port 60 dscp 11;
        transfers-in 60;
        transfers-out 60;
        transfers-per-ns 60;
        trust-anchor-telemetry no;
        try-tcp-refresh no;
        udp-receive-buffer 60;
        udp-send-buffer 60;
        update-check-ksk no;
        use-alt-transfer-source no;
        use-v4-udp-ports { range 1 1024; };
        use-v6-udp-ports { range 1025 44315; };
        v6-bias 60;
        validate-except { "168.192.in-addr.arpa."; };
        version "funky dns server, uh?";
        zero-no-soa-ttl no;
        zero-no-soa-ttl-cache no;
        zone-statistics terse;
    };""",
            {'options': [{'allow-recursion': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'allow-recursion-on': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'allow_new_zones': 'yes',
                          'allow_notify': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'allow_query': {'aml': [{'keyword': 'any'}]},
                          'allow_query_cache': {'aml': [{'keyword': 'none'}]},
                          'allow_query_cache_on': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'allow_query_on': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'allow_transfer': {'aml': [{'ip4_addr': '127.0.0.1'}],
                                             'ip_port': '855'},
                          'allow_update': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'allow_update_forwarding': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'also-notify': {'port': '856',
                                          'remote': [{'ip_addr': '127.0.0.1',
                                                      'key_id': 'ABC_KEY',
                                                      'tls_algorithm_name': 'SSLv3'}]},
                          'alt_transfer_source': {'dscp_port': 1,
                                                  'ip_port_w': '*'},
                          'alt_transfer_source_v6': {'dscp_port': 2,
                                                     'ip_port_w': '*'},
                          'answer-cookie': 'no',
                          'attach_cache': 'ABC_CACHE',
                          'auth_nxdomain': 'no',
                          'auto_dnssec': 'off',
                          'automatic_interface_scan': 'no',
                          'avoid_v4_udp_ports': ['1', '2', '3'],
                          'avoid_v6_udp_ports': ['4', '5', '6'],
                          'bindkeys_file': 'dir/file',
                          'blackhole': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'check_dup_records': 'warn',
                          'check_integrity': 'no',
                          'check_mx': 'fail',
                          'check_mx_cname': 'ignore',
                          'check_names': [{'result_status': 'ignore',
                                           'zone_type': 'primary'}],
                          'check_sibling': 'fail',
                          'check_spf': 'warn',
                          'check_srv_cname': 'fail',
                          'check_wildcard': 'no',
                          'clients_per_query': 10,
                          'cookie_algorithm': 'aes',
                          'cookie_secret': '"cookie_secret"',
                          'coresize': ['default'],
                          'datasize': [1, 'G'],
                          'deny_answer_addresses': {'aml': [{'ip4_addr': '127.0.0.1'}],
                                                    'except_from': [{'fqdn': '172.in-addr.arpa.'}]},
                          'deny_answer_aliases': {'except_from': [{'fqdn': '172.in-addr.arpa.'}],
                                                  'name_list': ['example.test',
                                                                'test.example']},
                          'dialup': 'notify-passive',
                          'directory': 'dir/file',
                          'disable_algorithms': {'algorithms': ['AES512',
                                                                'SHA512'],
                                                 'domain_name': 'aaaaaaaaaaaaaaaaa'},
                          'disable_ds_digests': [{'algorithm_name': ['RSASHA512'],
                                                  'domain_name': '.'}],
                          'disable_empty_zone': [{'zone_name': '127.in-addr.arpa'}],
                          'dns64': [{'aml': [{'ip4_addr': '127.0.0.1'}],
                                     'break_dnssec': 'yes',
                                     'clients': [{'ip4_addr': '127.0.0.1'}],
                                     'exclude': [{'ip4_addr': '127.0.0.1'}],
                                     'mapped': [{'ip4_addr': '127.0.0.1'}],
                                     'netprefix': {'ip6_addr': '64:ff9b::',
                                                   'prefix': '96'},
                                     'recursive_only': 'no'}],
                          'dns64_contact': {'soa_rname': 'dns64.contact.string.content'},
                          'dns64_server': {'soa_rname': 'dns64.server.string.content'},
                          'dnskey_sig_validity': 3,
                          'dnsrps_enable': 'no',
                          'dnssec_accept_expired': 'no',
                          'dnssec_dnskey_kskonly': 'no',
                          'dnssec_loadkeys_interval': 1,
                          'dnssec_must_be_secure': [{'dnssec_secured': 'yes',
                                                     'fqdn': '"home.arpa."'},
                                                    {'dnssec_secured': 'yes',
                                                     'fqdn': '"example.test."'}],
                          'dnssec_policy': 'my_policy',
                          'dnssec_secure_to_insecure': 'no',
                          'dnssec_update_mode': 'no-resign',
                          'dnssec_validation': 'auto',
                          'dnstap': ['all', 'response'],
                          'dnstap-output': {'path': 'dir/file',
                                            'size': 'unlimited',
                                            'versions': 5},
                          'dnstap-version': 'none',
                          'dscp': 14,
                          'dump_file': 'dir/file',
                          'edns_udp_size': 512,
                          'empty_contact': {'soa_contact_name': 'empty-contact-string-content'},
                          'empty_server': {'soa_contact_name': 'empty-server-string-content'},
                          'empty_zones_enable': 'no',
                          'fetch_quota_params': {'high_threshold': 1.0,
                                                 'low_threshold': 1.0,
                                                 'moving_average_discount_rate': 1.0,
                                                 'moving_avg_recalculate_interval': 5},
                          'fetches_per_server': {'action': 'drop',
                                                 'fetches': 5},
                          'fetches_per_zone': {'action': 'drop',
                                               'fetches': 4},
                          'files': {'files_count': 'unlimited'},
                          'flush_zones_on_shutdown': 'no',
                          'forward': 'only',
                          'forwarders': {'forwarder': [{'ip_addr': '127.0.0.1'}],
                                         'ip_port': '753'},
                          'heartbeat_interval': 60,
                          'hostname': {'none': 'none'},
                          'http_listener_clients': 5,
                          'http_port': 80,
                          'http_streams_per_connection': 5,
                          'https_port': 443,
                          'interface_interval': 60,
                          'ip_port': '53',
                          'ipv4only_contact': {'soa_rname': 'ipv4only-contact-string-content'},
                          'ipv4only_enable': 'no',
                          'ipv4only_server': {'soa_rname': 'ipv4only-contact-string-content'},
                          'ixfr_from_differences': 'primary',
                          'keep-response-order': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'key_directory': 'dir/file',
                          'lame_ttl': 60,
                          'listen_on': [{'aml': [{'ip4_addr': '127.0.0.1'}],
                                         'http_port': 'HTTP_NAME',
                                         'ip_port': '53',
                                         'tls_port': 'TLS_NAME'}],
                          'listen_on_v6': [{'aml': [{'ip6_addr': '::1'}],
                                            'http_port': 'HTTP_NAME',
                                            'ip_port': '53',
                                            'tls_port': 'TLS_NAME'}],
                          'lmdb_mapsize': {'amount': 1, 'unit': 'M'},
                          'lock_file': 'dir/file',
                          'managed_keys_directory': 'dir/file',
                          'masterfile_format': 'text',
                          'masterfile_style': 'relative',
                          'match_mapped_addresses': 'no',
                          'max-ixfr-ratio': 'unlimited',
                          'max-zone-ttl': 'unlimited',
                          'max_cache_size': ['unlimited'],
                          'max_cache_ttl': '1H',
                          'max_clients_per_query': 60,
                          'max_journal_size': [11, 'M'],
                          'max_ncache_ttl': '1H',
                          'max_records': 5,
                          'max_recursion_depth': 3,
                          'max_recursion_queries': 4,
                          'max_refresh_time': 60,
                          'max_retry_time': 60,
                          'max_rsa_exponent_size': 512,
                          'max_stale_ttl': '16',
                          'max_transfer_idle_in': 5,
                          'max_transfer_idle_out': 5,
                          'max_transfer_time_in': 5,
                          'max_transfer_time_out': 5,
                          'max_udp_size': 5,
                          'memstatistics': 'no',
                          'memstatistics_file': 'dir/file',
                          'message_compression': 'no',
                          'min_cache_ttl': '1D',
                          'min_ncache_ttl': '2d',
                          'min_refresh_time': '1W',
                          'min_retry_time': 1,
                          'minimal_any': 'no',
                          'multi_master': 'no',
                          'new_zones_directory': 'dir/file',
                          'no_case_compress': [{'acl_name': 'example.test'}],
                          'nocookie_udp_size': 512,
                          'notify': 'primary-only',
                          'notify_delay': 60,
                          'notify_rate': 60,
                          'notify_source': {'dscp_port': 4,
                                            'ip4_addr-w': '*',
                                            'ip4_port_w': '*'},
                          'notify_source_v6': {'dscp_port': 5,
                                               'ip6_addr': '*',
                                               'ip_port_w': '*'},
                          'notify_to_soa': 'no',
                          'nsec3_test_zone': 'no',
                          'nta_lifetime': '60m',
                          'nta_recheck': '24h',
                          'nxdomain_redirect': 'redirect.example.test.',
                          'parental_source': {'ip4_addr_w': '127.0.0.1',
                                              'ip_port_w': '12388'},
                          'parental_source_v6': {'ip6_addr_w': 'ffe2::1',
                                                 'ip_port_w': '12389'},
                          'preferred_glue': 'AAAA',
                          'prefetch': {'expiry_ttl': 30,
                                       'threshold_ttl': 60},
                          'provide_ixfr': 'no',
                          'qname_minimization': 'relaxed',
                          'query_source': {'ip4_addr': '127.0.0.1'},
                          'query_source_v6': {'ip6_addr': 'fec2::1'},
                          'querylog_boolean': 'no',
                          'rate_limit': [{'all_per_second': 60}],
                          'recursing_file': 'dir/file',
                          'recursion': 'no',
                          'recursive_clients': 60,
                          'request_expire': 'no',
                          'request_ixfr': 'no',
                          'request_nsid': 'no',
                          'require_server_cookie': 'no',
                          'reserved_sockets': 30,
                          'resolver_nonbackoff_tries': 25,
                          'resolver_query_timeout': 24,
                          'resolver_retry_interval': 23,
                          'response-padding': {'aml': [{'ip4_addr': '127.0.0.1'}],
                                               'fqdn': 512},
                          'response_policy': {'add_soa': 'no',
                                              'break_dnssec': 'no',
                                              'dnsrps_enable': 'yes',
                                              'max_policy_ttl': '30S',
                                              'min_ns_dots': 2,
                                              'min_update_interval': '4w',
                                              'nsdname_enable': 'yes',
                                              'nsdname_wait_recurse': 'yes',
                                              'nsip_enable': 'yes',
                                              'nsip_wait_recurse': 'yes',
                                              'qname_wait_recurse': 'yes',
                                              'recursive_only': 'yes',
                                              'zone': [{'add_soa': 'no',
                                                        'log': 'no',
                                                        'max_policy_ttl': '4Y',
                                                        'min_update_interval': '30S',
                                                        'nsdname_enable': 'no',
                                                        'nsip_enable': 'no',
                                                        'policy': ['no-op'],
                                                        'recursive_only': 'no',
                                                        'zone_name': '172.in-addr.arpa.'},
                                                       {'add_soa': 'yes',
                                                        'log': 'yes',
                                                        'max_policy_ttl': '3Y',
                                                        'min_update_interval': '20S',
                                                        'nsdname_enable': 'yes',
                                                        'nsip_enable': 'yes',
                                                        'policy': [[]],
                                                        'recursive_only': 'yes',
                                                        'zone_name': '168.192.in-addr.arpa.'},
                                                       {'add_soa': 'no',
                                                        'log': 'yes',
                                                        'max_policy_ttl': '4Y',
                                                        'min_update_interval': '30S',
                                                        'nsdname_enable': 'no',
                                                        'nsip_enable': 'yes',
                                                        'policy': ['no-op'],
                                                        'recursive_only': 'yes',
                                                        'zone_name': 'example.test.'},
                                                       {'add_soa': 'yes',
                                                        'log': 'yes',
                                                        'max_policy_ttl': '4Y',
                                                        'min_update_interval': '30S',
                                                        'nsdname_enable': 'no',
                                                        'nsip_enable': 'yes',
                                                        'policy': ['no-op'],
                                                        'recursive_only': 'yes',
                                                        'zone_name': 'example2.test.'},
                                                       {'add_soa': 'no',
                                                        'log': 'yes',
                                                        'max_policy_ttl': '4Y',
                                                        'min_update_interval': '30S',
                                                        'nsdname_enable': 'no',
                                                        'nsip_enable': 'yes',
                                                        'policy': ['no-op'],
                                                        'recursive_only': 'yes',
                                                        'zone_name': '172.in-addr.arpa.'}]},
                          'reuseport': 'no',
                          'root_delegation_only': {'domains': ['name1',
                                                               'name2',
                                                               'name3']},
                          'root_key_sentinel': 'no',
                          'rrset_order': [{'name': 'fixed.example',
                                           'order': 'fixed'},
                                          {'name': 'random.example',
                                           'order': 'random'},
                                          {'name': 'cyclic.example',
                                           'order': 'cyclic'},
                                          {'name': 'none.example',
                                           'order': 'none'},
                                          {'order': 'random',
                                           'type': 'NS'},
                                          {'order': 'cyclic'}],
                          'secroots_file': 'dir/file',
                          'send_cookie': 'no',
                          'serial_query_rate': 5,
                          'serial_update_method': 'unixtime',
                          'server_id_name': 'hostname',
                          'servfail_ttl': 1,
                          'session_keyalg': 'hmac-md5',
                          'session_keyfile': 'dir/file',
                          'session_keyname': '"session_keyname"',
                          'sig_signing_nodes': 5,
                          'sig_signing_signatures': 5,
                          'sig_signing_type': 6,
                          'sig_validity_interval': 5,
                          'sortlist': {'aml': [{'aml': [{'keyword': 'localhost'},
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
                                                                           'prefix': '24'}]}]}]}]},
                          'stacksize': ['default'],
                          'stale_answer_client_timeout': 'disabled',
                          'stale_answer_enable': 'no',
                          'stale_answer_ttl': 60,
                          'stale_cache_enable': 'no',
                          'stale_refresh_time': 8,
                          'startup_notify_rate': 5,
                          'statistics_file': 'dir/file',
                          'suppress_initial_notify': 'no',
                          'synth_from_dnssec': 'no',
                          'tcp_advertised_timeout': 60,
                          'tcp_clients': 60,
                          'tcp_idle_timeout': 60,
                          'tcp_initial_timeout': 60,
                          'tcp_keepalive_timeout': 60,
                          'tcp_listen_queue': 60,
                          'tcp_receive_buffer': 60,
                          'tcp_send_buffer': 60,
                          'tkey_dhkey': [{'host_name': 'dhkey_string_content',
                                          'key_tag': 60}],
                          'tkey_domain': '172.in-addr.arpa.',
                          'tkey_gssapi_credential': {'instance': 'kdc1.example.test',
                                                     'primary': 'kadmin',
                                                     'principal': 'kadmin/kdc1.example.test@EXAMPLE.TEST',
                                                     'realm': 'EXAMPLE.TEST'},
                          'tkey_gssapi_keytab': 'directory/file',
                          'tls_port': 60,
                          'transfer_format': 'many-answers',
                          'transfer_message_size': 60,
                          'transfer_source': {'dscp_port': 12,
                                              'ip4_addr': '127.0.0.1',
                                              'ip_port_w': '60'},
                          'transfer_source_v6': {'dscp_port': 11,
                                                 'ip6_addr': 'ffec::1',
                                                 'ip_port_w': '60'},
                          'transfers_in': 60,
                          'transfers_out': 60,
                          'transfers_per_ns': 60,
                          'trust_anchor_telemetry': 'no',
                          'try_tcp_refresh': 'no',
                          'udp_receive_buffer': 60,
                          'udp_send_buffer': 60,
                          'update_check_ksk': 'no',
                          'use_alt_transfer_source': 'no',
                          'use_v4_udp_ports': [{'port_end': 1024,
                                                'port_start': 1}],
                          'use_v6_udp_ports': [{'port_end': 44315,
                                                'port_start': 1025}],
                          'v6_bias': 60,
                          'validate_except': ['168.192.in-addr.arpa.'],
                          'version_string': 'funky dns server, uh?',
                          'zero_no_soa_ttl': 'no',
                          'zero_no_soa_ttl_cache': 'no',
                          'zone_statistics': 'terse'}]}

        )

    def test_isc_clause_all_passing(self):
        """ Clause, All; All clauses; passing """
        assert_parser_result_dict_true(
            clause_statements, """
options {
    allow-new-zones yes;
    allow-notify { 127.0.0.1; };
    allow-query { any; };
    allow-query-cache { none; };
    allow-query-cache-on { 127.0.0.1; };
    allow-query-on { 127.0.0.1; };
    allow-recursion { 127.0.0.1; };
    allow-recursion-on { 127.0.0.1; };
    allow-transfer port 855 { 127.0.0.1; };
    allow-update { 127.0.0.1; };
    allow-update-forwarding { 127.0.0.1; };
    also-notify port 856 { 127.0.0.1 key ABC_KEY tls SSLv3; };
    alt-transfer-source * port *;
    alt-transfer-source * port * dscp 1;
    alt-transfer-source-v6 * port * dscp 2;
    answer-cookie no;
    attach-cache ABC_CACHE;
    auth-nxdomain no;
    auto-dnssec off;
    automatic-interface-scan no;
    avoid-v4-udp-ports { 1; 2; 3; };
    avoid-v6-udp-ports { 4; 5; 6; };
    bindkeys-file "dir/file";
    blackhole { 127.0.0.1; };
    check-dup-records ignore;
    check-dup-records warn;
    check-integrity no;
    check-mx fail;
    check-mx-cname ignore;
    check-names primary ignore;
    check-sibling fail;
    check-spf warn;
    check-srv-cname fail;
    check-wildcard no;
    clients-per-query 10;
    cookie-algorithm aes;
    cookie-secret "cookie_secret";
    coresize default;
    datasize 1G;
    deny-answer-addresses { 127.0.0.1; } except-from { "172.in-addr.arpa."; };
    deny-answer-aliases { "example.test"; "test.example"; } except-from { "172.in-addr.arpa."; };
    dialup notify-passive;
    directory "dir/file";
    disable-algorithms "aaaaaaaaaaaaaaaaa" { AES512; SHA512; };
    disable-ds-digests "." { RSASHA512; };
    disable-empty-zone "127.in-addr.arpa";
    dns64 64:ff9b::/96 { 
        break-dnssec yes;
        recursive-only no;
        clients { 127.0.0.1; };
        exclude { 127.0.0.1; };
        mapped   { 127.0.0.1; };
        };

    dns64-contact dns64.contact.string.content;
    dns64-server dns64.server.string.content;
    dnskey-sig-validity 3;
    dnsrps-enable no;
    dnskey-sig-validity 3;
    dnsrps-enable no;
    dnssec-accept-expired no;
    dnssec-dnskey-kskonly no;
    dnssec-loadkeys-interval 1;
    dnssec-must-be-secure "home.arpa." yes;
    dnssec-must-be-secure "example.test." yes;
    dnssec-policy my_policy;
    dnssec-secure-to-insecure no;
    dnssec-update-mode no-resign;
    dnssec-validation auto;
    dnstap { all; response; }; 
    dnstap-identity none;
    dnstap-output file "dir/file" size unlimited versions 5 suffix timestamp;
    dnstap-version none;
    dscp 14;
    dump-file "dir/file";
    edns-udp-size 512;
    empty-contact "empty-contact-string-content";
    empty-server "empty-server-string-content";
    empty-zones-enable no;
    fetch-quota-params 5 1.0 1.0 1.0;
    fetches-per-server 5 drop;
    fetches-per-zone 4 drop;
    files unlimited;
    flush-zones-on-shutdown no;
    forward only;
    forwarders port 753 { 127.0.0.1; };
    geoip-directory none;
    heartbeat-interval 60;
    hostname none;
    http-listener-clients 5;
    http-port 80;
    http-streams-per-connection 5;
    https-port 443;
    interface-interval 60;
    ipv4only-contact "ipv4only-contact-string-content";
    ipv4only-enable no;
    ipv4only-server "ipv4only-contact-string-content";
    ixfr-from-differences primary;
    keep-response-order { 127.0.0.1; };
    key-directory "dir/file";
    lame-ttl 60;
    listen-on port 53 tls TLS_NAME http HTTP_NAME { 127.0.0.1; };
    listen-on-v6 port 53 tls TLS_NAME http HTTP_NAME { ::1; };
    lmdb-mapsize 1M;
    lock-file "dir/file";
    managed-keys-directory "dir/file";
    masterfile-format text;
    masterfile-style relative;
    match-mapped-addresses no;
    max-cache-size unlimited;
    max-cache-ttl 1H;
    max-clients-per-query 60;
    max-ixfr-ratio unlimited;
    max-journal-size 11M;
    max-ncache-ttl 1H;
    max-records 5;
    max-recursion-depth 3;
    max-recursion-queries 4;
    max-refresh-time 60;
    max-retry-time 60;
    max-rsa-exponent-size 512;
    max-stale-ttl 16;
    max-transfer-idle-in 5;
    max-transfer-idle-out 5;
    max-transfer-time-in 5;
    max-transfer-time-out 5;
    max-udp-size 5;
    max-zone-ttl unlimited;
    memstatistics no;
    memstatistics-file "dir/file";
    message-compression no;
    min-cache-ttl 1D;
    min-ncache-ttl 2d;
    min-refresh-time 1W;
    min-retry-time 1;
    minimal-any no;
    minimal-responses no-auth-recursive;
    multi-master no;
    new-zones-directory "dir/file";
    no-case-compress { example.test; };
    nocookie-udp-size 512;
    notify primary-only;
    notify-delay 60;
    notify-rate 60;
    notify-source * port * dscp 4;
    notify-source-v6 * port * dscp 5;
    notify-to-soa no;
    nsec3-test-zone no;
    nta-lifetime 60m;
    nta-recheck 24h;
    nxdomain-redirect redirect.example.test.;
    parental-source 127.0.0.1 port 12388;
    parental-source-v6 ffe2::1 port 12389;
    pid-file none;
    port 53;
    preferred-glue AAAA;
    prefetch 30 60;
    provide-ixfr no;
    qname-minimization relaxed;
    query-source address 127.0.0.1;
    query-source-v6 address fec2::1;
    querylog no;
    random-device none;
    rate-limit { all-per-second 60; };
    recursing-file "dir/file";
    recursion no;
    recursive-clients 60;
    request-expire no;
    request-ixfr no;
    request-nsid no;
    require-server-cookie no;
    reserved-sockets 30;
    resolver-nonbackoff-tries 25;
    resolver-query-timeout 24;
    resolver-retry-interval 23;
    response-padding { 127.0.0.1; } block-size 512;
    response-policy { 
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
             nsip-enable yes nsdname-enable yes dnsrps-enable yes ;
    reuseport no;
    root-delegation-only exclude { name1; name2; name3; };
    root-key-sentinel no;
    rrset-order { name "fixed.example" order fixed;
        name "random.example" order random;
        name "cyclic.example" order cyclic;
        name "none.example" order none;
        type NS order random;
        order cyclic; };
    secroots-file "dir/file";
    send-cookie no;
    serial-query-rate 5;
    serial-update-method unixtime;
    server-id hostname;
    servfail-ttl 1;
    session-keyalg hmac-md5;
    session-keyfile "dir/file";
    session-keyname "session_keyname";
    sig-signing-nodes 5;
    sig-signing-signatures 5;
    sig-signing-type 6;
    sig-validity-interval 5;
    sortlist { 
        { localhost; 
            { localnets; 192.168.1.0/24; 
                { 192.168.2.0/24; 192.168.3.0/24; }; }; }; 
        { 192.168.1.0/24; { 192.168.1.0/24; { 192.168.2.0/24; 192.168.3.0/24; }; }; }; };
    stacksize default;
    stale-answer-client-timeout disabled;
    stale-answer-enable no;
    stale-answer-ttl 60;
    stale-cache-enable no;
    stale-refresh-time 8;
    startup-notify-rate 5;
    statistics-file "dir/file";
    suppress-initial-notify no;
    synth-from-dnssec no;
    tcp-advertised-timeout 60;
    tcp-clients 60;
    tcp-idle-timeout 60;
    tcp-initial-timeout 60;
    tcp-keepalive-timeout 60;
    tcp-listen-queue 60;
    tcp-receive-buffer 60;
    tcp-send-buffer 60;
    tkey-dhkey "dhkey_string_content" 60;
    tkey-domain "172.in-addr.arpa.";
    tkey-gssapi-credential "kadmin/kdc1.example.test@EXAMPLE.TEST";
    tkey-gssapi-keytab "directory/file";
    tls-port 60;
    transfer-format many-answers;
    transfer-message-size 60;
    transfer-source 127.0.0.1 port 60 dscp 12;
    transfer-source-v6 ffec::1 port 60 dscp 11;
    transfers-in 60;
    transfers-out 60;
    transfers-per-ns 60;
    trust-anchor-telemetry no;
    try-tcp-refresh no;
    udp-receive-buffer 60;
    udp-send-buffer 60;
    update-check-ksk no;
    use-alt-transfer-source no;
    use-v4-udp-ports { range 1 1024; };
    use-v6-udp-ports { range 1025 44315; };
    v6-bias 60;
    validate-except { "168.192.in-addr.arpa."; };
    version "funky dns server, uh?";
    zero-no-soa-ttl no;
    zero-no-soa-ttl-cache no;
    zone-statistics terse;
};
    acl MY_BASTION_HOSTS { 4.4.4.4; 3.3.3.3; 2.2.2.2; 1.1.1.1; };
    controls { inet 128.0.0.9 port 8006 allow { 128.0.0.10; 128.0.0.11;} read-only yes; };
    dlz your_IBM_2 { database "RSDMS"; search no; };
    dyndb "example-ldap" "/usr/lib64/bind/ldap.so" { uri "ldap://ldap.example.com"; base "cn=dns, dc=example,dc=com"; auth_method "none"; };
    key dyndns { algorithm hmac-sha512; secret ABCDEFG; };
    logging { channel salesfolks { file "/tmp/sales.log" size 5M; severity info; print-time no;};
              channel accounting { file "/tmp/acct.log" size 30M; severity info; print-time no; };
              channel badguys { file "/tmp/alert" size 255G; severity debug 77; print-time yes;}; };
    managed-keys { www1.www.example.com initial-key 1 1 1 "ASBASDASD"; };
    masters bastion_host_group { bastion_hosts22; hidden_bastion; };
    zone red { file "/var/lib/bind9/public/masters/db.example.com"; };
    server 3.4.5.6 { bogus yes; edns no; edns-udp-size 102; edns-version 2;
                     keys my_key_name_to_private_dns; max-udp-size 32768; notify-source *; notify-source-v6 *;
                     padding 53; provide-ixfr yes; query-source *; query-source address *; query-source-v6 *;
                     request-expire yes; request-ixfr yes; request-nsid yes; send-cookie yes; tcp-keepalive yes;
                     tcp-only yes; transfer-format one-answer; transfer-source *; transfer-source-v6 *; transfers 36; };
    trusted-keys { abc 1 1 1 "ASBASDASD";};
    zone green { file "/var/lib/bind9/public/masters/db.green.com"; };
    masters dmz_masters port 7553 dscp 5 { 10.0.0.1 key priv_dns_chan_key5; };""",
            {'acl': [{'acl_name': 'MY_BASTION_HOSTS',
                      'aml_series': [{'aml': [{'ip4_addr': '4.4.4.4'},
                                              {'ip4_addr': '3.3.3.3'},
                                              {'ip4_addr': '2.2.2.2'},
                                              {'ip4_addr': '1.1.1.1'}]}]}],
             'controls': [{'inet': {'allow': {'aml': [{'ip4_addr': '128.0.0.10'},
                                                      {'ip4_addr': '128.0.0.11'}]},
                                    'control_server_addr': '128.0.0.9',
                                    'ip_port_w': '8006',
                                    'read-only': 'yes'}}],
             'dlz': [{'db_args': 'RSDMS',
                      'dlz_name': 'your_IBM_2',
                      'search': 'no'}],
             'dyndb': [{'db_name': '"example-ldap"',
                        'driver_parameters': 'uri '
                                             '"ldap://ldap.example.com"; '
                                             'base "cn=dns, '
                                             'dc=example,dc=com"; '
                                             'auth_method "none"; ',
                        'module_filename': '/usr/lib64/bind/ldap.so'}],
             'key': [{'algorithm': 'hmac-sha512',
                      'key_id': 'dyndns',
                      'secret': 'ABCDEFG'}],
             'logging': {'channels': [{'channel_name': 'salesfolks',
                                       'path_name': '/tmp/sales.log',
                                       'print_time': 'no',
                                       'severity': ['info'],
                                       'size_spec': [5, 'M']},
                                      {'channel_name': 'accounting',
                                       'path_name': '/tmp/acct.log',
                                       'print_time': 'no',
                                       'severity': ['info'],
                                       'size_spec': [30, 'M']},
                                      {'channel_name': 'badguys',
                                       'path_name': '/tmp/alert',
                                       'print_time': 'yes',
                                       'severity': {'debug': {'debug_level': 77}},
                                       'size_spec': [255, 'G']}]},
             'managed_keys': [{'algorithm_id': 1,
                               'flags': 1,
                               'key_secret': '"ASBASDASD"',
                               'protocol_id': 1,
                               'rr_domain': 'www1.www.example.com'}],
             'options': [{'allow-recursion': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'allow-recursion-on': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'allow_new_zones': 'yes',
                          'allow_notify': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'allow_query': {'aml': [{'keyword': 'any'}]},
                          'allow_query_cache': {'aml': [{'keyword': 'none'}]},
                          'allow_query_cache_on': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'allow_query_on': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'allow_transfer': {'aml': [{'ip4_addr': '127.0.0.1'}],
                                             'ip_port': '855'},
                          'allow_update': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'allow_update_forwarding': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'also-notify': {'port': '856',
                                          'remote': [{'ip_addr': '127.0.0.1',
                                                      'key_id': 'ABC_KEY',
                                                      'tls_algorithm_name': 'SSLv3'}]},
                          'alt_transfer_source': {'dscp_port': 1,
                                                  'ip_port_w': '*'},
                          'alt_transfer_source_v6': {'dscp_port': 2,
                                                     'ip_port_w': '*'},
                          'answer-cookie': 'no',
                          'attach_cache': 'ABC_CACHE',
                          'auth_nxdomain': 'no',
                          'auto_dnssec': 'off',
                          'automatic_interface_scan': 'no',
                          'avoid_v4_udp_ports': ['1', '2', '3'],
                          'avoid_v6_udp_ports': ['4', '5', '6'],
                          'bindkeys_file': 'dir/file',
                          'blackhole': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'check_dup_records': 'warn',
                          'check_integrity': 'no',
                          'check_mx': 'fail',
                          'check_mx_cname': 'ignore',
                          'check_names': [{'result_status': 'ignore',
                                           'zone_type': 'primary'}],
                          'check_sibling': 'fail',
                          'check_spf': 'warn',
                          'check_srv_cname': 'fail',
                          'check_wildcard': 'no',
                          'clients_per_query': 10,
                          'cookie_algorithm': 'aes',
                          'cookie_secret': '"cookie_secret"',
                          'coresize': ['default'],
                          'datasize': [1, 'G'],
                          'deny_answer_addresses': {'aml': [{'ip4_addr': '127.0.0.1'}],
                                                    'except_from': [{'fqdn': '172.in-addr.arpa.'}]},
                          'deny_answer_aliases': {'except_from': [{'fqdn': '172.in-addr.arpa.'}],
                                                  'name_list': ['example.test',
                                                                'test.example']},
                          'dialup': 'notify-passive',
                          'directory': 'dir/file',
                          'disable_algorithms': {'algorithms': ['AES512',
                                                                'SHA512'],
                                                 'domain_name': 'aaaaaaaaaaaaaaaaa'},
                          'disable_ds_digests': [{'algorithm_name': ['RSASHA512'],
                                                  'domain_name': '.'}],
                          'disable_empty_zone': [{'zone_name': '127.in-addr.arpa'}],
                          'dns64': [{'aml': [{'ip4_addr': '127.0.0.1'}],
                                     'break_dnssec': 'yes',
                                     'clients': [{'ip4_addr': '127.0.0.1'}],
                                     'exclude': [{'ip4_addr': '127.0.0.1'}],
                                     'mapped': [{'ip4_addr': '127.0.0.1'}],
                                     'netprefix': {'ip6_addr': '64:ff9b::',
                                                   'prefix': '96'},
                                     'recursive_only': 'no'}],
                          'dns64_contact': {'soa_rname': 'dns64.contact.string.content'},
                          'dns64_server': {'soa_rname': 'dns64.server.string.content'},
                          'dnskey_sig_validity': 3,
                          'dnsrps_enable': 'no',
                          'dnssec_accept_expired': 'no',
                          'dnssec_dnskey_kskonly': 'no',
                          'dnssec_loadkeys_interval': 1,
                          'dnssec_must_be_secure': [{'dnssec_secured': 'yes',
                                                     'fqdn': '"home.arpa."'},
                                                    {'dnssec_secured': 'yes',
                                                     'fqdn': '"example.test."'}],
                          'dnssec_policy': 'my_policy',
                          'dnssec_secure_to_insecure': 'no',
                          'dnssec_update_mode': 'no-resign',
                          'dnssec_validation': 'auto',
                          'dnstap': ['all', 'response'],
                          'dnstap-output': {'path': 'dir/file',
                                            'size': 'unlimited',
                                            'versions': 5},
                          'dnstap-version': 'none',
                          'dscp': 14,
                          'dump_file': 'dir/file',
                          'edns_udp_size': 512,
                          'empty_contact': {'soa_contact_name': 'empty-contact-string-content'},
                          'empty_server': {'soa_contact_name': 'empty-server-string-content'},
                          'empty_zones_enable': 'no',
                          'fetch_quota_params': {'high_threshold': 1.0,
                                                 'low_threshold': 1.0,
                                                 'moving_average_discount_rate': 1.0,
                                                 'moving_avg_recalculate_interval': 5},
                          'fetches_per_server': {'action': 'drop',
                                                 'fetches': 5},
                          'fetches_per_zone': {'action': 'drop',
                                               'fetches': 4},
                          'files': {'files_count': 'unlimited'},
                          'flush_zones_on_shutdown': 'no',
                          'forward': 'only',
                          'forwarders': {'forwarder': [{'ip_addr': '127.0.0.1'}],
                                         'ip_port': '753'},
                          'heartbeat_interval': 60,
                          'hostname': {'none': 'none'},
                          'http_listener_clients': 5,
                          'http_port': 80,
                          'http_streams_per_connection': 5,
                          'https_port': 443,
                          'interface_interval': 60,
                          'ip_port': '53',
                          'ipv4only_contact': {'soa_rname': 'ipv4only-contact-string-content'},
                          'ipv4only_enable': 'no',
                          'ipv4only_server': {'soa_rname': 'ipv4only-contact-string-content'},
                          'ixfr_from_differences': 'primary',
                          'keep-response-order': {'aml': [{'ip4_addr': '127.0.0.1'}]},
                          'key_directory': 'dir/file',
                          'lame_ttl': 60,
                          'listen_on': [{'aml': [{'ip4_addr': '127.0.0.1'}],
                                         'http_port': 'HTTP_NAME',
                                         'ip_port': '53',
                                         'tls_port': 'TLS_NAME'}],
                          'listen_on_v6': [{'aml': [{'ip6_addr': '::1'}],
                                            'http_port': 'HTTP_NAME',
                                            'ip_port': '53',
                                            'tls_port': 'TLS_NAME'}],
                          'lmdb_mapsize': {'amount': 1, 'unit': 'M'},
                          'lock_file': 'dir/file',
                          'managed_keys_directory': 'dir/file',
                          'masterfile_format': 'text',
                          'masterfile_style': 'relative',
                          'match_mapped_addresses': 'no',
                          'max-ixfr-ratio': 'unlimited',
                          'max-zone-ttl': 'unlimited',
                          'max_cache_size': ['unlimited'],
                          'max_cache_ttl': '1H',
                          'max_clients_per_query': 60,
                          'max_journal_size': [11, 'M'],
                          'max_ncache_ttl': '1H',
                          'max_records': 5,
                          'max_recursion_depth': 3,
                          'max_recursion_queries': 4,
                          'max_refresh_time': 60,
                          'max_retry_time': 60,
                          'max_rsa_exponent_size': 512,
                          'max_stale_ttl': '16',
                          'max_transfer_idle_in': 5,
                          'max_transfer_idle_out': 5,
                          'max_transfer_time_in': 5,
                          'max_transfer_time_out': 5,
                          'max_udp_size': 5,
                          'memstatistics': 'no',
                          'memstatistics_file': 'dir/file',
                          'message_compression': 'no',
                          'min_cache_ttl': '1D',
                          'min_ncache_ttl': '2d',
                          'min_refresh_time': '1W',
                          'min_retry_time': 1,
                          'minimal_any': 'no',
                          'multi_master': 'no',
                          'new_zones_directory': 'dir/file',
                          'no_case_compress': [{'acl_name': 'example.test'}],
                          'nocookie_udp_size': 512,
                          'notify': 'primary-only',
                          'notify_delay': 60,
                          'notify_rate': 60,
                          'notify_source': {'dscp_port': 4,
                                            'ip4_addr-w': '*',
                                            'ip4_port_w': '*'},
                          'notify_source_v6': {'dscp_port': 5,
                                               'ip6_addr': '*',
                                               'ip_port_w': '*'},
                          'notify_to_soa': 'no',
                          'nsec3_test_zone': 'no',
                          'nta_lifetime': '60m',
                          'nta_recheck': '24h',
                          'nxdomain_redirect': 'redirect.example.test.',
                          'parental_source': {'ip4_addr_w': '127.0.0.1',
                                              'ip_port_w': '12388'},
                          'parental_source_v6': {'ip6_addr_w': 'ffe2::1',
                                                 'ip_port_w': '12389'},
                          'preferred_glue': 'AAAA',
                          'prefetch': {'expiry_ttl': 30,
                                       'threshold_ttl': 60},
                          'provide_ixfr': 'no',
                          'qname_minimization': 'relaxed',
                          'query_source': {'ip4_addr': '127.0.0.1'},
                          'query_source_v6': {'ip6_addr': 'fec2::1'},
                          'querylog_boolean': 'no',
                          'rate_limit': [{'all_per_second': 60}],
                          'recursing_file': 'dir/file',
                          'recursion': 'no',
                          'recursive_clients': 60,
                          'request_expire': 'no',
                          'request_ixfr': 'no',
                          'request_nsid': 'no',
                          'require_server_cookie': 'no',
                          'reserved_sockets': 30,
                          'resolver_nonbackoff_tries': 25,
                          'resolver_query_timeout': 24,
                          'resolver_retry_interval': 23,
                          'response-padding': {'aml': [{'ip4_addr': '127.0.0.1'}],
                                               'fqdn': 512},
                          'response_policy': {'add_soa': 'no',
                                              'break_dnssec': 'no',
                                              'dnsrps_enable': 'yes',
                                              'max_policy_ttl': '30S',
                                              'min_ns_dots': 2,
                                              'min_update_interval': '4w',
                                              'nsdname_enable': 'yes',
                                              'nsdname_wait_recurse': 'yes',
                                              'nsip_enable': 'yes',
                                              'nsip_wait_recurse': 'yes',
                                              'qname_wait_recurse': 'yes',
                                              'recursive_only': 'yes',
                                              'zone': [{'add_soa': 'no',
                                                        'log': 'no',
                                                        'max_policy_ttl': '4Y',
                                                        'min_update_interval': '30S',
                                                        'nsdname_enable': 'no',
                                                        'nsip_enable': 'no',
                                                        'policy': ['no-op'],
                                                        'recursive_only': 'no',
                                                        'zone_name': '172.in-addr.arpa.'},
                                                       {'add_soa': 'yes',
                                                        'log': 'yes',
                                                        'max_policy_ttl': '3Y',
                                                        'min_update_interval': '20S',
                                                        'nsdname_enable': 'yes',
                                                        'nsip_enable': 'yes',
                                                        'policy': [[]],
                                                        'recursive_only': 'yes',
                                                        'zone_name': '168.192.in-addr.arpa.'},
                                                       {'add_soa': 'no',
                                                        'log': 'yes',
                                                        'max_policy_ttl': '4Y',
                                                        'min_update_interval': '30S',
                                                        'nsdname_enable': 'no',
                                                        'nsip_enable': 'yes',
                                                        'policy': ['no-op'],
                                                        'recursive_only': 'yes',
                                                        'zone_name': 'example.test.'},
                                                       {'add_soa': 'yes',
                                                        'log': 'yes',
                                                        'max_policy_ttl': '4Y',
                                                        'min_update_interval': '30S',
                                                        'nsdname_enable': 'no',
                                                        'nsip_enable': 'yes',
                                                        'policy': ['no-op'],
                                                        'recursive_only': 'yes',
                                                        'zone_name': 'example2.test.'},
                                                       {'add_soa': 'no',
                                                        'log': 'yes',
                                                        'max_policy_ttl': '4Y',
                                                        'min_update_interval': '30S',
                                                        'nsdname_enable': 'no',
                                                        'nsip_enable': 'yes',
                                                        'policy': ['no-op'],
                                                        'recursive_only': 'yes',
                                                        'zone_name': '172.in-addr.arpa.'}]},
                          'reuseport': 'no',
                          'root_delegation_only': {'domains': ['name1',
                                                               'name2',
                                                               'name3']},
                          'root_key_sentinel': 'no',
                          'rrset_order': [{'name': 'fixed.example',
                                           'order': 'fixed'},
                                          {'name': 'random.example',
                                           'order': 'random'},
                                          {'name': 'cyclic.example',
                                           'order': 'cyclic'},
                                          {'name': 'none.example',
                                           'order': 'none'},
                                          {'order': 'random',
                                           'type': 'NS'},
                                          {'order': 'cyclic'}],
                          'secroots_file': 'dir/file',
                          'send_cookie': 'no',
                          'serial_query_rate': 5,
                          'serial_update_method': 'unixtime',
                          'server_id_name': 'hostname',
                          'servfail_ttl': 1,
                          'session_keyalg': 'hmac-md5',
                          'session_keyfile': 'dir/file',
                          'session_keyname': '"session_keyname"',
                          'sig_signing_nodes': 5,
                          'sig_signing_signatures': 5,
                          'sig_signing_type': 6,
                          'sig_validity_interval': 5,
                          'sortlist': {'aml': [{'aml': [{'keyword': 'localhost'},
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
                                                                           'prefix': '24'}]}]}]}]},
                          'stacksize': ['default'],
                          'stale_answer_client_timeout': 'disabled',
                          'stale_answer_enable': 'no',
                          'stale_answer_ttl': 60,
                          'stale_cache_enable': 'no',
                          'stale_refresh_time': 8,
                          'startup_notify_rate': 5,
                          'statistics_file': 'dir/file',
                          'suppress_initial_notify': 'no',
                          'synth_from_dnssec': 'no',
                          'tcp_advertised_timeout': 60,
                          'tcp_clients': 60,
                          'tcp_idle_timeout': 60,
                          'tcp_initial_timeout': 60,
                          'tcp_keepalive_timeout': 60,
                          'tcp_listen_queue': 60,
                          'tcp_receive_buffer': 60,
                          'tcp_send_buffer': 60,
                          'tkey_dhkey': [{'host_name': 'dhkey_string_content',
                                          'key_tag': 60}],
                          'tkey_domain': '172.in-addr.arpa.',
                          'tkey_gssapi_credential': {'instance': 'kdc1.example.test',
                                                     'primary': 'kadmin',
                                                     'principal': 'kadmin/kdc1.example.test@EXAMPLE.TEST',
                                                     'realm': 'EXAMPLE.TEST'},
                          'tkey_gssapi_keytab': 'directory/file',
                          'tls_port': 60,
                          'transfer_format': 'many-answers',
                          'transfer_message_size': 60,
                          'transfer_source': {'dscp_port': 12,
                                              'ip4_addr': '127.0.0.1',
                                              'ip_port_w': '60'},
                          'transfer_source_v6': {'dscp_port': 11,
                                                 'ip6_addr': 'ffec::1',
                                                 'ip_port_w': '60'},
                          'transfers_in': 60,
                          'transfers_out': 60,
                          'transfers_per_ns': 60,
                          'trust_anchor_telemetry': 'no',
                          'try_tcp_refresh': 'no',
                          'udp_receive_buffer': 60,
                          'udp_send_buffer': 60,
                          'update_check_ksk': 'no',
                          'use_alt_transfer_source': 'no',
                          'use_v4_udp_ports': [{'port_end': 1024,
                                                'port_start': 1}],
                          'use_v6_udp_ports': [{'port_end': 44315,
                                                'port_start': 1025}],
                          'v6_bias': 60,
                          'validate_except': ['168.192.in-addr.arpa.'],
                          'version_string': 'funky dns server, uh?',
                          'zero_no_soa_ttl': 'no',
                          'zero_no_soa_ttl_cache': 'no',
                          'zone_statistics': 'terse'}],
             'primaries': [{'dscp_port': 5,
                            'ip_port': '7553',
                            'primary_id': 'dmz_masters',
                            'primary_list': [{'ip4_addr': '10.0.0.1',
                                              'key_id': 'priv_dns_chan_key5'}]}],
             'server': [{'configs': {'bogus': 'yes',
                                     'edns': 'no',
                                     'edns_udp_size': 102,
                                     'edns_version': 2,
                                     'keys': 'my_key_name_to_private_dns',
                                     'max_udp_size': 32768,
                                     'notify_source': {'ip4_addr': '*'},
                                     'notify_source_v6': {'ip6_addr_w': '*'},
                                     'padding': 53,
                                     'provide_ixfr': 'yes',
                                     'query_source': {'ip4_addr_w': '*'},
                                     'query_source_v6': {'ip6_addr_w': '*'},
                                     'request_expire': 'yes',
                                     'request_ixfr': 'yes',
                                     'request_nsid': 'yes',
                                     'send_cookie': 'yes',
                                     'tcp_keepalive': 'yes',
                                     'tcp_only': 'yes',
                                     'transfer_format': 'one-answer',
                                     'transfer_source': {'ip4_addr_w': '*'},
                                     'transfer_source_v6': {'ip6_addr': '*'},
                                     'transfers': 36},
                         'ip_addr': '3.4.5.6'}],
             'trusted_keys': [{'algorithm_id': '1',
                               'domain': 'abc',
                               'key_id': '1',
                               'protocol_type': '1',
                               'pubkey_base64': 'ASBASDASD'}],
             'zones': [{'file': '/var/lib/bind9/public/masters/db.example.com',
                        'zone_name': 'red'},
                       {'file': '/var/lib/bind9/public/masters/db.green.com',
                        'zone_name': 'green'}]}
        )


if __name__ == '__main__':
    unittest.main()
