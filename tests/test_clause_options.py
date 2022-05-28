#!/usr/bin/env python3
"""
File: test_clause_options.py

Description:  Performs unit test on the isc_options.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictFalse, assertParserResultDictTrue
from bind9_parser.isc_options import options_statements_set, options_statements_series,\
    options_stmt_avoid_v4_udp_ports

from bind9_parser.isc_clause_options import clause_stmt_options, options_all_statements_set,\
    options_all_statements_series


class TestClauseOptions(unittest.TestCase):
    """ Clause options """

    def test_isc_clause_options_all_statement_set_passing(self):
        """ Clause options; Statement Set All; passing mode """
        test_data = [
            'version 5;',
            'version 5;',
            ]
        result = options_all_statements_set.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_clause_options_all_statement_set_a_passing(self):
        """ Clause options; Statement Set All; keywords starting wtih 'a'; passing mode """
        assertParserResultDictTrue(
            options_all_statements_series,
            """
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
avoid-v6-udp-ports { 4; 5; 6; };""",
            {'allow-recursion': {'aml': [{'ip4_addr': '127.0.0.1'}]},
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
             'alt_transfer_source': {'dscp_port': 1, 'ip_port_w': '*'},
             'alt_transfer_source_v6': {'dscp_port': 2, 'ip_port_w': '*'},
             'answer-cookie': 'no',
             'attach_cache': 'ABC_CACHE',
             'auth_nxdomain': 'no',
             'auto_dnssec': 'off',
             'automatic_interface_scan': 'no',
             'avoid_v4_udp_ports': ['1', '2', '3'],
             'avoid_v6_udp_ports': ['4', '5', '6']}
            )

    def test_isc_clause_options_all_statement_set_check_passing(self):
        """ Clause options; Statement Set All; keywords starting from 'b' to 'c'; passing mode """
        assertParserResultDictTrue(
            options_all_statements_series,
            """
    deny-answer-addresses { 127.0.0.1; } except-from { "172.in-addr.arpa."; };
""",
            {'deny_answer_addresses': {'aml': [{'ip4_addr': '127.0.0.1'}],
                                       'except_from': [{'fqdn': '172.in-addr.arpa.'}]}}
        )

    def test_isc_clause_options_all_statement_set_b_to_c_passing(self):
        """ Clause options; Statement Set All; keywords starting from 'b' to 'c'; passing mode """
        assertParserResultDictTrue(
            options_all_statements_series, """
bindkeys-file "dir/file";
blackhole { 127.0.0.1; };
check-dup-records ignore;
check-dup-records warn;
check-integrity no;
check-mx fail;
check-mx-cname ignore;
check-names primary ignore;
check-sibling warn;
check-spf warn;
check-srv-cname fail;
check-wildcard no;
clients-per-query 10;
cookie-algorithm aes;
cookie-secret "cookie_secret";
coresize default;
""",
            {'bindkeys_file': 'dir/file',
             'blackhole': {'aml': [{'ip4_addr': '127.0.0.1'}]},
             'check_dup_records': 'warn',
             'check_integrity': 'no',
             'check_mx': 'fail',
             'check_mx_cname': 'ignore',
             'check_names': [{'result_status': 'ignore',
                              'zone_type': 'primary'}],
             'check_sibling': 'warn',
             'check_spf': 'warn',
             'check_srv_cname': 'fail',
             'check_wildcard': 'no',
             'clients_per_query': 10,
             'cookie_algorithm': 'aes',
             'cookie_secret': '"cookie_secret"',
             'coresize': ['default']}
        )

    x = """
"""

    def test_isc_clause_options_all_statement_set_d_passing(self):
        """ Clause options; Statement Set All; keywords starting wtih 'd'; passing mode """
        assertParserResultDictTrue(
            options_all_statements_series,
            """
deny-answer-addresses { 127.0.0.2/24; };
deny-answer-addresses { 127.0.0.1/24; } except-from { "172.in-addr.arpa."; };
deny-answer-aliases { "example.test"; "test.example"; } except-from { "172.in-addr.arpa."; };
deny-answer-addresses {
    0.0.0.0; 
    10.0.0.0/8;
    172.16.0.0/12;
    192.168.0.0/16;
    169.254.0.0/16;
    ::/80;
    fe80::/10;
    64:ff9b::/96;
} except-from { "Your.Domain"; };
dialup notify-passive;
directory "dir/file";
disable-algorithms "aaaaaaaaaaaaaaaaa" { AES512; SHA512; };
disable-algorithms "172.in-addr.arpa." { AES512; SHA512; RSASHA512; };
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
dump-file "dir/file";""",
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
                                       'except_from': [{'fqdn': 'Your.Domain'}]},
             'deny_answer_aliases': {'except_from': [{'fqdn': '172.in-addr.arpa.'}],
                                     'name_list': ['example.test',
                                                   'test.example']},
             'dialup': 'notify-passive',
             'directory': 'dir/file',
             'disable_algorithms': {'algorithms': ['AES512',
                                                   'SHA512',
                                                   'RSASHA512'],
                                    'domain_name': '172.in-addr.arpa.'},
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
             'dump_file': 'dir/file'}
        )

    def test_isc_clause_options_all_statement_set_e_to_i_passing(self):
        """ Clause options; Statement Set All; keywords starting from 'e' to 'i'; passing mode """
        assertParserResultDictTrue(
            options_all_statements_series,
            """
edns-udp-size 512;
empty-contact empty-contact-string-content;
empty-server empty-server-string-content;
empty-zones-enable no;
fetch-quota-params 5 10 10 10;
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
ipv4only-contact ipv4only.contact.string.content;
ipv4only-enable no;
ipv4only-server ipv4only.con-tact.string.content;
ixfr-from-differences primary;
""",
            {'action': 'drop',
             'edns_udp_size': 512,
             'empty_contact': {'soa_contact_name': 'empty-contact-string-content'},
             'empty_server': {'soa_contact_name': 'empty-server-string-content'},
             'empty_zones_enable': 'no',
             'fetch_quota_params': {'high_threshold': 10,
                                    'low_threshold': 10,
                                    'moving_average_discount_rate': 10,
                                    'moving_avg_recalculate_interval': 5},
             'fetches_per_server': 5,
             'fetches_per_zone': 4,
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
             'ipv4only_contact': {'soa_rname': 'ipv4only.contact.string.content'},
             'ipv4only_enable': 'no',
             'ipv4only_server': {'soa_rname': 'ipv4only.con-tact.string.content'},
             'ixfr_from_differences': 'primary'}
        )

    def test_isc_clause_options_all_statement_set_k_to_m_passing(self):
        """ Clause options; Statement Set All; keywords starting from 'k' to 'm'; passing mode """
        assertParserResultDictTrue(
            options_all_statements_series,
            """
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
max-journal-size 11M;
max-ncache-ttl 1H;
max-records 5;
max-retry-time 60;
max-rsa-exponent-size 512;
max-transfer-idle-in 5;
max-transfer-idle-out 5;
max-transfer-time-in 5;
max-transfer-time-out 5;
memstatistics no;
memstatistics-file "dir/file";
multi-master no;
max-recursion-depth 3;
max-recursion-queries 4;
max-stale-ttl 16;
max-udp-size 5;
max-zone-ttl unlimited;
message-compression no;
min-cache-ttl 1D;
min-ncache-ttl 2d;
max-refresh-time 60;
min-refresh-time 1W;
min-retry-time 1;
minimal-any no;
minimal-responses no-auth-recursive;
max-ixfr-ratio unlimited;""",
            {'keep-response-order': {'aml': [{'ip4_addr': '127.0.0.1'}]},
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
             'max-zone-ttl': {'files_count': 'unlimited'},
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
             'multi_master': 'no'}
        )

    def test_isc_clause_options_all_statement_set_n_to_r_passing(self):
        """ Clause options; Statement Set All; keywords starting from 'n' to 'r'; passing mode """
        assertParserResultDictTrue(
            options_all_statements_series,
            """
notify-source * port * dscp 4;
notify-source-v6 * port * dscp 5;
notify-to-soa no;
port 53;
prefetch 30 60;
provide-ixfr no;
query-source-v6 address fec2::1;
querylog no;
rate-limit { all-per-second 60; };
recursing-file "dir/file";
recursion no;
recursive-clients 60;
request-ixfr no;
request-nsid no;
resolver-query-timeout 24;
nocookie-udp-size 512;
notify primary-only;
notify-delay 60;
notify-rate 60;
pid-file none;
random-device none;
reuseport no;
reserved-sockets 30;

nsec3-test-zone no;
nta-lifetime 60m;
nta-recheck 24h;
nxdomain-redirect "redirect.example.test.";
parental-source 127.0.0.1 port 88;
preferred-glue "some_glue";
qname-minimization strict;
query-source address 127.0.0.1 );
request-expire no;
require-server-cookie no;
resolver-nonbackoff-tries 25;
resolver-retry-interval 23;
response-padding { 127.0.0.1; } block-size 512;
response-policy { zone "." log on };
root-delegation-only exclude { "127.in-addr.arpa."; };
root-key-sentinel no;
rrset-order { class IN A example.test; };
""",
            {}
        )
        
    def test_isc_clause_options_all_statement_set_s_to_z_passing(self):
        """ Clause options; Statement Set All; keywords starting from 's' to 'z'; passing mode """
        assertParserResultDictTrue(
            options_all_statements_series,
            """
secroots-file "dir/file";
send-cookie no;
serial-query-rate 5;
serial-update-method unixtime;
server-id hostname;
servfail-ttl 30m;
session-keyalg AES512;
session-keyfile "dir/file";
session-keyname "session_keyname";
sig-signing-nodes 5;
sig-signing-signatures 5;
sig-signing-type 6;
sig-validity-interval 5;
sortlist { 127.0.0.1; };
stacksize default;
stale-answer-client-timeout disabled;
stale-answer-enable no;
stale-answer-ttl 60s;
stale-cache-enable no;
stale-refresh-time 8h;
startup-notify-rate 5;
statistics-file "dir/file";
suppress-initial-notify no;  // obsolete
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
tkey-gssapi-credential "krb5_credential";
tkey-gssapi-keytab "keytab_string_content";
tls-port 60;
transfer-format many-answers;
transfer-message-size 60;
transfer-source 127.0.0.1 port 60 dscp 12;
transfer-source-v6 ffec::1 port 60 dscp 11;
transfers-in 60;
transfers-out 60;
transfers-per-ns 60;
trust-anchor-telemetry no; // experimental
try-tcp-refresh no;
udp-receive-buffer 60;
udp-send-buffer 60;
update-check-ksk no;
use-alt-transfer-source no;
use-v4-udp-ports { 1;2;3;4;5;6;7; };
use-v6-udp-ports { 8;9;10;11;12;13;14;15; };
v6-bias 60;
validate-except { "168.192.in-addr.arpa."; };
version "funky dns server, uh?";
zero-no-soa-ttl no;
zero-no-soa-ttl-cache no;
zone-statistics terse;""",
            {}
        )

    def test_isc_clause_options_all_statement_set_all_passing(self):
        """ Clause options; Statement Set All ; passing mode """
        assertParserResultDictTrue(
            options_all_statements_series,
            """
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
alt-transfer-source * port *;
alt-transfer-source * port * dscp 1;
alt-transfer-source-v6 * port * dscp 2;
answer-cookie no;
attach-cache ABC_CACHE;
auth-nxdomain no;
auto-dnssec off;
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
check-spf warn;
check-srv-cname fail;
check-wildcard no;
clients-per-query 10;
cookie-algorithm aes;
cookie-secret "cookie_secret";
coresize default;
datasize 1G;
dialup notify-passive;
directory "dir/file";
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
dnsrps-options { "<unspecified-text>"; };
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
min-retry-time 1w;
minimal-any no;
minimal-responses no-auth-recursive;
multi-master no;
new-zones-directory "dir/file";
no-case-compress { 127.0.0.1; };
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
nxdomain-redirect "redirect.example.test.";
parental-source 127.0.0.1 port 88;
pid-file none;
port 53;
preferred-glue "some_glue";
prefetch 30 60;
provide-ixfr no;
qname-minimization strict;
query-source address 127.0.0.1 );
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
response-policy { zone "." log on };
reuseport no;
root-delegation-only exclude { "127.in-addr.arpa."; };
root-key-sentinel no;
rrset-order { class IN A example.test; };
secroots-file "dir/file";
send-cookie no;
serial-query-rate 5;
serial-update-method unixtime;
server-id hostname;
servfail-ttl 30m;
session-keyalg AES512;
session-keyfile "dir/file";
session-keyname "session_keyname";
sig-signing-nodes 5;
sig-signing-signatures 5;
sig-signing-type 6;
sig-validity-interval 5;
sortlist { 127.0.0.1; };
stacksize default;
stale-answer-client-timeout disabled;
stale-answer-enable no;
stale-answer-ttl 60s;
stale-cache-enable no;
stale-refresh-time 8h;
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
tkey-gssapi-credential "krb5_credential";
tkey-gssapi-keytab "keytab_string_content";
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
use-v4-udp-ports { 1;2;3;4;5;6;7; };
use-v6-udp-ports { 8;9;10;11;12;13;14;15; };
v6-bias 60;
validate-except { "168.192.in-addr.arpa."; };
version "funky dns server, uh?";
zero-no-soa-ttl no;
zero-no-soa-ttl-cache no;
zone-statistics terse;
automatic-interface-scan off;
also-notify port 856 { 127.0.0.1; key ABC_KEY; tls TLS_NAME; };
check-sibling no;
deny-answer-addresses { 127.0.0.1; } except-from { "172.in-addr.arpa." };
deny-answer-aliases { 127.0.0.1; } except-from { "172.in-addr.arpa." };
disable-algorithms "172.in-addr.arpa." { "AES512"; "SHA512" };
disable-ds-digests "." { "RSA512" };
disable-empty-zone "172.16.0.0/22";
""",
            {'ip_port': '53', 'version_string': '5'}
        )

    def test_isc_clause_options_all_statements_set_failing(self):
        """ Clause options; Statement Set All; failing mode """
        test_data = [
            'also-notify localhost;',
        ]
        result = options_all_statements_set.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_clause_options_all_statement_series_1_passing(self):
        """ Clause options; Statement Series 1; passing mode """
        test_data = [
            'version 5; port 53;',
            'version 5; coresize unlimited; pid-file "/var/run/named.pid";',
            ]
        result = options_all_statements_series.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_clause_options_all_statement_series_2_passing(self):
        """ Clause options; Statement Series 2; passing mode """
        assertParserResultDictTrue(
            options_all_statements_series,
            'version 5; port 53;',
            {'ip_port': '53', 'version_string': '5'}
        )

    def test_isc_clause_options_all_statement_series_3_passing(self):
        """ Clause options; Statement Series 3; passing mode """
        assertParserResultDictTrue(
            options_all_statements_series,
            'version 5; coresize unlimited; pid-file "/var/run/named.pid";',
            {'coresize': ['unlimited'],
             'pid_file_path_name': '/var/run/named.pid',
             'version_string': '5'}
        )

    def test_isc_clause_options_all_statement_series_4_passing(self):
        """ Clause options; Statement Series 4; passing mode """
        assertParserResultDictTrue(
            options_all_statements_series,
            'version 5; port 53;',
            {'ip_port': '53', 'version_string': '5'}
        )

    def test_isc_clause_options_all_statements_series_5_failing(self):
        """ Clause options; Statement Series 5; failing mode """
        test_data = [
            'version 5; moresize unlimited; pid-file "/var/run/named.pid";',
        ]
        result = options_all_statements_series.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_clause_stmt_option_passing(self):
        """ Clause options; passing mode """
        test_data = [
            'options { version 5; coresize unlimited; pid-file "/var/run/named.pid"; };',
            ]
        result = clause_stmt_options.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_clause_stmt_options_failing(self):
        """ Clause options; failing mode """
        test_data = [
            'country us',
        ]
        result = clause_stmt_options.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()

