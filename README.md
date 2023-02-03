# bind9-parser

You got `named.conf`?  Itching to read it and work with it ... in Python?

Now we can parse `named.conf` with relative ease using Python.  Could even output this as JSON so ANY language can read `named.conf`.

[PyParsing](https://github.com/pyparsing/pyparsing) is our friend, and there are some 2,400 BNF syntax elements for `named.conf` ... in Python3!

# Features

* Pythonized `named.conf` settings (DONE)
* JSON output (DONE)
* Schema lookup (DONE)
* offline local search engine on all Bind9 clauses, statements, and keywords. (DONE)
* Python chaining the setters/getters of `view`/`zone` clauses (DONE)
* Outputting `named.conf` (IN-PROGRES)

# Introduction

bind9_parser is a pythonized token constructor of `named.conf` configuration file 
used in ISC Bind9 DNS name server daemon.

bind9_parser parses a text-based `named.conf` containing ISC Bind9 configuration settings, such as:

```nginx
options {
    recursion yes;
    };
zone example.test IN {
    file "db.example.test.master";
    };
```

bind9_parser constructs a token tree of all settings found in the `named.conf`.

```python
named_conf_tokens = {
  'options': [{'recursion': 'yes'}],
  'zone': [
    {
      'zone_name': 'example.test',
      'class': 'IN',
      'file': 'db.example.test.master'
    } ] }
```

Tokenize `named.conf` variable consists of `dict` and `list` to ameliorate and preserve the many `1:1`
, `1:M`, `1:*`, and `N:M` relationships that are defined between its clause and statement keywords.

# Design

Token parser is chosen here for the primary purpose of performing automated checking of its valid settings. No concrete 
syntax tree (and certainly no abstract syntax tree either).

This is about as simple as getting and setting configurations with like an `.INI` file, but with the complexity of `named.conf`
instead.

# Token Parser Design

`PyParsing` library (v2.9+) is used to ensure accurate token extractions of `named.conf` settings and generates a single
variable containing the entire file.

Latest (and some 2,500-odd) EBNFs for ISC Bind9 `named.conf` have been incorporated and all of its clauses and
statements each have their own independently-usable `ParseElement` (an aspect of EBNF but in `PyParsing` parlance) that can be used to analyze even
smaller text portion of its configuration file.

Since there are no abstraction within `named.conf` (except maybe for the `addresses_match_list`), there is no need for
an AST.

No support for concrete syntax tree (CST) means no saving of comment lines, formatting, nor extraneous whitespaces. Sole
purpose of this design is to get all the raw `named.conf` settings. No CST support also means no way to reconstruct the
original file containing such annotation.

It is all about extracting the settings. Writing it back out into a `named.conf`-style file has become a secondary goal
here because too many passive security tools awaits this (pending) outputter() feature.

# Python  Design

The token tree consists of a Pythonized `dict`/`list` that is fully readable by various built-in JSON APIs.

There is a work-in-progress DESIGN document that will:

* tokenize `named.conf` (DONE)
* Python chaining the setters/getters of `view`/`zone` clauses (DONE)
* Outputting `named.conf` from its tokenized Python variable (IN-PROGRES)

[DESIGN-work-in-progress.md](DESIGN-work-in-progress.md)

# Examples

A working example of:

```nginx
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
    masters dmz_masters port 7553 dscp 5 { 10.0.0.1 key priv_dns_chan_key5; };
```

results in producing this variable:

```python
named_conf_elements = {
    'acl': [{'acl_name': 'MY_BASTION_HOSTS',
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
```

# Full-Blown Examples

```python
parse_result_named_conf = {
    'acl': [
        {'acl_name': 'MY_BASTION_HOSTS',
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
    'logging': [{'channel': [{'channel_name': 'salesfolks',
                              'path_name': '/tmp/sales.log',
                              'print_time': 'no',
                              'severity': ['info'],
                              'size_spec': [5, 'M']}]},
                {'channel': [{'channel_name': 'accounting',
                              'path_name': '/tmp/acct.log',
                              'print_time': 'no',
                              'severity': ['info'],
                              'size_spec': [30, 'M']}]},
                {'channel': [{'channel_name': 'badguys',
                              'path_name': '/tmp/alert',
                              'print_time': 'yes',
                              'severity': {'debug': [77]},
                              'size_spec': [255, 'G']}]}],
    'managed_keys': [{'algorithm_id': 1,
                      'flags': 1,
                      'key_secret': '"ASBASDASD"',
                      'protocol_id': 1,
                      'rr_domain': 'www1.www.example.com'}],
    'options': [{
        'action': 'drop',
        'allow-recursion': {'aml': [{'ip4_addr': '127.0.0.1'}]},
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
        'disable_algorithms': {'algorithms': ['AES512', 'SHA512'],
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
        'prefetch': {'expiry_ttl': 30, 'threshold_ttl': 60},
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
        'rrset_order': [{'name': 'fixed.example', 'order': 'fixed'},
                        {'name': 'random.example', 'order': 'random'},
                        {'name': 'cyclic.example', 'order': 'cyclic'},
                        {'name': 'none.example', 'order': 'none'},
                        {'order': 'random', 'type': 'NS'},
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
        'use_v4_udp_ports': {'port_end': 1024, 'port_start': 1},
        'use_v6_udp_ports': {'port_end': 44315, 'port_start': 1025},
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
    'trusted_keys': parser_result_trusted_keys,
    'zones': [{'file': '/var/lib/bind9/public/masters/db.example.com',
               'zone_name': 'red'},
              {'file': '/var/lib/bind9/public/masters/db.green.com',
               'zone_name': 'green'}]}
```

# Quick Demo

What does the Python variable name look like if I parsed [`named-zytrax.conf`](https://github.com/egberts/bind9_parser/blob/master/examples/named-conf/named-zytrax.conf).

```command
$ ./dump-named-conf.py examples/named-conf/named-zytrax.conf
```

```python
print(result.asDict()):
{'logging': [{'channel': [{'channel_name': 'example_log',
                           'path_name': '/var/log/named/example.log',
                           'print_category': 'yes',
                           'print_severity': 'yes',
                           'print_time': 'yes',
                           'severity': ['info'],
                           'size_spec': [2,
                                         'm'],
                           'versions': 3}]},
             {'category_group': [{'categories': ['example_log'],
                                  'category_group_name': 'default'}]}],
 'options': [{'allow-recursion': {'aml': [{'ip4_addr': '192.168.3.0',
                                           'prefix': '24'}]},
              'allow_transfer': {'aml': [{'acl_name': '"none"'}]},
              'directory': '/var/named',
              'version_string': 'get '
                                'lost'}],
 'zones': [{'file': 'root.servers',
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
```



# Quick HOWTO

To take your `named.conf` file and output a Pythonized variable containing ALL
of the settings found:

```shell
./dump-named-conf.py examples/named-conf/named-oracle.conf
```
and the output of the Python array variable is:
```console
{'logging': [{'category_group': [{'categories': ['default_syslog'],
                                  'category_group_name': 'queries'}]}],
 'options': [{'allow_transfer': {'aml': [{'addr': '127.0.1.1/24'}]},
              'datasize': [2098],
              'directory': '"/var/named"',
              'forward': 'only',
              'forwarders': {'forwarders_list': [{'addr': '99.11.33.44'}]},
              'recursion': 'no',
              'transfers_in': 10,
              'transfers_per_ns': 2}],
 'zones': [{'file': '"db.cities.zn"',
            'type': 'master',
            'zone_name': '"cities.zn"'},
           {'file': '"db.127.cities.zn"',
            'type': 'master',
            'zone_name': '"0.0.127.in-addr.arpa"'},
           {'file': '"db.cities.zn.rev"',
            'type': 'master',
            'zone_name': '"168.192.in-addr.arpa"'},
           {'file': '"slave/db.sales.doc"',
            'masters_zone': {'zone_master_list': [{'ip4': '192.168.1.151'}]},
            'type': 'slave',
            'zone_name': '"sales.doc.com"'},
           {'file': '"slave/db.sales.doc.rev"',
            'masters_zone': {'zone_master_list': [{'ip4': '192.168.1.151'}]},
            'type': 'slave',
            'zone_name': '"168.192.in-addr.arpa"'}]}
```

To install this package, consult README.install.md


# Features

Features:
* 'include' statements are also folded into the parser
* Relative directory support (not stuck on /etc/bind or /var/lib/bind)
  * Useful for testing many config files in their respective local subdirectory(s).
* Support for Bind 4.8 to v9.15.1 (working on Bind10)
* ISC config files are used in ISC Bind9 server, as well as both ISC DHCP server and client.

bind9-parser make it so easy to do all of that, and now easier for you.

# Introduction
Here is a program to parse ``"options { server-id 'example.invalid'; };"`` :

```python

    from bind9_parser import *
    test_named_conf_text = "options { server-id 'example.invalid'; };"
    result = clause_statements.parseString(test_named_conf_text, parseAll=True)
    print(result.asDict())
```

The program outputs the following::

```python
    {'options': [{'server_id_name': "'example.invalid'"}]}
```



# Unit Tests
A massive unit tests files are supplied (under `tests/` subdirectory) to ensure that future breakage does not occur.

I use JetBrain PyCharm to unittest these all these modules.  However, you can also do it from a command line:
```console
python3 -munittest tests/test_*.py
```

# JSON 

```console
$ ./dump-named-conf-json.py examples/named-conf/named-oracle.conf 
```

```console
print(result.asDict()):
{'logging': [{'category_group': [{'categories': ['default_syslog'],
                                  'category_group_name': 'queries'}]}],
 'options': [{'allow_transfer': {'aml': [{'ip4_addr': '127.0.1.1',
                                          'prefix': '24'}]},
              'datasize': [2098],
              'directory': '/var/named',
              'forward': 'only',
              'forwarders': {'forwarder': [{'ip_addr': '99.11.33.44'}]},
              'recursion': 'no',
              'transfers_in': 10,
              'transfers_per_ns': 2}],
 'zones': [{'file': 'db.cities.zn',
            'type': 'master',
            'zone_name': 'cities.zn'},
           {'file': 'db.127.cities.zn',
            'type': 'master',
            'zone_name': '0.0.127.in-addr.arpa'},
           {'file': 'db.cities.zn.rev',
            'type': 'master',
            'zone_name': '168.192.in-addr.arpa'},
           {'file': 'slave/db.sales.doc',
            'masters_zone': {'zone_master_list': [{'ip4': '192.168.1.151'}]},
            'type': 'slave',
            'zone_name': 'sales.doc.com'},
           {'file': 'slave/db.sales.doc.rev',
            'masters_zone': {'zone_master_list': [{'ip4': '192.168.1.151'}]},
            'type': 'slave',
            'zone_name': '168.192.in-addr.arpa'}]}

JSON dump:

json-pretty:  {
    "options": [
        {
            "directory": "/var/named",
            "datasize": [
                2098
            ],
            "forward": "only",
            "forwarders": {
                "forwarder": [
                    {
                        "ip_addr": "99.11.33.44"
                    }
                ]
            },
            "recursion": "no",
            "transfers_in": 10,
            "transfers_per_ns": 2,
            "allow_transfer": {
                "aml": [
                    {
                        "ip4_addr": "127.0.1.1",
                        "prefix": "24"
                    }
                ]
            }
        }
    ],
    "logging": [
        {
            "category_group": [
                {
                    "category_group_name": "queries",
                    "categories": [
                        "default_syslog"
                    ]
                }
            ]
        }
    ],
    "zones": [
        {
            "zone_name": "cities.zn",
            "type": "master",
            "file": "db.cities.zn"
        },
        {
            "zone_name": "0.0.127.in-addr.arpa",
            "type": "master",
            "file": "db.127.cities.zn"
        },
        {
            "zone_name": "168.192.in-addr.arpa",
            "type": "master",
            "file": "db.cities.zn.rev"
        },
        {
            "zone_name": "sales.doc.com",
            "type": "slave",
            "file": "slave/db.sales.doc",
            "masters_zone": {
                "zone_master_list": [
                    {
                        "ip4": "192.168.1.151"
                    }
                ]
            }
        },
        {
            "zone_name": "168.192.in-addr.arpa",
            "type": "slave",
            "file": "slave/db.sales.doc.rev",
            "masters_zone": {
                "zone_master_list": [
                    {
                        "ip4": "192.168.1.151"
                    }
                ]
            }
        }
    ]
}
end of result.
```
# Status

At the moment, my focus is on the remaining breakage of just the unittesting scripts for  top-level 'options' clause where I'm busy doing unit-testing, but the EBNF is largely deployed and ready
to go and should work for a large percentage of deployed `named.conf`. It takes time to validate each clause and statement.

In the future, I do expect some minor tweaks for conversion to integer from strings, perhaps some argument validation.  Might be some forgotten aspect of EBNF like (1:N, or 1:1, or even 1:*).

Enjoy the parser.

# Why Did I Do This?

I see lots of Python scripts for ISC Bind Zone files, but not its configuration.  This Bind9 Parser (in Python) has to do or at least pave the way for the following:

* verification of settings against actual environment setting
* security audit
* massive unit testing of Bind 9 using pre-canned configurations
* implement CISecurity against Bind 9 

Closest cousin of Bind configuration format is NGINX config.

Closest Python (and configuration file) parser that I could find was
[liuyangc3/nginx_config_parser](https://github.com/liuyangc3/nginx_config_parser) on GitHub here.

Lots of generator, beautifier, lint, builder, change detector for Bind9 everywhere, but not a Python parser for Bind9 configuration file.

Works for Bind 4.9 to latest v9.19.1.

# Bonus Tools

## Offline Search Engine

We do offer a Python utility to annotate default ISC description for each clause/statement as an ease-of-use for a
budding DNS administrator. 

At the moment, this clause/statement keyword CLI utility is a simple dictionary lookup from a
static flat-file Python array database for we later plan to fold this into the `named.conf` outputter stage, as an
option.

This tool will help find related clauses or statements or even keywords related to your specific topic.  

Take **ANSWER** as a topic, let us search for this keyword, oh in Bind9 version 9.8 (kinda old, uh, but it goes up to ***v9.19.1*** **!!!**:

```console
$ python3 examples/rough-draft/namedconfglobal.py  -w topic -k answer -v9.19.1
Version: 9.19.1
Pattern: answer
----------------
sortlist
      comment:
 
The response to a DNS query may consist of multiple resource records
(RRs) forming a resource record set (RRset). The name server
normally returns the RRs within the RRset in an indeterminate order (but
see the ``rrset-order`` statement in :ref:`rrset_ordering`). The client resolver code should
rearrange the RRs as appropriate: that is, using any addresses on the
local net in preference to other addresses. However, not all resolvers
can do this or are correctly configured. When a client is using a local
server, the sorting can be performed in the server, based on the
client's address. This only requires configuring the name servers, not
all the clients.

The ``sortlist`` statement (see below) takes an ``address_match_list`` and
interprets it in a special way. Each top-level statement in the ``sortlist``
must itself be an explicit ``address_match_list`` with one or two elements. The
first element (which may be an IP address, an IP prefix, an ACL name, or a nested
``address_match_list``) of each top-level list is checked against the source
address of the query until a match is found. When the addresses in the first
element overlap, the first rule to match is selected.

Once the source address of the query has been matched, if the top-level
statement contains only one element, the actual primitive element that
matched the source address is used to select the address in the response
to move to the beginning of the response. If the statement is a list of
two elements, then the second element is interpreted as a topology
preference list. Each top-level element is assigned a distance, and the
address in the response with the minimum distance is moved to the
beginning of the response.

In the following example, any queries received from any of the addresses
of the host itself get responses preferring addresses on any of the
locally connected networks. Next most preferred are addresses on the
192.168.1/24 network, and after that either the 192.168.2/24 or
192.168.3/24 network, with no preference shown between these two
networks. Queries received from a host on the 192.168.1/24 network
prefer other addresses on that network to the 192.168.2/24 and
192.168.3/24 networks. Queries received from a host on the 192.168.4/24
or the 192.168.5/24 network only prefer other addresses on their
directly connected networks.


----------------
stale-answer-enable
      comment:
 
If ``yes``, enable the returning of "stale" cached answers when the name
servers for a zone are not answering and the ``stale-cache-enable`` option is
also enabled. The default is not to return stale answers.

Stale answers can also be enabled or disabled at runtime via
:option:`rndc serve-stale on <rndc serve-stale>` or :option:`rndc serve-stale off <rndc serve-stale>`; these override 
the configured setting. :option:`rndc serve-stale reset <rndc serve-stale>` restores the
setting to the one specified in :iscman:`named.conf`. Note that if stale
answers have been disabled by :iscman:`rndc`, they cannot be
re-enabled by reloading or reconfiguring :iscman:`named`; they must be
re-enabled with :option:`rndc serve-stale on <rndc serve-stale>`, or the server must be
restarted.

Information about stale answers is logged under the ``serve-stale``
log category.


----------------
stale-answer-ttl
      comment:
 
This specifies the TTL to be returned on stale answers. The default is 30
seconds. The minimum allowed is 1 second; a value of 0 is updated silently
to 1 second.

For stale answers to be returned, they must be enabled, either in the
configuration file using ``stale-answer-enable`` or via
:option:`rndc serve-stale on <rndc serve-stale>`.


END
```

# Coverages
[![build status](https://api.travis-ci.org/egberts/bind9_parser.svg)](https://travis-ci.org/egberts/bind9_parser)
[![coverage status](https://coveralls.io/repos/github/egberts/bind9_parser/badge.svg)](https://coveralls.io/github/egberts/bind9_parser)  
|  |license| |[![GitHub version](https://badge.fury.io/gh/egberts%2Fbind9_parser.svg)](https://badge.fury.io/gh/egberts%2Fbind9_parser)| |status|
|  |ci-status| |win-ci-status| |docs| | [![codecov](https://codecov.io/gh/egberts/bind9_parser/branch/master/graph/badge.svg?token=V8RieceAFx)](https://codecov.io/gh/egberts/bind9_parser) |
[![star this repo](http://githubbadges.com/star.svg?user=egberts&repo=bind9_parser)](http://github.com/egberts/bind9_parser/star)
[![fork this repo](http://githubbadges.com/fork.svg?user=egberts&repo=bind9_parser)](http://github.com/egberts/bind9_parser/fork)
|  |kit| |format| |repos| |downloads|
|| |contributors|
|  |tidelift| |twitter-coveragepy| |twitter-nedbat|
