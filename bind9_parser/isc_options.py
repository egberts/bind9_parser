#!/usr/bin/env python3
"""
File: isc_options.py

Clause: options

Title: Statements Used Only By 'options' Clause

Description: Various 'options' statement that is used
             only by 'options' clause.
"""
from pyparsing import Group, Keyword, Optional, \
    ZeroOrMore, OneOrMore, Literal, ungroup, CaselessLiteral
from pyparsing import pyparsing_common
from bind9_parser.isc_utils import lbrack, rbrack, semicolon, size_spec, \
    dequotable_path_name, number_type, seconds_type, \
    isc_boolean, krb5_principal_name, \
    exclamation, dequoted_path_name, squote, dquote, \
    fqdn_name_dequoted, fqdn_name_dequotable, quotable_name, \
    size_spec_nodefault, iso8601_duration, tsig_session_key_name
from bind9_parser.isc_inet import ip_port, \
    inet_dscp_port_keyword_and_number_element, \
    inet_http_port_keyword_and_number_element, \
    inet_ip_port_keyword_and_number_element, \
    inet_tls_port_keyword_and_number_element, \
    dscp_port
from bind9_parser.isc_domain import dequotable_domain_generic_fqdn
from bind9_parser.isc_aml import aml_nesting, aml_choices


options_stmt_acache_cleaning_interval = (
    Keyword('acache-cleaning-interval').suppress()
    - seconds_type('acache_cleaning_interval')
    + semicolon
)
options_stmt_acache_cleaning_interval.setName('acache-cleaning-interval <seconds>;')

options_stmt_acache_enable = (
    Keyword('acache-enable').suppress()
    - isc_boolean('acache-enable')
    + semicolon
)
options_stmt_acache_enable.setName('acache-enable <boolean>;')

options_stmt_answer_cookie = (
    Keyword('answer-cookie').suppress()
    - isc_boolean('answer-cookie')
    - semicolon
)
options_stmt_answer_cookie.setName('answer_cookie <boolean>;')

options_stmt_automatic_interface_scan = (
    Keyword('automatic-interface-scan').suppress()
    - isc_boolean('automatic_interface_scan')
    + semicolon
)
options_stmt_automatic_interface_scan.setName('automatic-interface-scan <boolean>;')

options_ip_port_list = (
    ip_port
    + semicolon
)

options_ip_port_series = (
    OneOrMore(
        ungroup(
            options_ip_port_list
        )
    )('options_ip_port_series_OneOrMore')
)

options_stmt_avoid_v4_udp_ports = (
    Keyword('avoid-v4-udp-ports').suppress()
    + lbrack
    + options_ip_port_series('avoid_v4_udp_ports')
    + rbrack
    + semicolon
)
options_stmt_avoid_v4_udp_ports.setName('avoid-v4-udp-ports { port; ... };')

options_stmt_avoid_v6_udp_ports = (
    Keyword('avoid-v6-udp-ports').suppress()
    + lbrack
    + options_ip_port_series('avoid_v6_udp_ports')
    + rbrack
    + semicolon
)
options_stmt_avoid_v6_udp_ports.setName('avoid-v6-udp-ports { port; ... };')

#  Wut?  was 'bindkey-file', now 'bindkeys-file'???
#  bindkey-file <path_name>; [ Opt ]    #  v9.5.0 to Feb 2017
options_stmt_bindkeys_file = (
    Keyword('bindkeys-file').suppress()
    - dequoted_path_name('bindkeys_file')
    + semicolon
)
options_stmt_bindkeys_file.setName('bindkeys-file <quoted-filespec>;')

options_stmt_blackhole = (
        Keyword('blackhole').suppress()
        + Group(
            aml_nesting('')
        )('blackhole')
)
options_stmt_blackhole.setName('blackhole <aml>;')

# cache-file <path_name> moved to isc_optview.py

options_stmt_clients_per_query = (
        Keyword('clients-per-query').suppress()
        - pyparsing_common.integer('clients_per_query')
        + semicolon
)
options_stmt_clients_per_query.setName('clients-per-query <integer>;')

options_stmt_cookie_algorithm = (
        Keyword('cookie-algorithm').suppress()
        - (
                Literal('aes')
                | Literal('siphash24')
        )('cookie_algorithm')
        + semicolon
)
options_stmt_cookie_algorithm.setName('cookie-algorithm [ aes | siphash24 ];')

options_stmt_cookie_secret = (
        Keyword('cookie-secret').suppress()
        - quotable_name('cookie_secret')
        - semicolon
)
options_stmt_cookie_secret.setName('cookie-secret <secret>;')

options_stmt_coresize = (
        Keyword('coresize').suppress()
        - size_spec('coresize')
        + semicolon
)
options_stmt_coresize.setName('coresize <size-spec>;')

options_stmt_datasize = (
    Keyword('datasize').suppress()
    - size_spec('datasize')
    + semicolon
)
options_stmt_datasize.setName('datasize <size-spec>;')

#  deallocate-on-exit <isc_boolean>;
options_stmt_deallocate_on_exit = (
    Keyword('deallocate-on-exit').suppress()
    - isc_boolean('deallocate_on_exit')
    + semicolon
)
options_stmt_deallocate_on_exit.setName('deallocate-on-exit <boolean>;')

#   deny-answer-addresses { address_match_list }
#     [ except-from { name_list } ]; [ Opt ]
options_stmt_deny_answer_addresses = (
    Keyword('deny-answer-addresses').suppress()
    - Group(
        lbrack
        + (
            ZeroOrMore(
                Group(
                    (
                        exclamation('not')
                        - aml_nesting
                    )
                    | (
                        exclamation('not')
                        - aml_choices
                        - semicolon
                    )
                    | (
                        aml_nesting
                    )
                    | (
                        aml_choices
                        - semicolon
                    )  # never set a ResultsLabel here, you get duplicate but un-nested 'ip_addr'
                )  # never set a ResultsLabel here, you get no []
            )
        )('aml')
        + rbrack
        # NOSEMICOLON HERE!
        - Optional(
            Keyword('except-from').suppress()
            + lbrack
            - OneOrMore(
                Group(
                    fqdn_name_dequoted('fqdn')
                    + semicolon
                )('except_from*')
            )
            + rbrack
        )
        + semicolon
    )('deny_answer_addresses')
)
options_stmt_deny_answer_addresses.setName('deny-answer-addresses [ except-from { <name>; } ];')

#   deny-answer-aliases { name_list }
#     [ except-from { name_list } ]; [ Opt ]
options_stmt_deny_answer_aliases = (
    Keyword('deny-answer-aliases').suppress()
    - Group(
        lbrack
        + (
            ZeroOrMore(
                ungroup(fqdn_name_dequoted)
                - semicolon
            )
        )('name_list')
        - rbrack
        # NOSEMICOLON HERE!
        - Optional(
            Keyword('except-from').suppress()
            - lbrack
            - OneOrMore(
                Group(
                    fqdn_name_dequoted('fqdn')
                    - semicolon
                )('except_from*')
            )
            - rbrack
        )
        - semicolon
    )('deny_answer_aliases')
)
options_stmt_deny_answer_aliases.setName('deny-answer-aliases [ except-from { <quotable-fqdn>; } ];')

options_stmt_directory = (
    Keyword('directory').suppress()
    - dequoted_path_name('directory')
    + semicolon
)
options_stmt_directory.setName('directory <quotable-fqdn>;')

#     Keyword('deny-answer-aliases').suppress()
#     - Group(
#         lbrack
#         - OneOrMore(
#             Group(
#                 name_type('name')
#                 + semicolon
#             )
#         )


#   dnstap-identity ( <quoted_string> | none | hostname ); [ Opt ]; since v9.11
options_stmt_dnstap_identity = (
        Keyword('dnstap-identity').suppress()
        + (
                Keyword('none')
                ^ Keyword('hostname')
                ^ fqdn_name_dequoted('dnstap_identity')
        )
        + semicolon
)
options_stmt_dnstap_identity.setName('dnstap-identity ( <quotable-fqdn> | none | hostname );')

#   dnstap-output; [ Opt ]; since v9.11
#          dnstap-output ( file | unix ) <quoted_string> [ size ( unlimited |
#             <size> ) ] [ versions ( unlimited | <integer> ) ] [ suffix (
#             increment | timestamp ) ];
options_stmt_dnstap_output_element_size = (
    Keyword('size').suppress()
    + ungroup(size_spec_nodefault)('size')
)

options_stmt_dnstap_output_element_versions = (
    Keyword('versions').suppress()
    + (
        Keyword('unlimited')
        ^ number_type('versions')
    )
)
options_stmt_dnstap_output_element_suffix = (
    Keyword('suffix').suppress()
    + (
        Literal('increment')
        | Literal('timestamp')
    )
)
options_stmt_dnstap_output_element = (
        options_stmt_dnstap_output_element_size
        ^ options_stmt_dnstap_output_element_versions
        ^ options_stmt_dnstap_output_element_suffix
)

options_stmt_dnstap_output = (
    Group(
        Keyword('dnstap-output').suppress()
        - Optional(
            Keyword('file')
            | Keyword('unix')
        )
        - dequoted_path_name('path')
        - OneOrMore(options_stmt_dnstap_output_element)
        - semicolon
    )('dnstap-output')
)
options_stmt_dnstap_output.setName('dnstap-output ( file | unix } <quotable-filepath>;')

options_stmt_dnstap_version = (
    Keyword('dnstap-version').suppress()
    - (
        Keyword('none')('dnstap-version')
        | (
            dequoted_path_name('dnstap-version')
        )
    )('dnstap-version')
    - semicolon
)
options_stmt_dnstap_version.setName('dnstap-version ( none | <quoted_filespec> );;')

#  dscp <integer>;
options_stmt_dscp = (
    Keyword('dscp').suppress()
    + (
        dscp_port('dscp_port')
    )('dscp')
    + semicolon
)
options_stmt_dscp.setName('dscp <number>;')

# dump-file <path_name>; [ Opt ]    # Introduced in v8.1, active at v9.6.3
options_stmt_dump_file = (
    Keyword('dump-file').suppress()
    - dequoted_path_name('dump_file')
    + semicolon
)
options_stmt_dump_file.setName('dump-file <quoted-filespec>;')

# fake-iquery <boolean.; [ Opt ]    # v8.1 to v9.0.0
options_stmt_fake_iquery = (
    Keyword('fake-iquery').suppress()
    - isc_boolean('fake_iquery')
    + semicolon
)
options_stmt_fake_iquery.setName('fake-iquery <boolean>;')

# flush-zones-on-shutdown <boolean>; [ Opt ]    # v9.3+
options_stmt_flush_zones_on_shutdown = (
    Keyword('flush-zones-on-shutdown').suppress()
    - isc_boolean('flush_zones_on_shutdown')
    + semicolon
)
options_stmt_flush_zones_on_shutdown.setName('flush-zones-on-shutdown <boolean>;')

options_stmt_geoip_directory = (
    Keyword('geoip-directory').suppress()
    - (
        Keyword('none')
        | dequoted_path_name('geoip_directory')
    )
    + semicolon
)
options_stmt_geoip_directory.setName('geoip-directory <quoted-filespec>;')

# has-old-clients <boolean>; [ Opt ]    # v8.1 to v9.7.0
options_stmt_has_old_clients = (
    Keyword('has-old-clients').suppress()
    - isc_boolean('has_old_clients')
    + semicolon
)
options_stmt_has_old_clients.setName('has-old-clients <boolean>;')

# hostname-statistics <boolean>; [ Opt ]  #  v8.1+, still inert
options_stmt_hostname_statistics = (
    Keyword('hostname-statistics').suppress()
    - isc_boolean('hostname_statistics')
    - semicolon
)
options_stmt_hostname_statistics.setName('hostname-statistics <boolean>;')

# http-listener-clients <number>;
options_stmt_http_listener_clients = (
    Keyword('http-listener-clients').suppress()
    - number_type('http_listener_clients')
    - semicolon
)

# http-port <number>;
options_stmt_http_port = (
    Keyword('http-port').suppress()
    - number_type('http_port')
    - semicolon
)

# http-streams-per-connection <number>;
options_stmt_http_streams_per_connection = (
    Keyword('http-streams-per-connection').suppress()
    - number_type('http_streams_per_connection')
    - semicolon
)

# https-port <number>;
options_stmt_https_port = (
    Keyword('https-port').suppress()
    - number_type('https_port')
    - semicolon
)

# hostname-statistics-max <number>; [ Opt ]  #  v8.1+, still inert
options_stmt_hostname_statistics_max = (
    Keyword('hostname-statistics-max').suppress()
    - isc_boolean('hostname_statistics_max')
    + semicolon
)
options_stmt_hostname_statistics_max.setName('hostname-statistics-max <boolean>;')

# interface-interval number;
options_stmt_interface_interval = (
    Keyword('interface-interval').suppress()
    - number_type('interface_interval')
    - semicolon
)
options_stmt_interface_interval.setName('interface-interval <integer>;')

options_stmt_keep_response_order = (
        Keyword('keep-response-order').suppress()
        - Group(
            aml_nesting('')
        )('keep-response-order')
)
options_stmt_keep_response_order.setName('keep-response-order { <aml>; }')

#   listen-on [ port ip_port ] { address_match_nosemicolon }; [Opt, lwres ]
options_stmt_listen_on = (
        Keyword('listen-on').suppress()
        - Group(
            Optional(inet_ip_port_keyword_and_number_element)
            + Optional(inet_dscp_port_keyword_and_number_element)
            + Optional(inet_tls_port_keyword_and_number_element)
            + Optional(inet_http_port_keyword_and_number_element)
            - aml_nesting
        )
)('listen_on')
options_stmt_listen_on.setName(
    'listen-on [ port <port> ] [ dscp <number> ]'
    + '[ tls <string> ] [ http <string> ] { <aml>; ... };')

#   listen-on-v6 [ port ip_port ] { address_match_nosemicolon }; [ Opt ]
options_stmt_listen_on_v6 = (
        Keyword('listen-on-v6').suppress()
        - Group(
            Optional(inet_ip_port_keyword_and_number_element)
            + Optional(inet_dscp_port_keyword_and_number_element)
            + Optional(inet_tls_port_keyword_and_number_element)
            + Optional(inet_http_port_keyword_and_number_element)
            - aml_nesting
        )
)('listen_on_v6')
options_stmt_listen_on_v6.setName('listen-on-v6 [ <port> ] { <aml>; ... };')

# lock-file <path_name>; [ Opt ]    # Introduced in v9.15???
options_stmt_lock_file = (
    Keyword('lock-file').suppress()
    - dequoted_path_name('lock_file')
    + semicolon
)
options_stmt_lock_file.setName('lock-file <quoted-filespec>;')

# match-mapped-addresses ( yes | no ); [ Opt ]
options_stmt_match_mapped_addresses = (
    Keyword('match-mapped-addresses').suppress()
    - isc_boolean('match_mapped_addresses')
    + semicolon
)
options_stmt_match_mapped_addresses.setName('match-mapped-addresses <boolean>;')

# max-cache-ttl <duration>; [ Opt ]
options_stmt_max_cache_ttl = (
    Keyword('max-cache-ttl').suppress()
    - iso8601_duration('max_cache_ttl')
    + semicolon
)
options_stmt_max_cache_ttl.setName('max-cache-ttl <duration>;')

# max-clients-per-query <number>; [ Opt ]
options_stmt_max_clients_per_query = (
    Keyword('max-clients-per-query').suppress()
    - number_type('max_clients_per_query')
    + semicolon
)
options_stmt_max_cache_ttl.setName('max-clients-per-query <number>;')

# max-rsa-exponent-size bits; [ Opt ]
options_stmt_max_rsa_exponent_size = (
    Keyword('max-rsa-exponent-size').suppress()
    - number_type('max_rsa_exponent_size')
    + semicolon
)
options_stmt_max_rsa_exponent_size.setName('max-rsa-exponent-size <integer>;')

#  memstatistics <boolean>; [ Opt ]  # v9.5.0+
options_stmt_memstatistics = (
    Keyword('memstatistics').suppress()
    - isc_boolean('memstatistics')
    + semicolon
)
options_stmt_memstatistics.setName('memstatistics <boolean>;')

#  memstatistics-file <path_name>; [ Opt ]  # v8.0 to v9.1.8; now inert
options_stmt_memstatistics_file = (
    Keyword('memstatistics-file').suppress()
    - dequoted_path_name('memstatistics_file')
    + semicolon
)
options_stmt_memstatistics_file.setName('memstatistics-file <quoted-filespec>;')

#  multiple-cnames <boolean>; [ Opt ]
options_stmt_multiple_cnames = (
    Keyword('multiple-cnames').suppress()
    - isc_boolean('multiple_cnames_boolean')
    + semicolon
)
options_stmt_multiple_cnames.setName('multiple-cnames <boolean>;')

#  named-xfer <path_name>; [ Opt ]   Introduced in 8.1, still inert @ v9.10.3
options_stmt_named_xfer = (
    Keyword('named-xfer').suppress()
    - dequoted_path_name('named_xfer')
    + semicolon
)
options_stmt_named_xfer.setName('named-xfer <quoted-filespec>;')

# nocookie-udp-size <number>; [ Opt ]
options_stmt_nocookie_udp_size = (
    Keyword('nocookie-udp-size').suppress()
    - number_type('nocookie_udp_size')
    + semicolon
)
options_stmt_nocookie_udp_size.setName('nocookie-udp-size <number>;')


# pid-file "path_to_file"; [ Opt ]  # v8.1+
options_stmt_pid_file = (
    Keyword('pid-file').suppress()
    - Optional(
        Literal('none')
        | dequoted_path_name('pid_file')
    )
    + semicolon
)
options_stmt_pid_file.setName('pid-file ( <quoted-filespec> | none );')

options_stmt_port = inet_ip_port_keyword_and_number_element + semicolon

#   prefetch expiry-ttl-seconds [threshold-ttl-secs] ; [ Opt ]\
options_stmt_prefetch = (
    Keyword('prefetch').suppress()
    + Group(
        number_type('expiry_ttl')
        + Optional(
            seconds_type('threshold_ttl')
        )
    )('prefetch')
    + semicolon
)
options_stmt_prefetch.setName('prefetch <expiry-ttl> [ <threshold-ttl> ];')

#   querylog ( yes | no ); [ Opt ]
options_stmt_querylog = (
    Keyword('querylog').suppress()
    - isc_boolean('querylog_boolean')
    + semicolon
)
options_stmt_querylog.setName('querylog <boolean>;')

#   random-device "device_name" ; [ Opt ]
options_stmt_random_device = (
    Keyword('random-device').suppress()
    - (
            Literal('none')
            | dequoted_path_name('random_device')
    )
    + semicolon
)
options_stmt_random_device.setName('random-device <quoted-filespec>;')

#   recursing-file "path_to_file"; [ Opt ]  # v9.5.0+
options_stmt_recursing_file = (
    Keyword('recursing-file').suppress()
    - (
            Literal('none')
            | dequoted_path_name('recursing_file')
    )
    + semicolon
)
options_stmt_recursing_file.setName('recursing-file <quoted-filespec>;')

#   recursive-clients number; [ Opt ]
options_stmt_recursive_clients = (
    Keyword('recursive-clients').suppress()
    - number_type('recursive_clients')
    + semicolon
)
options_stmt_recursive_clients.setName('recursive-clients <integer>;')

#   reuseport <boolean>; [ Opt ]
options_stmt_reuseport = (
    Keyword('reuseport').suppress()
    - isc_boolean('reuseport')
    + semicolon
)
options_stmt_recursive_clients.setName('recursive-clients <integer>;')

#   reserved-sockets <number>; [ Opt ]
options_stmt_reserved_sockets = (
    Keyword('reserved-sockets').suppress()
    - number_type('reserved_sockets')
    + semicolon
)
options_stmt_reserved_sockets.setName('reserved-sockets  <integer>;')

#   resolver-query-timeout seconds ; [ Opt ]
options_stmt_resolver_query_timeout = (
    Keyword('resolver-query-timeout').suppress()
    - seconds_type('resolver_query_timeout')
    + semicolon
)
options_stmt_resolver_query_timeout.setName('resolver-query-timeout <seconds>;')

#  secroots-file <path_name>; [ Opt ]    # v9.5.0+
options_stmt_secroots_file = (
    Keyword('secroots-file').suppress()
    - dequoted_path_name('secroots_file')
    + semicolon
)
options_stmt_secroots_file.setName('secroots-file <quoted-filespec>;')

#     serial-query-rate number; [ Opt ]
options_stmt_serial_query_rate = (
    Keyword('serial-query-rate').suppress()
    - number_type('serial_query_rate')
    + semicolon
)
options_stmt_serial_query_rate.setName('serial-query-rate <integer>;')

#   server-id "server_id"; [ Opt ]
options_stmt_server_id_name = fqdn_name_dequotable('server_id_fqdn_name')
options_stmt_server_id_name.setName('<server_id_string>')

# Server-Id MUST be quoted
options_stmt_server_id = (
    Keyword('server-id').suppress()
    - (
        dequotable_domain_generic_fqdn
        | options_stmt_server_id_name('server_id_name')

    )('server_id_name')
    + semicolon
)
options_stmt_server_id.setName('server-id <quoted_fqdn_name>;')

options_stmt_session_keyalg = (
    Keyword('session-keyalg').suppress()
    - (
        CaselessLiteral('hmac-md5')
        | CaselessLiteral('hmac-sha1')
        | CaselessLiteral('hmac-sha128')
        | CaselessLiteral('hmac-sha224')
        | CaselessLiteral('hmac-sha256')
        | CaselessLiteral('hmac-sha384')
        | CaselessLiteral('hmac-sha512')
    )('session_keyalg')
    + semicolon
)
options_stmt_session_keyalg.setName('session-keyalg <key_algorithm_id>;')

options_stmt_session_keyname = (
    Keyword('session-keyname').suppress()
    - tsig_session_key_name('session_keyname')
    + semicolon
)
options_stmt_session_keyname.setName('session-keyname <key_id>;')

options_stmt_session_keyfile = (
    Keyword('session-keyfile').suppress()
    - dequoted_path_name('session_keyfile')
    + semicolon
)
options_stmt_session_keyfile.setName('session-keyfile <quotable_filespec>;')

#   stacksize size_in_bytes ; [ Opt ]
options_stmt_stacksize = (
    Keyword('stacksize').suppress()
    - size_spec('stacksize')
    + semicolon
)
options_stmt_stacksize.setName('stacksize <size>;')

#   startup-notify-rate <boolean>;  [ Opt ]
options_stmt_startup_notify_rate = (
    Keyword('startup-notify-rate').suppress()
    - number_type('startup_notify_rate')
    + semicolon
)
options_stmt_startup_notify_rate.setName('start-notify-rate <boolean>;')

#   statistics-file path_name; [ Opt ]  # v8.0+, inert at v9.0.0
options_stmt_statistics_file = (
    Keyword('statistics-file').suppress()
    - dequoted_path_name('statistics_file')
    + semicolon
)
options_stmt_statistics_file.setName('statistics-file <quotable_filespec>;')

# options_stmt_tcp_advertised_timeout
options_stmt_tcp_advertised_timeout = (
    Keyword('tcp-advertised-timeout').suppress()
    - number_type('tcp_advertised_timeout')
    + semicolon
)
options_stmt_tcp_advertised_timeout.setName('tcp-advertised-timeout <milliseconds>;')

#   tcp-clients number; [ Opt ]
options_stmt_tcp_clients = (
    Keyword('tcp-clients').suppress()
    - number_type('tcp_clients')
    + semicolon
)
options_stmt_tcp_clients.setName('tcp-clients <integer>;')

#   tcp-idle-timeout <number_centiseconds>; [ Opt ]
options_stmt_tcp_idle_timeout = (
    Keyword('tcp-idle-timeout').suppress()
    - number_type('tcp_idle_timeout')
    + semicolon
)
options_stmt_tcp_idle_timeout.setName('tcp-idle-timeout <integer>;')

#   tcp-initial-timeout <number_centiseconds>; [ Opt ]
options_stmt_tcp_initial_timeout = (
    Keyword('tcp-initial-timeout').suppress()
    - number_type('tcp_initial_timeout')
    + semicolon
)
options_stmt_tcp_initial_timeout.setName('tcp-initial-timeout <integer>;')

#   tcp-listen-queue number; [ Opt ]
options_stmt_tcp_listen_queue = (
    Keyword('tcp-listen-queue').suppress()
    - number_type('tcp_listen_queue')
    + semicolon
)
options_stmt_tcp_listen_queue.setName('tcp-listen-queue <integer>;')

#   tcp-keepalive-timeout <number_centiseconds>; [ Opt ]
options_stmt_tcp_keepalive_timeout = (
    Keyword('tcp-keepalive-timeout').suppress()
    - number_type('tcp_keepalive_timeout')
    + semicolon
)
options_stmt_tcp_keepalive_timeout.setName('tcp-keepalive-timeout <integer>;')

#   tcp-receive-buffer <number>; [ Opt ]
options_stmt_tcp_receive_buffer = (
    Keyword('tcp-receive-buffer').suppress()
    - number_type('tcp_receive_buffer')
    + semicolon
)
options_stmt_tcp_receive_buffer.setName('tcp-receive-buffer <integer>;')

#   tcp-send-buffer <number>; [ Opt ]
options_stmt_tcp_send_buffer = (
    Keyword('tcp-send-buffer').suppress()
    - number_type('tcp_send_buffer')
    + semicolon
)
options_stmt_tcp_send_buffer.setName('tcp-send-buffer <integer>;')

#   tkey-dhkey keyname_base key_tag; [ Opt ]
options_tkey_dhkey_tag = number_type
# options_tkey_dhkey_tag.setName('<key_tag>')  # do not do THAT!
# it overwrites number_type.setName()!!!! And confuses everyone else!

options_stmt_tkey_dhkey = (
    Keyword('tkey-dhkey').suppress()
    - Group(
        dequotable_domain_generic_fqdn('host_name')
        - options_tkey_dhkey_tag('key_tag')
    )
    + semicolon
)('tkey_dhkey')
options_stmt_tkey_dhkey.setName('tkey-dhkey <hostname> [ <key-tag> ];')

#   tkey-domain domainname; [ Opt ]
options_stmt_tkey_domain = (
    Keyword('tkey-domain').suppress()
    - dequotable_domain_generic_fqdn('tkey_domain')
    + semicolon
)
options_stmt_tkey_domain.setName('tkey-domain <fqdn>;')

#   tkey-gssapi-credential domainname; [ Opt ]
options_stmt_tkey_gssapi_credential = (
    Keyword('tkey-gssapi-credential').suppress()
    - Group(
        (
            (
                squote.suppress()
                - krb5_principal_name
                - squote.suppress()
            )
            ^ (
                dquote.suppress()
                - krb5_principal_name
                - dquote.suppress()
            )
        )
    )('tkey_gssapi_credential')
    - semicolon
)
options_stmt_tkey_gssapi_credential.setName('tkey-gssapi-credential "<principal-name/host.domain@KRB5_LABEL>";')

#  tkey-gssapi-keytab; [ Opt ]
options_stmt_tkey_gssapi_keytab = (
    Keyword('tkey-gssapi-keytab').suppress()
    - dequoted_path_name('tkey_gssapi_keytab')
    + semicolon
)
options_stmt_tkey_gssapi_keytab.setName('tkey-gssapi-keytab "<quoted-filespec>";')

#   tls-port <number>; [ Opt ]
options_stmt_tls_port = (
    Keyword('tls-port').suppress()
    - number_type('tls_port')
    + semicolon
)
options_stmt_tls_port.setName('tls-port <integer>;')

#   transfer-message-size <number>; [ Opt ]
options_stmt_transfer_message_size = (
    Keyword('transfer-message-size').suppress()
    - number_type('transfer_message_size')
    + semicolon
)
options_stmt_transfer_message_size.setName('transfer-message-size <integer>;')

#   transfers-in  number; [ Opt ]
options_stmt_transfers_in = (
    Keyword('transfers-in').suppress()
    - number_type('transfers_in')
    + semicolon
)
options_stmt_transfers_in.setName('transfers-in "<integer>";')

#   transfers-out number; [ Opt ]
options_stmt_transfers_out = (
    Keyword('transfers-out').suppress()
    - number_type('transfers_out')
    + semicolon
)

#   transfers-per-ns number; [ Opt ]
options_stmt_transfers_per_ns = (
    Keyword('transfers-per-ns').suppress()
    - number_type('transfers_per_ns')
    + semicolon
)
options_stmt_transfers_per_ns.setName('transfers-per_ns "<nanoseconds>";')

#   udp-receive-buffer <number>; [ Opt ]
options_stmt_udp_receive_buffer = (
    Keyword('udp-receive-buffer').suppress()
    - number_type('udp_receive_buffer')
    + semicolon
)
options_stmt_udp_receive_buffer.setName('udp-receive-buffer <integer>;')

#   udp-send-buffer <number>; [ Opt ]
options_stmt_udp_send_buffer = (
    Keyword('udp-send-buffer').suppress()
    - number_type('udp_send_buffer')
    + semicolon
)
options_stmt_udp_send_buffer.setName('udp-send-buffer <integer>;')

options_port_range = (
    (
        number_type('port_start')
        - number_type('port_end')
        - semicolon
    )  # no label, we are squishing dict items up-group
)

# port_range - serialized the 'range' keyword into separate logic
options_port_range_group = (
    # Match the keyword firstly otherwise fallback to numeric port numbers and its pair-thereof
    (
        Keyword('range').suppress()
        - options_port_range
    )
    ^ options_port_range
)
# options_stmt_use_v4_udp_ports
# use-v4-udp-ports { range 1024 65535; };
options_stmt_use_v4_udp_ports = (
    Keyword('use-v4-udp-ports').suppress()
    - lbrack
    - OneOrMore(
        Group(
            options_port_range_group
        )
    )
    - rbrack
    - semicolon
)('use_v4_udp_ports')
options_stmt_use_v4_udp_ports.setName('use-v4-udp-ports { range <start_port> <end_port>; };')

# options_stmt_use_v6_udp_ports
# use-v6-udp-ports { range 1024 65535; };
options_stmt_use_v6_udp_ports = (
    Keyword('use-v6-udp-ports').suppress()
    - lbrack
    - OneOrMore(
        Group(
            options_port_range_group
        )
    )
    - rbrack
    - semicolon
)('use_v6_udp_ports')
options_stmt_use_v6_udp_ports.setName('use-v6-udp-ports { range <start_port> <end_port>; };')

# version_string is latest as quoted_path_name, but it's path_name for backward compatibility
options_version_string = dequotable_path_name
options_version_string.setName('<version_string>')

#   version version_string; [ Opt ]
options_stmt_version = (
    Keyword('version').suppress()
    - options_version_string('version_string')
    + semicolon
)
options_stmt_version.setName('version <quotable-string>;')

#  Multiple-statement support  #

options_multiple_stmt_listen_on = ZeroOrMore(
    options_stmt_listen_on
)('listen_on')

options_multiple_stmt_listen_on_v6 = ZeroOrMore(
    options_stmt_listen_on_v6
)('listen_on')

options_multiple_stmt_tkey_dhkey = ZeroOrMore(
    options_stmt_tkey_dhkey
)('tkey_dhkey')

# Keywords are in dictionary-order, but with longest pattern as having been listed firstly
# This is irritating; was forced to used '^' over '|' in options_statements_set()
options_statements_set = (
    options_stmt_acache_cleaning_interval
    ^ options_stmt_acache_enable
    ^ options_stmt_answer_cookie
    ^ options_stmt_automatic_interface_scan
    ^ options_stmt_avoid_v4_udp_ports
    ^ options_stmt_avoid_v6_udp_ports
    ^ options_stmt_bindkeys_file
    ^ options_stmt_blackhole
    ^ options_stmt_clients_per_query
    ^ options_stmt_cookie_algorithm
    ^ options_stmt_cookie_secret
    ^ options_stmt_coresize
    ^ options_stmt_datasize
    ^ options_stmt_deallocate_on_exit
    ^ options_stmt_deny_answer_addresses
    ^ options_stmt_deny_answer_aliases
    ^ options_stmt_directory
    ^ options_stmt_dnstap_identity
    ^ options_stmt_dnstap_output
    ^ options_stmt_dnstap_version
    ^ options_stmt_dscp
    ^ options_stmt_dump_file
    ^ options_stmt_fake_iquery
    ^ options_stmt_flush_zones_on_shutdown
    ^ options_stmt_geoip_directory
    ^ options_stmt_has_old_clients
    ^ options_stmt_http_listener_clients
    ^ options_stmt_http_port
    ^ options_stmt_http_streams_per_connection
    ^ options_stmt_https_port
    ^ options_stmt_hostname_statistics_max
    ^ options_stmt_hostname_statistics
    ^ options_stmt_interface_interval
    ^ options_stmt_keep_response_order
    ^ options_stmt_lock_file
    ^ options_stmt_listen_on_v6
    ^ options_stmt_listen_on
    ^ options_stmt_match_mapped_addresses
    ^ options_stmt_max_cache_ttl
    ^ options_stmt_max_clients_per_query
    ^ options_stmt_max_rsa_exponent_size
    ^ options_stmt_memstatistics_file
    ^ options_stmt_memstatistics
    ^ options_stmt_multiple_cnames
    ^ options_stmt_named_xfer
    ^ options_stmt_nocookie_udp_size
    ^ options_stmt_pid_file
    ^ options_stmt_port
    ^ options_stmt_prefetch
    ^ options_stmt_querylog
    ^ options_stmt_random_device
    ^ options_stmt_recursing_file
    ^ options_stmt_recursive_clients
    ^ options_stmt_reserved_sockets
    ^ options_stmt_resolver_query_timeout
    ^ options_stmt_reuseport
    ^ options_stmt_secroots_file
    ^ options_stmt_serial_query_rate
    ^ options_stmt_server_id
    ^ options_stmt_session_keyalg
    ^ options_stmt_session_keyfile
    ^ options_stmt_session_keyname
    ^ options_stmt_stacksize
    ^ options_stmt_startup_notify_rate
    ^ options_stmt_statistics_file
    ^ options_stmt_tcp_advertised_timeout
    ^ options_stmt_tcp_clients
    ^ options_stmt_tcp_idle_timeout
    ^ options_stmt_tcp_initial_timeout
    ^ options_stmt_tcp_listen_queue
    ^ options_stmt_tcp_keepalive_timeout
    ^ options_stmt_tcp_receive_buffer
    ^ options_stmt_tcp_send_buffer
    ^ options_stmt_tkey_domain
    ^ options_stmt_tkey_gssapi_credential
    ^ options_stmt_tkey_gssapi_keytab
    ^ options_stmt_tls_port
    ^ options_stmt_transfer_message_size
    ^ options_stmt_transfers_in
    ^ options_stmt_transfers_out
    ^ options_stmt_transfers_per_ns
    ^ options_stmt_udp_receive_buffer
    ^ options_stmt_udp_send_buffer
    ^ options_stmt_use_v4_udp_ports
    ^ options_stmt_use_v6_udp_ports
    ^ options_stmt_version
    ^ options_stmt_tkey_dhkey
)

# options_statements_set = (
#    options_stmt_disable_algorithms
#    ^ options_stmt_version
#
# )
options_statements_series = (
    ZeroOrMore(
        options_statements_set
    )
)
