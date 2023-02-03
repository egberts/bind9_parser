#!/usr/bin/env python3
"""
File: isc_optviewzone.py

Clause: options, view, zone

Title: Statements Used Only By options, view, And zone Clauses

Description: isc_optviewzone covers configuration options that
             goes into 'options', 'view', AND 'zone'.
"""
from pyparsing import Group, Keyword, Optional, \
    Literal, ZeroOrMore, CaselessLiteral, ungroup
from bind9_parser.isc_utils import lbrack, rbrack, semicolon, isc_boolean, \
    seconds_type, days_type, minute_type, dequoted_path_name, \
    size_spec, name_base, fqdn_name, check_options, number_type, iso8601_duration, \
    percentage_type
from bind9_parser.isc_inet import ip4_addr, ip_port, \
    inet_ip_port_keyword_and_wildcard_element, ip6_addr, \
    inet_ip_port_keyword_and_number_element, ip46_addr_or_prefix, \
    ip4_addr_or_wildcard, ip6_addr_or_wildcard, inet_dscp_port_keyword_and_number_element
from bind9_parser.isc_aml import aml_nesting


optviewzone_stmt_allow_notify = (
    Keyword('allow-notify').suppress()
    - Group(
        aml_nesting
    )('allow_notify')
)

optviewzone_stmt_allow_query = (
    Keyword('allow-query').suppress()
    - Group(
        aml_nesting
    )('allow_query')
)

optviewzone_stmt_allow_query_on = (
    Keyword('allow-query-on').suppress()
    - Group(
        aml_nesting
    )('allow_query_on')
)

optviewzone_stmt_allow_transfer_optionals = (
    (
        Keyword('port').suppress()
        - ip_port
    )
    | (
        Keyword('transport').suppress()
        - fqdn_name
    )
)

optviewzone_stmt_allow_transfer = (
    Keyword('allow-transfer').suppress()
    - Group(
        ZeroOrMore(optviewzone_stmt_allow_transfer_optionals)
        - aml_nesting
    )('allow_transfer')
)

optviewzone_stmt_allow_update = (
    Keyword('allow-update').suppress()
    - Group(
        aml_nesting
    )('allow_update')
)

optviewzone_stmt_allow_update_on = (
    Keyword('allow-update-on').suppress()
    - Group(
        aml_nesting
    )('allow_update_on')
)

optviewzone_stmt_allow_update_forwarding = (
    Keyword('allow-update-forwarding').suppress()
    - Group(
        aml_nesting
    )('allow_update_forwarding')
)

optviewzone_stmt_allow_v6_synthesis = (
    Keyword('allow-v6-synthesis').suppress()
    - Group(
        aml_nesting
    )('allow_v6_synthesis')
)

#  alt-transfer-source ( ipv4_address | * ) [ port ( integer | * )];
optviewzone_stmt_alt_transfer_source = (
    Keyword('alt-transfer-source').suppress()
    - Group(
        (
            (
                ip4_addr('ip4_addr')
                | Literal('*')
            )('')
            + Optional(inet_ip_port_keyword_and_wildcard_element)
            + Optional(inet_dscp_port_keyword_and_number_element)
        )('')
    )('alt_transfer_source')
    + semicolon
)('')

#  alt-transfer-source-v6 ( ipv4_address | * ) [ port ( integer | * )];
optviewzone_stmt_alt_transfer_source_v6 = (
    Keyword('alt-transfer-source-v6').suppress()
    - Group(
        (
            (
                ip6_addr('ip6_addr')
                | Literal('*')
            )
            + Optional(inet_ip_port_keyword_and_wildcard_element)
            + Optional(inet_dscp_port_keyword_and_number_element)
        )('')
    )('alt_transfer_source_v6')
    + semicolon
)

optviewzone_stmt_auto_dnssec = (
    Keyword('auto-dnssec').suppress()
    + (
        (
            CaselessLiteral('allow')
            | CaselessLiteral('maintain')
            | CaselessLiteral('off')
        )
    )('auto_dnssec')
    + semicolon
)

optviewzone_stmt_check_sibling = (
        Keyword('check-sibling').suppress()
        + check_options('check_sibling')
        + semicolon
).setName('check-sibling ( warn | fail | ignore );')  # [ Opt View Zone ] v9.4+

optviewzone_stmt_dialup = (
    Keyword('dialup').suppress()
    - (
        Literal('notify-passive')
        | Literal('notify')
        | Literal('no')
        | Literal('yes')
        | Literal('passive')
        | Literal('refresh')
    )('dialup')
    + semicolon
).setName('dialup [ notify | notify-passive | passive | refresh | yes | no ];')

# range (1, 3660 <10-year>)
optviewzone_stmt_dnskey_sig_validity = (
        Keyword('dnskey-sig-validity')
        - days_type('dnskey_sig_validity')
        + semicolon
)

optviewzone_stmt_dnssec_dnskey_kskonly = (
    Keyword('dnssec-dnskey-kskonly')
    - name_base('dnssec_dnskey_kskonly')
    + semicolon
)

optviewzone_stmt_dnssec_policy = (
        Keyword('dnssec-policy')
        - name_base('dnssec_policy')
        + semicolon
)

optviewzone_stmt_dnssec_loadkeys_interval = (
    Keyword('dnssec-loadkeys-interval').suppress()
    + minute_type('dnssec_loadkeys_interval')
    + semicolon
)

optviewzone_stmt_dnssec_secure_to_insecure = (
    Keyword('dnssec-secure-to-insecure')
    - isc_boolean('dnssec_secure_to_insecure')
    + semicolon
)

optviewzone_stmt_dnssec_update_mode = (
    Keyword('dnssec-update-mode')
    - (
            Literal('maintain')
            | Literal('no-resign')
    )('dnssec_update_mode')
    + semicolon
)

# forward ( only | first ); [ Opt View Zone ]  # v8.1+
optviewzone_stmt_forward = (
    Keyword('forward').suppress()
    + (
        Literal('only')
        | Literal('first')
    )('forward')
    + semicolon
)

forwarders_ip46_addr_prefix_port_element = (
    ungroup(ip46_addr_or_prefix)('ip_addr')   # .setName() must be same as ip46_addr
    - Optional(inet_ip_port_keyword_and_number_element)
    - Optional(inet_dscp_port_keyword_and_number_element)
    + semicolon
)

forwarders_ip46_addr_prefix_port_series = (
    ZeroOrMore(
        Group(
            forwarders_ip46_addr_prefix_port_element
        )('forwarder*')
    )
)

#  forwarders {
#      ip46_addr_or_prefix [port ip_port] ; [ ... ]
#  }; [ Opt View Zone ]  # v4.8+
#  forwarders { 10.2.3.4; 192.168.2.5; };
optviewzone_stmt_forwarders = (
    Keyword('forwarders').suppress()
    + Group(
        Optional(inet_ip_port_keyword_and_number_element)
        - Optional(inet_dscp_port_keyword_and_number_element)
        + lbrack
        - forwarders_ip46_addr_prefix_port_series('')
        + rbrack
        + semicolon
    )('forwarders')
)

# ixfr-from-differences ( master | slave | <boolean> );
optviewzone_stmt_ixfr_from_differences = (
    Keyword('ixfr-from-differences').suppress()
    + (
            Literal('master')
            | Literal('primary')
            | Literal('slave')
            | Literal('secondary')
            | isc_boolean
    )('ixfr_from_differences')
    + semicolon
)

# ixfr-tmp-file "<path_name>"; [ Opt View Zone ]  #  v8.0 to v8.4; now inert
optviewzone_stmt_ixfr_tmp_file = (
    Keyword('ixfr-tmp-file').suppress()
    + dequoted_path_name('ixfr_tmp_file')
    + semicolon
).setName('ixfr-tmp-file <quoted_file_path>')

# key-directory "<path_name>"; [ Opt View Zone]
optviewzone_stmt_key_directory = (
    Keyword('key-directory').suppress()
    - dequoted_path_name('key_directory')
    + semicolon
)

#  maintain-ixfr-base <boolean>; [ Opt View Zone ]  # v8.2- v9.7.0; still inert
optviewzone_stmt_maintain_ixfr_base = (
    Keyword('maintain-ixfr-base').suppress()
    - isc_boolean('maintain_ixfr_base')
    + semicolon
)

# masterfile-format text | raw | map;
# masterfile-format map;
optviewzone_stmt_masterfile_format = (
    Keyword('masterfile-format').suppress()
    + (
            Literal('text')
            | Literal('raw')
            | Literal('map')  # removed in v9.19
    )('masterfile_format')
    + semicolon
).setName('masterfile-format ( text | raw );')

# masterfile-style ( full | relative );
optviewzone_stmt_masterfile_style = (
    Keyword('masterfile-style').suppress()
    + (
            Literal('full')
            | Literal('relative')
    )('masterfile_style')
    + semicolon
).setName('masterfile-style ( full | relative );')

optviewzone_stmt_max_ixfr_ratio = (
    Keyword('max-ixfr-ratio').suppress()
    + (
            ungroup(percentage_type)('max-ixfr-ratio')
            | Literal('unlimited')('max-ixfr-ratio')
    )
    + semicolon
).setName('max-ixfr-ratio ( unlimited | <percentage>% );')

#   max-journal-size size_in_bytes; [ Opt, View, Zone ]
optviewzone_stmt_max_journal_size = (
    Keyword('max-journal-size').suppress()
    - size_spec('max_journal_size')
    + semicolon
).setName('max-journal-size <size_spec>;')

#   max-records <integer>; [ Opt, View, Zone ]
optviewzone_stmt_max_records = (
    Keyword('max-records').suppress()
    - number_type('max_records')
    + semicolon
).setName('max-records <integer>;')

#   max-refresh-time seconds ; [ Opt, View, Zone ]
optviewzone_stmt_max_refresh_time = (
    Keyword('max-refresh-time').suppress()
    - seconds_type('max_refresh_time')
    + semicolon
).setName('max-refresh-time <seconds>;')

#   max-retry-time seconds ; [ Opt, View, Zone ]
optviewzone_stmt_max_retry_time = (
    Keyword('max-retry-time').suppress()
    - seconds_type('max_retry_time')
    + semicolon
).setName('max-retry-time <seconds>;')

#   max-transfer-idle-in minutes; [ Opt, View, Zone ]
optviewzone_stmt_max_transfer_idle_in = (
    Keyword('max-transfer-idle-in').suppress()
    - seconds_type('max_transfer_idle_in')
    + semicolon
).setName('max-transfer-idle-in <seconds>;')

#   max-transfer-idle-out minutes; [ Opt, View, Zone ]
optviewzone_stmt_max_transfer_idle_out = (
    Keyword('max-transfer-idle-out').suppress()
    - seconds_type('max_transfer_idle_out')
    + semicolon
).setName('max-transfer-idle-out <seconds>;')

#   max-transfer-time-in minutes; [ Opt, View, Zone ]
optviewzone_stmt_max_transfer_time_in = (
    Keyword('max-transfer-time-in').suppress()
    - seconds_type('max_transfer_time_in')
    + semicolon
).setName('max-transfer-time-in <seconds>;')

#   max-transfer-time-out minutes; [ Opt, View, Zone ]
optviewzone_stmt_max_transfer_time_out = (
    Keyword('max-transfer-time-out').suppress()
    - seconds_type('max_transfer_time_out')
    + semicolon
).setName('max-transfer-time-out <seconds>;')

#   min-refresh-time seconds ; [ Opt, View, Zone ]
optviewzone_stmt_min_refresh_time = (
    Keyword('min-refresh-time').suppress()
    - iso8601_duration('min_refresh_time')
    + semicolon
).setName('min-refresh-time <iso8601_duration>;')

#   min-retry-time seconds ; [ Opt, View, Zone ]
optviewzone_stmt_min_retry_time = (
    Keyword('min-retry-time').suppress()
    - seconds_type('min_retry_time')
    - semicolon
).setName('min-retry-time <seconds>;')

#   multi-master ( yes | no ) ; [ Opt, View, Zone ]
optviewzone_stmt_multi_master = (
    Keyword('multi-master').suppress()
    - isc_boolean('multi_master')
    + semicolon
).setName('multi-master <boolean>;')

# notify ( explicit | master-only | primary-only | <boolean> );
optviewzone_stmt_notify = (
    Keyword('notify').suppress()
    - ungroup(
        Group(
            isc_boolean('notify')
            | Keyword('explicit')
            | Keyword('primary-only')
            | Keyword('master-only')
        )
    )('notify')
    + semicolon
).setName('notify ( <boolean> | explicit | primary-only );')

#   notify-delay 0; [ Opt, View, Zone ]
optviewzone_stmt_notify_delay = (
    Keyword('notify-delay').suppress()
    - seconds_type('notify_delay')
    + semicolon
).setName('notify-delay <seconds>;')

#  notify-source (ip4_addr | *) [port ip_port] ;
optviewzone_stmt_notify_source = (
    Keyword('notify-source').suppress()
    - Group(
        ip4_addr_or_wildcard('ip4_addr-w')
        + Optional(ungroup(inet_ip_port_keyword_and_wildcard_element))('ip4_port_w')
        + Optional(ungroup(inet_dscp_port_keyword_and_number_element))('dscp_port')
    )('notify_source')
    + semicolon
).setName('notify-source ( <ip4_addr> | * ) [ port ( <port_no> | * ) ] [ dscp <dscp_port> ];')

#  notify-source-v6 (ip4_addr | *) [port ip_port] ;
optviewzone_stmt_notify_source_v6 = (
    Keyword('notify-source-v6').suppress()
    - Group(
        ip6_addr_or_wildcard('ip6_addr')
        + Optional(inet_ip_port_keyword_and_wildcard_element)
        + Optional(inet_dscp_port_keyword_and_number_element)
    )('notify_source_v6')
    + semicolon
).setName('notify-source-v6 ( <ip6_addr> | * ) [ port ( <port_no> | * ) ] [ dscp <dscp_port> ];')

#   provide-ixfr ( yes | no) ; [ Opt, View, server ]
optviewzone_stmt_provide_ixfr = (
    Keyword('provide-ixfr').suppress()
    - isc_boolean('provide_ixfr')
    + semicolon
).setName('provide-ixfr <boolean>;')

#   request-ixfr ( yes | no ); [ Opt, View, server ]
optviewzone_stmt_request_ixfr = (
    Keyword('request-ixfr').suppress()
    - isc_boolean('request_ixfr')
    + semicolon
).setName('request-ixfr <boolean>;')

#  request-nsid <boolean>; [ Opt, View, server ]
optviewzone_stmt_request_nsid = (
    Keyword('request-nsid').suppress()
    + isc_boolean('request_nsid')
    + semicolon
).setName('request-nsid <boolean>;')

# optviewzone_stmt_serial_update_method
optviewzone_stmt_serial_update_method = (
    Keyword('serial-update-method')
    - (
        Keyword('unixtime')
        | Keyword('date')
        | Keyword('increment')
    )('serial_update_method')
    - semicolon
).setName('serial-update-method ( increment | unixtime | date )')

# optviewzone_stmt_sig_signing_nodes
optviewzone_stmt_sig_signing_nodes = (
    Keyword('sig-signing-nodes').suppress()
    - seconds_type('sig_signing_nodes')
    + semicolon
).setName('sig-signing-node <seconds>;')

# optviewzone_stmt_sig_signing_signatures
optviewzone_stmt_sig_signing_signatures = (
    Keyword('sig-signing-signatures').suppress()
    - seconds_type('sig_signing_signatures')
    + semicolon
).setName('sig-signing-signatures <seconds>;')

# optviewzone_stmt_sig_signing_type
optviewzone_stmt_sig_signing_type = (
    Keyword('sig-signing-type').suppress()
    - seconds_type('sig_signing_type')
    + semicolon
).setName('sig-signing-type <seconds>;')

#   sig-validity-interval number ; [ Opt, View, Zone ]
optviewzone_stmt_sig_validity_interval = (
    Keyword('sig-validity-interval').suppress()
    - days_type('sig_validity_interval')
    + semicolon
).setName('sig-validity-interval <days>;')

#   transfer-format ( one-answer | many-answers ); [ Opt, View, server ]
optviewzone_stmt_transfer_format = (
    Keyword('transfer-format').suppress()
    + (
        Literal('one-answer')
        | Literal('many-answers')
    )('transfer_format')
    + semicolon
).setName('transfer-format ( many-answers | one-answer )')

#  transfer-source (ip4_addr | *) [port ip_port] ; ]
optviewzone_stmt_transfer_source = (
    Keyword('transfer-source').suppress()
    + Group(
        ip4_addr_or_wildcard('ip4_addr')
        + Optional(inet_ip_port_keyword_and_wildcard_element)
        + Optional(inet_dscp_port_keyword_and_number_element)
    )('transfer_source')
    + semicolon
).setName('transfer-source ( <ip4_addr> | * ) [ port ( <port_no> | * ) ] [ dscp <dscp_port> ];')

#  transfer-source (ip6_addr | *) [port ip_port] ; ]
optviewzone_stmt_transfer_source_v6 = (
    Keyword('transfer-source-v6').suppress()
    - Group(
        ip6_addr_or_wildcard('ip6_addr')
        - Optional(inet_ip_port_keyword_and_wildcard_element)
        - Optional(inet_dscp_port_keyword_and_number_element)
    )('transfer_source_v6')
    + semicolon
).setName('transfer-source-v6 ( <ip6_addr> | * ) [ port ( <port_no> | * ) ] [ dscp <dscp_port> ];')

# optviewzone_stmt_try_tcp_refresh
optviewzone_stmt_try_tcp_refresh = (
        Keyword('try-tcp-refresh').suppress()
        + isc_boolean('try_tcp_refresh')
        + semicolon
).setName('try-tcp-refresh <boolean>;')

# optviewzone_stmt_update_check_ksk
optviewzone_stmt_update_check_ksk = (
        Keyword('update-check-ksk').suppress()
        + isc_boolean('update_check_ksk')
        + semicolon
).setName('update-check-ksk <boolean>;')

#  use-alt-transfer-source yes | no;
optviewzone_stmt_use_alt_transfer_source = (
    Keyword('use-alt-transfer-source').suppress()
    + isc_boolean('use_alt_transfer_source')
    + semicolon
).setName('use-alt-transfer-source <boolean>;')

# optviewzone_stmt_zero_no_soa_ttl
optviewzone_stmt_zero_no_soa_ttl = (
        Keyword('zero-no-soa-ttl').suppress()
        + isc_boolean('zero_no_soa_ttl')
        + semicolon
).setName('zero-no-soa-ttl <boolean>;')

optviewzone_stmt_zone_statistics = (
    Keyword('zone-statistics').suppress()
    - (
        CaselessLiteral('terse')
        | CaselessLiteral('full')
        | CaselessLiteral('none')
        | isc_boolean
    )('zone_statistics')
    + semicolon
).setName('zone-statistics <boolean>;')

#  Ordering matters, I tried to keep them in dictionary order, but
#  with longest pattern firstly.
#  Keywords are in dictionary-order, but with longest pattern as
#  having been listed firstly
optviewzone_statements_set = (
        optviewzone_stmt_allow_notify
        ^ optviewzone_stmt_allow_query_on
        ^ optviewzone_stmt_allow_query
        ^ optviewzone_stmt_allow_transfer
        ^ optviewzone_stmt_allow_update_forwarding
        ^ optviewzone_stmt_allow_update_on
        ^ optviewzone_stmt_allow_update
        ^ optviewzone_stmt_allow_v6_synthesis
        ^ optviewzone_stmt_alt_transfer_source_v6
        ^ optviewzone_stmt_alt_transfer_source
        ^ optviewzone_stmt_auto_dnssec
        ^ optviewzone_stmt_check_sibling
        ^ optviewzone_stmt_dialup
        ^ optviewzone_stmt_dnskey_sig_validity
        ^ optviewzone_stmt_dnssec_dnskey_kskonly
        ^ optviewzone_stmt_dnssec_loadkeys_interval
        ^ optviewzone_stmt_dnssec_policy
        ^ optviewzone_stmt_dnssec_secure_to_insecure
        ^ optviewzone_stmt_dnssec_update_mode
        ^ optviewzone_stmt_forwarders
        ^ optviewzone_stmt_forward
        ^ optviewzone_stmt_ixfr_from_differences
        ^ optviewzone_stmt_ixfr_tmp_file
        ^ optviewzone_stmt_key_directory
        ^ optviewzone_stmt_maintain_ixfr_base
        ^ optviewzone_stmt_masterfile_format
        ^ optviewzone_stmt_masterfile_style
        ^ optviewzone_stmt_max_ixfr_ratio
        ^ optviewzone_stmt_max_journal_size
        ^ optviewzone_stmt_max_records
        ^ optviewzone_stmt_max_refresh_time
        ^ optviewzone_stmt_max_retry_time
        ^ optviewzone_stmt_max_transfer_idle_in
        ^ optviewzone_stmt_max_transfer_idle_out
        ^ optviewzone_stmt_max_transfer_time_in
        ^ optviewzone_stmt_max_transfer_time_out
        ^ optviewzone_stmt_min_refresh_time
        ^ optviewzone_stmt_min_retry_time
        ^ optviewzone_stmt_multi_master
        ^ optviewzone_stmt_notify  # gone from 'zone' in v9.18
        ^ optviewzone_stmt_notify_delay
        ^ optviewzone_stmt_notify_source_v6
        ^ optviewzone_stmt_notify_source
        ^ optviewzone_stmt_provide_ixfr
        ^ optviewzone_stmt_request_ixfr
        ^ optviewzone_stmt_request_nsid
        ^ optviewzone_stmt_serial_update_method
        ^ optviewzone_stmt_sig_signing_nodes
        ^ optviewzone_stmt_sig_signing_signatures
        ^ optviewzone_stmt_sig_signing_type
        ^ optviewzone_stmt_sig_validity_interval
        ^ optviewzone_stmt_transfer_format
        ^ optviewzone_stmt_transfer_source_v6
        ^ optviewzone_stmt_transfer_source
        ^ optviewzone_stmt_use_alt_transfer_source
        ^ optviewzone_stmt_try_tcp_refresh
        ^ optviewzone_stmt_update_check_ksk
        ^ optviewzone_stmt_zero_no_soa_ttl
        ^ optviewzone_stmt_zone_statistics
)

# No need to keep the ordering of statements, stick in a dictionarized Dict {}
optviewzone_statements_series = (
    ZeroOrMore(
            optviewzone_statements_set
    )
)
