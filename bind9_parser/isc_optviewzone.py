#!/usr/bin/env python3.7
"""
File: isc_optviewzone.py

Clause: options, view, zone

Title: Statements Used Only By options, view, And zone Clauses

Description: isc_optviewzone covers configuration options that
             goes into 'options', 'view', AND 'zone'.
"""
from pyparsing import Group, Keyword, Optional,\
    Literal, ZeroOrMore, CaselessLiteral
from bind9_parser.isc_utils import lbrack, rbrack, semicolon, isc_boolean, path_name, \
    parse_me, seconds_type, days_type, minute_type, quoted_path_name,\
    size_spec
from bind9_parser.isc_inet import ip4_addr,\
    inet_ip_port_keyword_and_wildcard_element, ip6_addr,\
    inet_ip_port_keyword_and_number_element, ip46_addr_or_prefix,\
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

optviewzone_stmt_allow_transfer = (
    Keyword('allow-transfer').suppress()
    - Group(
        aml_nesting
    )('allow_transfer')
)

optviewzone_stmt_allow_transfer_on = (
    Keyword('allow-transfer-on').suppress()
    - Group(
        aml_nesting
    )('allow_transfer_on')
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
)('')

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

optviewzone_stmt_dialup = (
    Keyword('dialup')
    - isc_boolean('dialup')
    + semicolon
)

optviewzone_stmt_dnssec_loadkeys_interval = (
    Keyword('dnssec-loadkeys-interval').suppress()
    + minute_type('dnssec_loadkeys_interval')
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
    ip46_addr_or_prefix('addr')
    + Optional(inet_ip_port_keyword_and_number_element)
    + Optional(inet_dscp_port_keyword_and_number_element)
    + semicolon
)

forwarders_ip46_addr_prefix_port_series = (
    ZeroOrMore(
        Group(
            forwarders_ip46_addr_prefix_port_element
        )
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
        + Optional(inet_dscp_port_keyword_and_number_element)
        + lbrack
        + (
            (
                (
                    forwarders_ip46_addr_prefix_port_series
                )('')
            )('fwdr3')
        )('fwdr2')
        + rbrack
        + semicolon
    )('')
)('fowarders')

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

# ixfr-tmp-file <path_name:; [ Opt View Zone ]  #  v8.0 to v8.4; now inert
optviewzone_stmt_ixfr_tmp_file = (
    Keyword('ixfr-tmp-file').suppress()
    + path_name('ixfr_tmp_file')
    + semicolon
)

# key-directory path_name; [ Opt View Zone]
optviewzone_stmt_key_directory = (
    Keyword('key-directory').suppress()
    - quoted_path_name('key_directory')
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
            | Literal('map')
    )('masterfile_format')
    + semicolon
)

#   max-journal-size size_in_bytes; [ Opt, View, Zone ]
optviewzone_stmt_max_journal_size = (
    Keyword('max-journal-size').suppress()
    - size_spec('max_journal_size')
    + semicolon
)

#   max-refresh-time seconds ; [ Opt, View, Zone ]
optviewzone_stmt_max_refresh_time = (
    Keyword('max-refresh-time').suppress()
    - seconds_type('max_refresh_time')
    + semicolon
)

#   max-retry-time seconds ; [ Opt, View, Zone ]
optviewzone_stmt_max_retry_time = (
    Keyword('max-retry-time').suppress()
    - seconds_type('max_retry_time')
    + semicolon
)

#   max-transfer-idle-in minutes; [ Opt, View, Zone ]
optviewzone_stmt_max_transfer_idle_in = (
    Keyword('max-transfer-idle-in').suppress()
    - seconds_type('max_transfer_idle_in')
    + semicolon
)

#   max-transfer-idle-out minutes; [ Opt, View, Zone ]
optviewzone_stmt_max_transfer_idle_out = (
    Keyword('max-transfer-idle-out').suppress()
    - seconds_type('max_transfer_idle_out')
    + semicolon
)

#   max-transfer-time-in minutes; [ Opt, View, Zone ]
optviewzone_stmt_max_transfer_time_in = (
    Keyword('max-transfer-time-in').suppress()
    - seconds_type('max_transfer_time_in')
    + semicolon
)

#   max-transfer-time-out minutes; [ Opt, View, Zone ]
optviewzone_stmt_max_transfer_time_out = (
    Keyword('max-transfer-time-out').suppress()
    - seconds_type('max_transfer_time_out')
    + semicolon
)

#   min-refresh-time seconds ; [ Opt, View, Zone ]
optviewzone_stmt_min_refresh_time = (
    Keyword('min-refresh-time').suppress()
    - seconds_type('min_refresh_time')
    + semicolon
)

#   min-retry-time seconds ; [ Opt, View, Zone ]
optviewzone_stmt_min_retry_time = (
    Keyword('min-retry-time').suppress()
    - seconds_type('min_retry_time')
    + semicolon
)

#   multi-master ( yes | no ) ; [ Opt, View, Zone ]
optviewzone_stmt_multi_master = (
    Keyword('multi-master').suppress()
    - isc_boolean('multi_master')
    + semicolon
)

#   notify ( yes | no | explicit | master-only ); [ Opt, View, Zone ]
#  'master-only' is a seen in 9.9.7, not in 9.0
optviewzone_stmt_notify = (
    Keyword('notify').suppress()
    + (
            isc_boolean
            | Literal('explicit')
            | Literal('master-only')
    )('notify')
    + semicolon
)

#  notify-source (ip4_addr | *) [port ip_port] ;
optviewzone_stmt_notify_source = (
    Keyword('notify-source').suppress()
    - Group(
        ip4_addr_or_wildcard('addr')
        + Optional(inet_ip_port_keyword_and_wildcard_element)
        + Optional(inet_dscp_port_keyword_and_number_element)
    )('notify_source')
    + semicolon
)

#  notify-source-v6 (ip4_addr | *) [port ip_port] ;
optviewzone_stmt_notify_source_v6 = (
    Keyword('notify-source-v6').suppress()
    - Group(
        ip6_addr_or_wildcard('addr')
        + Optional(inet_ip_port_keyword_and_wildcard_element)
        + Optional(inet_dscp_port_keyword_and_number_element)
    )('notify_source_v6')
    + semicolon
)

#   provide-ixfr ( yes | no) ; [ Opt, View, server ]
optviewzone_stmt_provide_ixfr = (
    Keyword('provide-ixfr').suppress()
    - isc_boolean('provide_ixfr')
    + semicolon
)

#   request-ixfr ( yes | no ); [ Opt, View, server ]
optviewzone_stmt_request_ixfr = (
    Keyword('request-ixfr').suppress()
    - isc_boolean('request_ixfr')
    + semicolon
)

#  request-nsid <boolean>; [ Opt, View, server ]
optviewzone_stmt_request_nsid = (
   Keyword('request-nsid').suppress()
   + isc_boolean('request_nsid')
   + semicolon
)

#   sig-validity-interval number ; [ Opt, View, Zone ]
optviewzone_stmt_sig_validity_interval = (
    Keyword('sig-validity-interval').suppress()
    - days_type('sig_validity_interval')
    + semicolon
)

#   transfer-format ( one-answer | many-answers ); [ Opt, View, server ]
optviewzone_stmt_transfer_format = (
    Keyword('transfer-format').suppress()
    + (
        Literal('one-answer')
        | Literal('many-answers')
    )('transfer_format')
    + semicolon
)

#  transfer-source (ip4_addr | *) [port ip_port] ; ]
optviewzone_stmt_transfer_source = (
    Keyword('transfer-source').suppress()
    + Group(
        ip4_addr_or_wildcard('addr')
        + Optional(inet_ip_port_keyword_and_wildcard_element)
        + Optional(inet_dscp_port_keyword_and_number_element)
    )('transfer_source')
    + semicolon
)

#  transfer-source (ip6_addr | *) [port ip_port] ; ]
optviewzone_stmt_transfer_source_v6 = (
    Keyword('transfer-source-v6').suppress()
    - Group(
        ip6_addr_or_wildcard('addr')
        - Optional(inet_ip_port_keyword_and_wildcard_element)
        - Optional(inet_dscp_port_keyword_and_number_element)
    )('transfer_source_v6')
    + semicolon
)

#  use-alt-transfer-source yes | no;
optviewzone_stmt_use_alt_transfer_source = (
    Keyword('use-alt-transfer-source').suppress()
    + isc_boolean('use_alt_transfer_source')
    + semicolon
)

optviewzone_stmt_zone_statistics = (
    Keyword('zone-statistics').suppress()
    + isc_boolean('zone_statistics')
    + semicolon
)

#  Ordering matters, I tried to keep them in dictionary order, but
#  with longest pattern firstly.
#  Keywords are in dictionary-order, but with longest pattern as
#  having been listed firstly
optviewzone_statements_set = (
        optviewzone_stmt_allow_notify
        | optviewzone_stmt_allow_query_on
        | optviewzone_stmt_allow_query
        | optviewzone_stmt_allow_transfer_on
        | optviewzone_stmt_allow_transfer
        | optviewzone_stmt_allow_update_forwarding
        | optviewzone_stmt_allow_update_on
        | optviewzone_stmt_allow_update
        | optviewzone_stmt_allow_v6_synthesis
        | optviewzone_stmt_alt_transfer_source_v6
        | optviewzone_stmt_alt_transfer_source
        | optviewzone_stmt_auto_dnssec
        | optviewzone_stmt_dialup
        | optviewzone_stmt_dnssec_loadkeys_interval
        | optviewzone_stmt_forwarders
        | optviewzone_stmt_forward
        | optviewzone_stmt_ixfr_from_differences
        | optviewzone_stmt_ixfr_tmp_file
        | optviewzone_stmt_key_directory
        | optviewzone_stmt_maintain_ixfr_base
        | optviewzone_stmt_masterfile_format
        | optviewzone_stmt_max_journal_size
        | optviewzone_stmt_max_refresh_time
        | optviewzone_stmt_max_retry_time
        | optviewzone_stmt_max_transfer_idle_in
        | optviewzone_stmt_max_transfer_idle_out
        | optviewzone_stmt_max_transfer_time_in
        | optviewzone_stmt_max_transfer_time_out
        | optviewzone_stmt_min_refresh_time
        | optviewzone_stmt_min_retry_time
        | optviewzone_stmt_multi_master
        | optviewzone_stmt_notify_source_v6
        | optviewzone_stmt_notify_source
        | optviewzone_stmt_notify
        | optviewzone_stmt_provide_ixfr
        | optviewzone_stmt_request_ixfr
        | optviewzone_stmt_request_nsid
        | optviewzone_stmt_sig_validity_interval  # BUG works here?
        | optviewzone_stmt_transfer_format
        | optviewzone_stmt_transfer_source_v6
        | optviewzone_stmt_transfer_source
        | optviewzone_stmt_use_alt_transfer_source
        | optviewzone_stmt_zone_statistics
)

# No need to keep the ordering of statements, stick in a dictionarized Dict {}
optviewzone_statements_series = (
    ZeroOrMore(
        (
            optviewzone_statements_set
        )('')
    )('')
)
