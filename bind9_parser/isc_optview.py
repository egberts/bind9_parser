#!/usr/bin/env python3.7
"""
File: isc_optview.py

Clause: options, view

Title: Statements Used Only By options And view Clauses

Description: isc_optview contains all parse elements pertaining
             to both options and view (but not zones)

"""
from pyparsing import Group, Keyword, OneOrMore, Literal, \
    CaselessLiteral, Combine, Optional, Word, alphanums, ZeroOrMore,\
    ungroup
from bind9_parser.isc_utils import isc_boolean, semicolon, lbrack, rbrack, \
    squote, dquote, number_type, name_type, minute_type, seconds_type, \
    byte_type, run_me, dequoted_path_name, check_options, \
    size_spec, exclamation, iso8601_duration, view_name, \
    algorithm_name, fqdn_name_dequoted, fqdn_name_dequotable,\
    algorithm_name_list_series, charset_filename_base, size_spec_nodefault, size_spec_plain,\
    fixedpoint_type
from bind9_parser.isc_aml import aml_nesting, aml_choices
from bind9_parser.isc_inet import ip4_addr, ip6_addr, ip6s_prefix, \
    ip6_optional_prefix, ip4_addr_or_wildcard, ip6_addr_or_wildcard, \
    inet_ip_port_keyword_and_number_element, \
    inet_ip_port_keyword_and_wildcard_element, dscp_port
from bind9_parser.isc_utils import dequotable_zone_name
from bind9_parser.isc_domain import quoted_domain_generic_fqdn, \
    domain_generic_fqdn, rr_fqdn_w_absolute, rr_domain_name_type, quotable_domain_generic_fqdn, \
    soa_rname, dequotable_domain_generic_fqdn, dequoted_domain_generic_fqdn

optview_stmt_acache_cleaning_interval = (
    Keyword('acache-cleaning-interval').suppress()
    - isc_boolean('acache_cleaning_interval')
    + semicolon
).setName('acache-cleaning-interval <boolean>')

optview_stmt_acache_enable = (
    Keyword('acache-enable').suppress()
    - isc_boolean('acache_enable')
    + semicolon
).setName('acache-enable <boolean>;')

optview_stmt_additional_from_auth = (
    Keyword('additional-from-auth').suppress()
    - isc_boolean('additional_from_auth')
    + semicolon
).setName('additional-from-auth <boolean>;')

optview_stmt_additional_from_cache = (
    Keyword('additional-from-cache').suppress()
    - isc_boolean('additional_from_cache')
    + semicolon
)
optview_stmt_additional_from_cache.setName('additional-from-cache <boolean>;')

# allow-new-zones <boolean>; [ Opt View ]  # v9.5.0+
optview_stmt_allow_new_zones = (
    Keyword('allow-new-zones').suppress()
    - isc_boolean('allow_new_zones')
    + semicolon
).setName('allow-new-zones <boolean>;')

optview_stmt_allow_query_cache = (
        Keyword('allow-query-cache').suppress()
        - Group(
    aml_nesting('')
)('allow_query_cache')
).setName('allow-query-cache <aml>;')

optview_stmt_allow_query_cache_on = (
    Keyword('allow-query-cache-on').suppress()
    - Group(
        aml_nesting('')
    )('allow_query_cache_on')
).setName('allow-query-cache-on <boolean>;')

optview_stmt_allow_recursion = (
    Keyword('allow-recursion').suppress()
    - Group(
        aml_nesting('')
    )('allow-recursion')
).setName('allow-recursion <aml>;')

optview_stmt_allow_recursion_on = (
    Keyword('allow-recursion-on').suppress()
    - Group(
        aml_nesting('')
    )('allow-recursion-on')
).setName('allow-recursion-on <aml>;')

optview_attach_cache_name = name_type  # TODO: Identify when it got obsoleted???
optview_attach_cache_name.setName('<cache_name>')
optview_stmt_attach_cache = (
    Keyword('attach-cache').suppress()
    - view_name('attach_cache')
    + semicolon
).setName('attach-cache <view_name>;')

# [auth-nxdomain yes | no;]
optview_stmt_auth_nxdomain = (
    Keyword('auth-nxdomain').suppress()
    - isc_boolean('auth_nxdomain')
    + semicolon
).setName('auth-nxdomain <boolean>;')

#  cache-file <path_name>  # [ Opt View ]
#    (moved from isc_options.py sometime in v9.8?)
optview_stmt_cache_file = (
    Keyword('cache-file').suppress()
    - dequoted_path_name('cache_file')
    + semicolon
).setName('cache-file <quoted-path_name>;')

optview_stmt_check_dup_records = (
    Keyword('check-dup-records').suppress()
    - check_options('check_dup_records')
    + semicolon
).setName('check-dup-records <options>;')  # [ Opt View Zone ] v9.5+

optview_stmt_check_integrity = (
    Keyword('check-integrity').suppress()
    - isc_boolean('check_integrity')
    + semicolon
).setName('check-integrity <boolean>;')  # [ Opt View Zone ] v9.4+

optview_stmt_check_mx = (
    Keyword('check-mx').suppress()
    - check_options('check_mx')
    + semicolon
).setName('check-mx <options>;')  # [ Opt View Zone ] v9.4+

optview_stmt_check_mx_cname = (
    Keyword('check-mx-cname').suppress()
    - check_options('check_mx_cname')
    + semicolon
).setName('check-mx-cname <options>;')  # [ Opt View Zone ] v9.4+

#  check-names (master |slave| response) (warn|fail|ignore) ; [ Opt View (Zone) ]
#  Zone-variant of check-names is more simplified syntax than OptView-variant
#  check-names response warn;
optview_stmt_check_names = (
    Keyword('check-names').suppress()
    - Group(
        (
            Literal('master')('')
            | Literal('primary')('')
            | Literal('slave')('')
            | Literal('secondary')('')
            | Literal('response')('')
        )('zone_type')
        + check_options('result_status')
    )('')
    + semicolon
)('check_names')
optview_stmt_check_names.setName('check-names [ primary | secondary | response | master | slave ] <options>;')

optview_stmt_check_spf = (
    Keyword('check-spf').suppress()
    - check_options('check_spf')
    - semicolon
).setName('check-spf <options>;')  # [ Opt View Zone ] v9.4+

optview_stmt_check_srv_cname = (
    Keyword('check-srv-cname').suppress()
    - check_options('check_srv_cname')
    + semicolon
).setName('check-srv-cname <options>;')  # [ Opt View Zone ] v9.4+

optview_stmt_check_wildcard = (
    Keyword('check-wildcard').suppress()
    - isc_boolean('check_wildcard')
    + semicolon
).setName('check-wildcard <options>;')  # [ Opt View Zone ] v9.4+

#  cleaning-interval minutes;
optview_stmt_cleaning_interval = (
    Keyword('cleaning-interval').suppress()
    - minute_type('cleaning_interval')
    + semicolon
).setName('cleaning-interval <minutes>')

#  deny-answer-addresses
optview_stmt_deny_answer_addresses = (
    Keyword('deny-answer-addresses').suppress()
    - Group(
        aml_nesting('')
    )('deny_answer_addresses')
).setName('deny-answer-addresses <aml>;')

#  deny-answer aliases
optview_stmt_deny_answer_aliases = (
    Keyword('deny-answer-aliases').suppress()
    - Group(
        aml_nesting('')
    )('deny_answer_aliases')
).setName('deny-answer-aliases <aml>;')

#   disable-algorithms domain { algorithm ; ... }; [ Opt/View ]
optview_stmt_disable_algorithms = (
    Keyword('disable-algorithms').suppress()
    - Group(
        fqdn_name_dequotable('domain_name')
        + lbrack
        - algorithm_name_list_series('algorithms')
        + rbrack
    )('disable_algorithms')  # must have '*' here  1-*
    + semicolon
)
optview_stmt_disable_algorithms.setName('disable-algorithms <quotable-fqdn> { <algorithm> ; ... };')

#   disable-ds-digests domain { digest ; ... }; [ Opt ]
optview_stmt_disable_ds_digests = (
    Keyword('disable-ds-digests').suppress()
    + Group(
        fqdn_name_dequotable('domain_name')
        + lbrack
        - OneOrMore(
            Combine(
                ungroup(algorithm_name)
                + semicolon
            )('algorithm_name*')  # multiple elements ('*') required here
        )
        + rbrack
    )('disable_ds_digests*')
    + semicolon
)
optview_stmt_disable_ds_digests.setName('disable-ds-digests <quotable-fqdn> { <algorithm> ; ... };')

# disable-empty-zone  zone_name ;
# disable-empty-zone "168.192.IN-ADDR.ARPA";
optview_stmt_disable_empty_zone = (
    Keyword('disable-empty-zone').suppress()
    - Group(
        (
            dequotable_zone_name('')
        )
    )('disable_empty_zone*')  # multiple-statement
    + semicolon
)
optview_stmt_disable_empty_zone.setName('disable-empty-zone <quotable-zone-name>;')

# dns64 {} ###############################################################
optview_dns64_group_element_break_dnssec = (
    Keyword('break-dnssec')
    - isc_boolean('break_dnssec')
    + semicolon
).setName('break-dnssec <boolean>;')

optview_dns64_group_element_clients = (
    Keyword('clients')
    - aml_nesting('clients')  # already includes terminating semicolon
)
optview_dns64_group_element_clients.setName('clients <aml>;')

optview_dns64_group_element_exclude = (
    Keyword('exclude')
    - aml_nesting('exclude')  # already includes terminating semicolon
)
optview_dns64_group_element_exclude.setName('exclude <aml>;')

optview_dns64_group_element_mapped = (
    Keyword('mapped')
    - aml_nesting('mapped')  # already includes terminating semicolon
)
optview_dns64_group_element_exclude.setName('mapped <aml>;')

optview_dns64_group_element_recursive_only = (
    Keyword('recursive-only')
    - isc_boolean('recursive_only')
    + semicolon
).setName('recursive-only <boolean>')

optview_dns64_group_element_suffix = (
    Keyword('suffix')
    - ip6_addr('suffix')
    + semicolon
).setName('suffix <ip6-addr>')

optview_dns64_group_set = (
    optview_dns64_group_element_break_dnssec
    | optview_dns64_group_element_clients
    | optview_dns64_group_element_exclude
    | optview_dns64_group_element_mapped
    | optview_dns64_group_element_recursive_only
    | optview_dns64_group_element_suffix
)

optview_stmt_dns64 = (
    Keyword('dns64').suppress()
    - Group(
        ip6_optional_prefix('netprefix')  # that includes support for '/99' prefix
        + lbrack
        - (
            OneOrMore(optview_dns64_group_set)
        )
        + rbrack
    )('dns64*')
    + semicolon
).setName("""
dns64 <netprefix> {
                break-dnssec <boolean>;
                clients { <address_match_element>; ... };
                exclude { <address_match_element>; ... };
                mapped { <address_match_element>; ... };
                recursive-only <boolean>;
                suffix <ipv6_address>; """)

#
optview_stmt_dns64_contact = (
    Keyword('dns64-contact').suppress()
    - Group(
        soa_rname('soa_rname')
    )('dns64_contact')
    + semicolon
)
optview_stmt_dns64_contact.setName('dns64-contact <soa_rname>;')

optview_stmt_dns64_server = (
    Keyword('dns64-server').suppress()
    - Group(
        soa_rname('soa_rname')
    )('dns64_server')
    + semicolon
)
optview_stmt_dns64_server.setName('dns64-server <soa_rname>;')

# dnsrps-enable <boolean>; [ Opt View  ]  # v9.3.0+
optview_stmt_dnsrps_enable = (
    Keyword('dnsrps-enable').suppress()
    - isc_boolean('dnsrps_enable')
    + semicolon
).setName('dnsrps-enable <boolean>;')

dnsrps_option_charset = charset_filename_base + ' '  # add whatever char you need here, but not '{};'
optview_stmt_dnsrps_options = (
    Keyword('dnsrps-options').suppress()
    - lbrack
    - Optional(
        Literal('"').suppress() | Literal("'").suppress()
    )
    - Word(dnsrps_option_charset, min=1, max=4096)('dnsrps_options')  # TODO Flesh this type of string out
    - Optional(
        Literal('"').suppress() | Literal("'").suppress()
    )
    - Optional(semicolon)
    - rbrack
    - semicolon
)('dnsrps_options')

#  dnssec-accept-expired <boolean>; [ Opt View ]  # v9.4.0+
optview_stmt_dnssec_accept_expired = (
    Keyword('dnssec-accept-expired').suppress()
    - isc_boolean('dnssec_accept_expired')
    + semicolon
).setName('dnssec-accept-expired <boolean>;')

# dnssec-enable <boolean>; [ Opt View  ]  # v9.3.0+
optview_stmt_dnssec_enable = (
    Keyword('dnssec-enable').suppress()
    - isc_boolean('dnssec_enable')
    + semicolon
).setName('dnssec-enable <boolean>;')

# Obsoleted first noted at 9.15.0, must be before...
optview_stmt_dnssec_lookaside = (
        Keyword('dnssec-lookaside').suppress()
        - Group(
                Keyword('auto')  # TODO as hard as I tried, I couldn't get rid of List [] here
                | Keyword('no')  # TODO as hard as I tried, I couldn't get rid of List [] here
                | Group(
                        rr_fqdn_w_absolute('rr_set')
                        + Keyword('trust-anchor')('').suppress()
                        + domain_generic_fqdn('prepend_key_name')
                )('trust_anchor_method')
        )('dnssec_lookaside')
        + semicolon
)('')
optview_stmt_dnssec_lookaside.setName('dnssec-lookaside [ auto | no | <fqdn> trust-anchor <fqdn>;')

#  dnssec-must-be-secure <domain_name> <boolean>; [ Opt View ]  # v9.3.0+
optview_stmt_dnssec_must_be_secure = (
    Keyword('dnssec-must-be-secure').suppress()
    - Group(
        (
            quotable_domain_generic_fqdn('fqdn')
            - isc_boolean('dnssec_secured')
        )
    )('dnssec_must_be_secure*')  # multiple-statement
    - semicolon
).setName('dnssec-must-be-secure <fqdn> domain <boolean>;')

# dnssec-validation ( yes | no );
optview_stmt_dnssec_validation = (
    Keyword('dnssec-validation').suppress()
    - (
        Literal('auto')
        | isc_boolean
    )('dnssec_validation')
    + semicolon
).setName('dnssec-validation [ auto | yes | no ];')

# dnstap [ { ( all | auth | client | forwarder | resolver | update ) [
#             ( query | response ) ]; ... };  #  since v9.11
optview_stmt_dnstap = (
    Keyword('dnstap').suppress()
    - Group(
        lbrack
        - OneOrMore(
            (
                Keyword('all')
                | Keyword('auth')
                | Keyword('client')
                | Keyword('forwarder')
                | Keyword('resolver')
                | Keyword('update')
                | Keyword('query')
                | Keyword('response')
            )
            - semicolon
        )
        - rbrack
    )('dnstap')
    + semicolon
)

#  dual-stack-servers [ port <pg_num> ]
#                     { ( <domain_name> [port <p_num>] |
#                         <ipv4> [port <p_num>] |
#                         <ipv6> [port <p_num>] ); ... };
dual_stack_servers_address_set = (
    (
        # Orderings matter
        Group(
            ip4_addr('ip4_addr')
            + Optional(inet_ip_port_keyword_and_number_element)
        )
        ^ Group(
            ip6_addr('ip6_addr')
            + Optional(inet_ip_port_keyword_and_number_element)
        )
        ^ Group(
            quoted_domain_generic_fqdn('domain')  # TODO is 'masters_name' the correct type for dual-stack-servers?
            + Optional(inet_ip_port_keyword_and_number_element)
        )
    )
    + semicolon
)('')
dual_stack_servers_address_set.setName('[ ip4 | ip6 | <fqdn> ];')

dual_stack_servers_address_series = Group(
    ZeroOrMore(
        (
            dual_stack_servers_address_set
        )('')
    )('')
)('')
dual_stack_servers_address_series.setName('[ ip4 | ip6 | <fqdn> ]; ...')

optview_stmt_dual_stack_servers = (
    Keyword('dual-stack-servers').suppress()
    - Group(
        Optional(inet_ip_port_keyword_and_number_element(''))
        + lbrack
        - (
            dual_stack_servers_address_series
        )('addrs')
        + rbrack
    )('dual_stack_servers')
    + semicolon
)('')
optview_stmt_dual_stack_servers.setName('dual-stack-servers [ port <port> ] { [ ip4 | ip6 | <fqdn> ]; ... };')

soa_name_type = rr_fqdn_w_absolute  # might be name_type

optview_stmt_empty_contact = (
    Keyword('empty-contact').suppress()
    - Group(
        dequotable_domain_generic_fqdn('soa_contact_name')
        - semicolon
    )('empty_contact')  # Dict (not a multiple-statement)
)('')
optview_stmt_empty_contact.setName('empty-contact <soa_rname>;')


optview_stmt_empty_server = (
    Keyword('empty-server').suppress()
    - Group(
        dequotable_domain_generic_fqdn('soa_contact_name')
        - semicolon
    )('empty_server')  # Dict (not a multiple-statement)
)('')
optview_stmt_empty_server.setName('empty-server <soa_rname>;')

optview_stmt_empty_zones_enable = (
    Keyword('empty-zones-enable').suppress()
    - isc_boolean('empty_zones_enable')
    + semicolon
)
optview_stmt_empty_zones_enable.setName('empty-zones-enable <boolean>;')

optview_stmt_fetch_glue = (
        Keyword('fetch-glue').suppress()
        - isc_boolean('fetch_glue')
        + semicolon
)  # v8.1 to v9.7.0
optview_stmt_fetch_glue.setName('fetch-glue  <boolean>;')

optview_stmt_fetch_quota_params = (
    Group(
        Keyword('fetch-quota-params').suppress()
        - number_type('moving_avg_recalculate_interval')
        - fixedpoint_type('low_threshold')
        - fixedpoint_type('high_threshold')
        - fixedpoint_type('moving_average_discount_rate')
        + semicolon
    )('fetch_quota_params')
)
optview_stmt_fetch_quota_params.setName('fetch-quota-params <number> <float> <float> <float>;')

optview_stmt_fetches_per_server = (
    Keyword('fetches-per-server').suppress()
    - ungroup(number_type)('fetches_per_server')
    - Optional(
        Keyword('drop')
        | Keyword('fail')
    )('action')
    - semicolon
)
optview_stmt_fetches_per_server.setName('fetches-per-server <fetches_per_query> [ ( drop | fail ) ];')

optview_stmt_fetches_per_zone = (
    Keyword('fetches-per-zone').suppress()
    - ungroup(number_type)('fetches_per_zone')
    - Optional(
        Keyword('drop')
        | Keyword('fail')
    )('action')
    - semicolon
)
optview_stmt_fetches_per_zone.setName('fetches-per-zone <fetches_per_query> [ ( drop | fail ) ];')

optview_stmt_files = (
    Keyword('files').suppress()
    - Group(
        (
            ungroup(number_type(''))
            | Literal('unlimited')('')
            | Keyword('default')
        )('files_count')
    )('files')
    + semicolon
)('')
optview_stmt_files.setName('files [ unlimited | default | <integer> ];')

optview_stmt_heartbeat_interval = (
    Keyword('heartbeat-interval').suppress()
    - minute_type('heartbeat_interval')
    + semicolon
).setName('heartbeat-interval <minutes>;')

#  hostname ( none | quoted_fqdn );  # [ Opt View ]
optview_stmt_hostname = (
    Keyword('hostname').suppress()
    - Group(
        Literal('none')('none')
        | quoted_domain_generic_fqdn('hostname')('name')
        | domain_generic_fqdn('hostname')('name')
    )('hostname')
    + semicolon
).setName('hostname [ none | hostname | <quotable_fqdn> ];')
#
optview_stmt_ipv4only_contact = (
    Keyword('ipv4only-contact').suppress()
    - Group(
        dequotable_domain_generic_fqdn('soa_rname')
    )('ipv4only_contact')
    + semicolon
)
optview_stmt_ipv4only_contact.setName('ipv4only-contact <soa_rname>;')

# dnsrps-enable <boolean>; [ Opt View  ]  # v9.3.0+
optview_stmt_ipv4only_enable = (
    Keyword('ipv4only-enable').suppress()
    - isc_boolean('ipv4only_enable')
    + semicolon
).setName('ipv4only-enable <boolean>;')

optview_stmt_ipv4only_server = (
    Keyword('ipv4only-server').suppress()
    - Group(
        dequotable_domain_generic_fqdn('soa_rname')
    )('ipv4only_server')
    - semicolon
)
optview_stmt_ipv4only_server.setName('ipv4only-server <soa_rname>;')

optview_stmt_lame_ttl = (
    Keyword('lame-ttl').suppress()
    - number_type('lame_ttl')
    - semicolon
).setName('lame-ttl <integer>;')

optview_stmt_lmdb_mapsize = (
    Keyword('lmdb-mapsize').suppress()
    - size_spec_plain('lmdb_mapsize')
    + semicolon
)
optview_stmt_lmdb_mapsize.setName('lmdb-mapsize <sizeval>;')

optview_stmt_managed_keys_directory = (
    Keyword('managed-keys-directory').suppress()
    - dequoted_path_name('managed_keys_directory')
    + semicolon
).setName('managed-keys-directory <quoted-filespec>;')

optview_stmt_max_cache_size = (
    Keyword('max-cache-size').suppress()
    - size_spec('max_cache_size')
    + semicolon
).setName('max-cache-size <size-spec>')

optview_stmt_max_cache_ttl = (
    Keyword('max-cache-ttl').suppress()
    - iso8601_duration('max_cache_ttl')
    + semicolon
).setName('max-cache-ttl <seconds>;')

optview_stmt_max_ncache_ttl = (
    Keyword('max-ncache-ttl').suppress()
    - iso8601_duration('max_ncache_ttl')
    + semicolon
).setName('max-ncache-ttl <seconds>;')

# max-recursion-depth 3;
optview_stmt_max_recursion_depth = (
    Keyword('max-recursion-depth').suppress()
    - number_type('max_recursion_depth')
    - semicolon
).setName('max-recursion-depth <integer>;')

# max-recursion-queries 4;
optview_stmt_max_recursion_queries = (
    Keyword('max-recursion-queries').suppress()
    - number_type('max_recursion_queries')
    - semicolon
).setName('max-recursion-queries <integer>;')

# max-stale-ttl 16;
optview_stmt_max_stale_ttl = (
    Keyword('max-stale-ttl').suppress()
    - iso8601_duration('max_stale_ttl')
    - semicolon
).setName('max-stale-ttl <iso8601_duration>;')

# max-udp-size 5;
optview_stmt_max_udp_size = (
    Keyword('max-udp-size').suppress()
    - number_type('max_udp_size')
    - semicolon
).setName('max-udp-size <integer>;')

# max-zone-ttl unlimited;
optview_stmt_max_zone_ttl = (
    Keyword('max-zone-ttl').suppress()
    - (
        (
            ungroup(iso8601_duration(''))
            | Literal('unlimited')('')
            | Keyword('default')
        )
    )('max-zone-ttl')
    + semicolon
)('')
optview_stmt_max_zone_ttl.setName('max-zone-ttl [ unlimited | default | <integer> ];')

# message-compression no;
optview_stmt_message_compression = (
    Keyword('message-compression').suppress()
    - isc_boolean('message_compression')
    + semicolon
)
optview_stmt_message_compression.setName('message-compression  <boolean>;')

# min-cache-ttl 1D;
optview_stmt_min_cache_ttl = (
    Keyword('min-cache-ttl').suppress()
    - iso8601_duration('min_cache_ttl')
    + semicolon
).setName('min-cache-ttl <iso8601_duration>;')

# min-ncache-ttl 2d;
optview_stmt_min_ncache_ttl = (
    Keyword('min-ncache-ttl').suppress()
    - iso8601_duration('min_ncache_ttl')
    + semicolon
).setName('min-ncache-ttl <iso8601_duration>;')

# max-refresh-time 60;
optview_stmt_max_refresh_time = (
    Keyword('max-refresh-time').suppress()
    - number_type('max_refresh_time')
    + semicolon
).setName('max-refresh-time <seconds>;')

# min-refresh-time 1W;
optview_stmt_min_refresh_time = (
    Keyword('min-refresh-time').suppress()
    - number_type('min_refresh_time')
    + semicolon
).setName('min-refresh-time <seconds>;')

# min-retry-time 1;
optview_stmt_min_retry_time = (
    Keyword('min-retry-time').suppress()
    - number_type('min_retry_time')
    + semicolon
).setName('min-retry-time <seconds>;')

# minimal-any no;
optview_stmt_minimal_any = (
    Keyword('minimal-any').suppress()
    - isc_boolean('minimal_any')
    + semicolon
).setName('minimal-any <boolean>;')

# minimal-responses no-auth-recursive;
optview_stmt_minimal_responses = (
    Keyword('minimal-responses').suppress()
    - (
        Literal('no-auth-recursive')  # ordering matters
        | Literal('no-auth')
        | isc_boolean('minimal_responses')
    )
    - semicolon
).setName('minimal-responses ( <boolean> | no-auth | no-auth-recursive );')

optview_stmt_new_zones_directory = (
    Keyword('new-zones-directory').suppress()
    - dequoted_path_name('new_zones_directory')
    + semicolon
).setName('new-zones-directory <quoted-filespec>;')

optview_stmt_no_case_compress = (
    Keyword('no-case-compress').suppress()
    + lbrack
    + (
        OneOrMore(
            Group(
                (
                    exclamation('not')
                    + aml_nesting
                )
                | (
                    exclamation('not')
                    + aml_choices
                    + semicolon
                )
                | (
                    aml_nesting
                )
                | (
                    aml_choices
                    + semicolon
                )
                # never set a ResultsLabel here, you get duplicate but un-nested 'ip_addr'
            )  # never set a ResultsLabel here, you get no []
        )(None)
    )('no_case_compress')
    + rbrack
    + semicolon
).setName('no-case-compress { <aml>; };')

# notify-rate 60;
optview_stmt_notify_rate = (
    Keyword('notify-rate').suppress()
    - number_type('notify_rate')
    + semicolon
).setName('notify-rate <seconds>;')

# nsec3-test-zone no;
optview_stmt_nsec3_test_zone = (
    Keyword('nsec3-test-zone').suppress()
    - isc_boolean('nsec3_test_zone')
    + semicolon
).setName('nsec3_test_zone <boolean>')

# nta-lifetime 60m;
optview_stmt_nta_lifetime = (
    Keyword('nta-lifetime').suppress()
    - iso8601_duration('nta_lifetime')
    - semicolon
).setName('nta-lifetime <iso8601_duration>;')

# nta-recheck 24h;
optview_stmt_nta_recheck = (
    Keyword('nta-recheck').suppress()
    - iso8601_duration('nta_recheck')
    - semicolon
).setName('nta-recheck <iso8601_duration>;')

# nxdomain-redirect "redirect.example.test.";
optview_stmt_nxdomain_redirect = (
    Keyword('nxdomain-redirect').suppress()
    - rr_fqdn_w_absolute('nxdomain_redirect')
    - semicolon
).setName('nxdomain-redirect <domain>;')

#  parental-source ( <ipv4_address> | * )
#                  [ port ( <integer> | * ) ]
#                  [ dscp <integer> ];
# parental-source 127.0.0.1 port 88;
optview_stmt_parental_source = (
    Keyword('parental-source').suppress()
    - Group(
        ip4_addr_or_wildcard('ip4_addr_w')
        - Optional(inet_ip_port_keyword_and_wildcard_element)
        - Optional(Keyword('dscp') - dscp_port)
        - semicolon
    )('parental_source')
).setName('parental-source <domain>;')

#  parental-source-v6 ( <ipv4_address> | * )
#                     [ port ( <integer> | * ) ]
#                     [ dscp <integer> ];
optview_stmt_parental_source_v6 = (
    Keyword('parental-source-v6').suppress()
    - Group(
        ip6_addr_or_wildcard('ip6_addr_w')
        - Optional(inet_ip_port_keyword_and_wildcard_element)
        - Optional(Keyword('dscp') - dscp_port)
        - semicolon
    )('parental_source_v6')
).setName('parental-source-v6 <domain>;')

optview_stmt_preferred_glue = (
    Keyword('preferred-glue').suppress()
    - (
        CaselessLiteral('A')
        ^ CaselessLiteral('AAAA')
        ^ CaselessLiteral('none')  # Introduced in 9.15.0-ish
    )('preferred_glue')
    - semicolon
).setName('preferred-glue [ A | AAAA | none ];')

# qname-minimization ( strict | relaxed | disabled | off );
optview_stmt_qname_minimization = (
    Keyword('qname-minimization').suppress()
    - (
        Literal('strict')
        | Literal('relaxed')
        | Literal('disabled')
        | Literal('off')
    )('qname_minimization')
    - semicolon
).setName('qname-minimization ( strict | relaxed | disabled | off );')

#   query-source [ address ( ip46_addr_or_prefix | * ) ] [ port ( ip_port | * ) ];
optview_stmt_query_source = (
    Keyword('query-source').suppress()
    - Group(
        Optional(
            Optional(
                Keyword('address').suppress()
                + (
                    ip4_addr('ip4_addr')
                    | Literal('*')('ip4_addr')
                )
            )('')
        )('')
        + Optional(inet_ip_port_keyword_and_wildcard_element(''))
    )('query_source')
    + semicolon
)('')  # disabling List for it is not a multiple-statement, use Dict
optview_stmt_query_source.setName('query-source address [ <ip4-addr> | * ];')

#   query-source-v6 [ address ( ip46_addr_or_prefix | * ) ] [ port ( ip_port | * ) ];
optview_stmt_query_source_v6 = (
    Keyword('query-source-v6').suppress()
    - Group(
        Optional(
            Keyword('address').suppress()
            + (
                ip6_addr('ip6_addr')
                | Literal('*')('ip6_addr')
           )('')
        )('')
        + Optional(inet_ip_port_keyword_and_wildcard_element(''))
    )('query_source_v6')
    + semicolon
)('')  # disabling List for it is not a multiple-statement, use Dict
optview_stmt_query_source_v6.setName('query-source address [ <ip6-addr> | * ];')

# rate-limit {
#      [ responses-per-second number ; ]
#      [ referrals-per-second number ; ]
#      [ nodata-per-second number ; ]
#      [ nxdomains-per-second number ; ]
#      [ errors-per-second number ; ]
#      [ all-per-second number ; ]
#      [ window number ; ]
#      [ log-only yes_or_no ; ]
#      [ qps-scale number ; ]
#      [ ipv4-prefix-length number ; ]
#      [ ipv6-prefix-length number ; ]
#      [ slip number ; ]
#      [ exempt-clients { aml } ; ]
#      [ max-table-size number ; ]
#      [ min-table-size number ; ]
# };

optview_rate_limit_options_all_per_seconds = (
    Keyword('all-per-second').suppress()
    - Group(
        number_type('all_per_second')
    )
).setName('all-per-second <seconds>')

optview_rate_limit_options = (
    (
        (
            optview_rate_limit_options_all_per_seconds
        )('')
        | (
            Keyword('errors-per-second').suppress()
            - Group(
                number_type('errors_per_second')
            )('')
        )('')
        | (
            Keyword('exempt-clients').suppress()
            + lbrack
            + (
                OneOrMore(
                    Group(
                        (
                                exclamation('not')
                                + aml_nesting
                        )
                        | (
                                exclamation('not')
                                + aml_choices
                                + semicolon
                        )
                        | (
                            aml_nesting
                        )
                        | (
                            aml_choices
                            + semicolon
                        )  # never set a ResultsLabel here, you get duplicate but un-nested 'ip_addr'
                    )  # never set a ResultsLabel here, you get no []
                )(None)
            )('')
            + rbrack
        )('')
        | (
            Keyword('ipv4-prefix-length').suppress()
            - Group(
                number_type('ipv4_prefix_length')
            )('')
        )('')
        | (
            Keyword('ipv6-prefix-length').suppress()
            - Group(
                number_type('ipv6_prefix_length')
            )('')
        )('')
        | (
            Keyword('log-only').suppress()
            - Group(
                isc_boolean('log_only')
            )('')
        )('')
        | (
            Keyword('min-table-size').suppress()
            - Group(
                number_type('min_table_size')
            )('')
        )('')
        | (
            Keyword('max-table-size').suppress()
            - Group(
                number_type('max_table_size')
            )('')
        )('')
        | (
            Keyword('nodata-per-second').suppress()
            - Group(
                number_type('nodata_per_second')
            )('')
        )('')
        | (
            Keyword('nxdomains-per-second').suppress()
            - Group(
                number_type('nxdomains_per_second')
            )('')
        )('')
        | (
            Keyword('qps-scale').suppress()
            - Group(
                number_type('qps_scale')
            )('')
        )('')
        | (
            Keyword('referrals-per-second').suppress()
            - Group(
                number_type('referrals_per_second')
            )('')
        )('')
        | (
            Keyword('responses-per-second').suppress()
            - Group(
                number_type('responses_per_second')
            )('')
        )('')
        | (
            Keyword('slip').suppress()
            - Group(
                number_type('slip')
            )('')
        )('')
        | (
            Keyword('responses-per-second').suppress()
            - Group(
                number_type('response_per_second')
            )('')
        )('')
        | (
            Keyword('slip').suppress()
            - Group(
                number_type('slip')
            )('')
        )('')
        | (
            Keyword('window').suppress()
            - Group(
                number_type('window')
            )('')
        )('')
    )
    + semicolon
).setName("""
      [ responses-per-second <number>; ]
      [ referrals-per-second <number>; ]
      [ nodata-per-second <number>; ]
      [ nxdomains-per-second <number>; ]
      [ errors-per-second <number>; ]
      [ all-per-second <number>; ]
      [ window <number>; ]
      [ log-only <boolean>; ]
      [ qps-scale <number> ; ]
      [ ipv4-prefix-length <number> ; ]
      [ ipv6-prefix-length <number> ; ]
      [ slip <number>; ]
      [ exempt-clients { <aml> }; ]
      [ max-table-size <number>; ]
      [ min-table-size <number>; ]
""")

optview_stmt_rate_limit = (
    Keyword('rate-limit').suppress()
    - lbrack
    - OneOrMore(
        optview_rate_limit_options
    )('rate_limit')
    - rbrack
    - semicolon
)('')
optview_stmt_rate_limit.setName("""
rate-limit {
      [ responses-per-second <number>; ]
      [ referrals-per-second <number>; ]
      [ nodata-per-second <number>; ]
      [ nxdomains-per-second <number>; ]
      [ errors-per-second <number>; ]
      [ all-per-second <number>; ]
      [ window <number>; ]
      [ log-only <boolean>; ]
      [ qps-scale <number> ; ]
      [ ipv4-prefix-length <number> ; ]
      [ ipv6-prefix-length <number> ; ]
      [ slip <number>; ]
      [ exempt-clients { <aml> }; ]
      [ max-table-size <number>; ]
      [ min-table-size <number>; ]
};""")

optview_stmt_recursion = (
    Keyword('recursion').suppress()
    - isc_boolean('recursion')
    - semicolon
).setName('recursion <boolean>;')

# optview_stmt_require_server_cookie
optview_stmt_require_server_cookie = (
    Keyword('require-server-cookie').suppress()
    - isc_boolean('require_server_cookie')
    - semicolon
).setName('require-server-cookie <boolean>;')

# optview_stmt_resolver_nonbackoff_tries
optview_stmt_resolver_nonbackoff_tries = (
    Keyword('resolver-nonbackoff-tries').suppress()
    - number_type('resolver_nonbackoff_tries')
    - semicolon
).setName('resolver-nonbackoff-tries <boolean>;')

#  response-padding { <address_match_element>; ... }
#                   block-size <integer>;
optview_stmt_response_padding = (
    Keyword('response-padding').suppress()
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
        - rbrack
        # NOSEMICOLON HERE!
        - Keyword('block-size').suppress()
        - number_type('fqdn')
        - semicolon
    )('response-padding')
)
optview_stmt_response_padding.setName('response-padding { <aml>; } block-size <integer>;')

optview_stmt_resolver_retry_interval = (
    Keyword('resolver-retry-interval').suppress()
    - number_type('resolver_retry_interval')
    + semicolon
).setName('resolver-retry-interval <number>;')

# 'response-policy' (super-)statements

# following 'response-policy' elements are in both zone-specific and global-specific
optview_stmt_response_policy_element_zone_add_soa = (
    Keyword('add-soa').suppress()  # introduced in v9.14
    - isc_boolean('add_soa')
)

# following 'response-policy' elements are in zone-specific-only
optview_stmt_response_policy_element_zone_log = (
    Keyword('log').suppress()  # introduced in v9.11
    - isc_boolean('log')
)

optview_stmt_response_policy_element_zone_max_policy_ttl = (
    Keyword('max-policy-ttl').suppress()
    - iso8601_duration('max_policy_ttl')
).setName('max-policy-ttl <iso8601_duration>;')

optview_stmt_response_policy_element_zone_min_update_interval = (
    Keyword('min-update-interval').suppress()  # introduced in v9.12
    - iso8601_duration('min_update_interval')
)

optview_stmt_response_policy_element_zone_nsdname_enable = (
    Keyword('nsdname-enable').suppress()
    - isc_boolean('nsdname_enable')
)

optview_stmt_response_policy_element_zone_nsip_enable = (
    Keyword('nsip-enable').suppress()
    - isc_boolean('nsip_enable')
)
optview_stmt_response_policy_element_zone_nsip_enable.setName('nsip-enable <boolean>')

optview_stmt_response_policy_element_zone_policy_type = (
    Keyword('policy').suppress()
    - Group(
        Literal('disabled')
        | Literal('drop')
        | Literal('given')
        | Literal('no-op')
        | Literal('nodata')
        | Literal('nxdomain')
        | Literal('passthru')
        | (
            Literal('tcp-only').suppress()  # introduced in v9.10
            - rr_fqdn_w_absolute('tcp_only')
        )  # TODO re-verify string-format needed for 'tcp-only'
        | Group(
            Literal('cname').suppress()  # - rr_fqdn_w_absolute('cname')
        )
    )('policy')
)
optview_stmt_response_policy_element_zone_policy_type.setName(
    """policy [ given | disabled | passthru | drop | nxdomain | nodata | cname <fqdn> | tcp-only <string>""")

optview_stmt_response_policy_element_zone_recursive_only = (
    Keyword('recursive-only').suppress()
    - isc_boolean('recursive_only')
)

optview_stmt_response_policy_zone_element_set = (
    (
        optview_stmt_response_policy_element_zone_add_soa
        ^ optview_stmt_response_policy_element_zone_log  # added v9.11 (zone-specific only)
        ^ optview_stmt_response_policy_element_zone_max_policy_ttl
        ^ optview_stmt_response_policy_element_zone_min_update_interval  # added v9.12
        ^ optview_stmt_response_policy_element_zone_nsdname_enable  # added v9.12
        ^ optview_stmt_response_policy_element_zone_nsip_enable  # added v9.12
        ^ optview_stmt_response_policy_element_zone_policy_type # added v9.14 (zone-specific only)
        ^ optview_stmt_response_policy_element_zone_recursive_only
    )
)
optview_stmt_response_policy_zone_element_set.setName('[ log <boolean> ] [ policy <string> ] [ add-soa <boolean> ]')


optview_stmt_response_policy_zone_group_set = (
    (
        Keyword('zone').suppress()
        - (
            dequotable_domain_generic_fqdn('zone_name')
            - ZeroOrMore(optview_stmt_response_policy_zone_element_set)
            - semicolon
        )
    )
)
optview_stmt_response_policy_zone_group_set.setName("""
        zone string 
        [ add-soa boolean ]  # v9.14
        [ log boolean ]  # v9.11
        [ max-policy-ttl duration ] 
        [ min-update-interval duration ]   # 9.12
        [ policy ( cname | disabled   # cname used to take a string @9.8
          | drop | given | no-op   # drop @ v9.10
          | nodata | nxdomain 
          | passthru | tcp-only quoted_string ) ]  # tcp-only @ v9.10
        [ recursive-only boolean ]
        [ nsip-enable boolean ]  # v9.12
        [ nsdname-enable boolean ];  # v9.12""")

optview_stmt_response_policy_zone_group_series = (
    ZeroOrMore(
        Group(  # must have group here for multiple zones within 'response-policy'
            optview_stmt_response_policy_zone_group_set
        )('zone*')
    )
)


# following 'response-policy' elements are in global-specific-only
optview_stmt_response_policy_element_global_add_soa = (
    Keyword('add-soa').suppress()  # introduced in v9.14
    - isc_boolean('add_soa')
)

optview_stmt_response_policy_element_global_break_dnssec = (
    Keyword('break-dnssec').suppress()  # not found in zone-specific
    - isc_boolean('break_dnssec')
    )

optview_stmt_response_policy_element_global_dnsrps_enable = (
    Keyword('dnsrps-enable').suppress()
    - isc_boolean('dnsrps_enable')
)

optview_stmt_response_policy_element_global_dnsrps_options = (
    Keyword('dnsrps-options').suppress()
    - lbrack
    - Group(
        (
            Literal('"')
            - Word(dnsrps_option_charset + ' ', min=1, max=4096)('dnsrps_options')  # TODO Flesh this type of string out
            - Literal('"')
        )
        | (
            Literal("'")
            - Word(dnsrps_option_charset, min=1, max=4096)('dnsrps_options')  # TODO Flesh this type of string out
            - Literal("'")
        )
        | Word(dnsrps_option_charset, min=1, max=4096)('dnsrps_options')  # TODO Flesh this type of string out
    )('dnsrps_options2')
    - rbrack
)

optview_stmt_response_policy_element_global_max_policy_ttl = (
    Keyword('max-policy-ttl').suppress()
    - iso8601_duration('max_policy_ttl')
).setName('max-policy-ttl <iso8601_duration>;')

optview_stmt_response_policy_element_global_min_ns_dots = (
    Keyword('min-ns-dots').suppress()
    - number_type('min_ns_dots')
    )

optview_stmt_response_policy_element_global_min_update_interval = (
    Keyword('min-update-interval').suppress()  # introduced in v9.12
    - iso8601_duration('min_update_interval')
)

optview_stmt_response_policy_element_global_nsip_enable = (
    Keyword('nsip-enable').suppress()
    - isc_boolean('nsip_enable')
)
optview_stmt_response_policy_element_global_nsip_enable.setName('nsip-enable <boolean>')

optview_stmt_response_policy_element_global_nsip_wait_recurse = (
    Keyword('nsip-wait-recurse').suppress()
    - isc_boolean('nsip_wait_recurse')
)

optview_stmt_response_policy_element_global_nsdname_enable = (
    Keyword('nsdname-enable').suppress()
    - isc_boolean('nsdname_enable')
)

optview_stmt_response_policy_element_global_nsdname_wait_recurse = (
    Keyword('nsdname-wait-recurse').suppress()
    - isc_boolean('nsdname_wait_recurse')
)

optview_stmt_response_policy_element_global_qname_wait_recurse = (
    Keyword('qname-wait-recurse').suppress()
    - isc_boolean('qname_wait_recurse')
)

optview_stmt_response_policy_element_global_recursive_only = (
    Keyword('recursive-only').suppress()
    - isc_boolean('recursive_only')
)

optview_stmt_response_policy_global_element_set = (
    (
        optview_stmt_response_policy_element_global_add_soa  # added v9.14
        ^ optview_stmt_response_policy_element_global_break_dnssec  # global-specific only
        ^ optview_stmt_response_policy_element_global_dnsrps_enable  # added v9.12
        ^ optview_stmt_response_policy_element_global_dnsrps_options  # added v9.12
        ^ optview_stmt_response_policy_element_global_max_policy_ttl
        ^ optview_stmt_response_policy_element_global_min_ns_dots  # global-specific only
        ^ optview_stmt_response_policy_element_global_min_update_interval  # added v9.12
        ^ optview_stmt_response_policy_element_global_nsdname_enable  # added v9.12
        ^ optview_stmt_response_policy_element_global_nsdname_wait_recurse  # added v9.16?
        ^ optview_stmt_response_policy_element_global_nsip_enable  # added v9.12
        ^ optview_stmt_response_policy_element_global_nsip_wait_recurse  # added v9.11
        ^ optview_stmt_response_policy_element_global_qname_wait_recurse  # added v9.10
        ^ optview_stmt_response_policy_element_global_recursive_only
    )
)

optview_stmt_response_policy_global_element_series = (
    ZeroOrMore(
        optview_stmt_response_policy_global_element_set
    )
)

optview_stmt_response_policy = (
    Group(
        Keyword('response-policy').suppress()
        - lbrack
        - optview_stmt_response_policy_zone_group_series
        - rbrack
        - optview_stmt_response_policy_global_element_series
        - semicolon
    )
)('response_policy')

optview_stmt_response_policy.setName("""
response-policy { 
    zone string 
    [ add-soa boolean ]  # v9.14
    [ log boolean ]  # v9.11
    [ max-policy-ttl duration ] 
    [ min-update-interval duration ]   # 9.12
    [ policy ( cname | disabled   # cname used to take a string @9.8
      | drop | given | no-op   # drop @ v9.10
      | nodata | nxdomain 
      | passthru | tcp-only quoted_string ) ]  # tcp-only @ v9.10
    [ recursive-only boolean ]
    [ nsip-enable boolean ]  # v9.12
    [ nsdname-enable boolean ];  # v9.12
     ... 
    } 
    [ add-soa boolean ]   # v9.14
    [ break-dnssec boolean ]
    [ max-policy-ttl duration ]
    [ min-update-interval duration ]  # v9.12
    [ min-ns-dots integer ]
    [ nsip-wait-recurse boolean ]  # v9.11
    [ nsdname-wait-recurse boolean ]  # v9.16?
    [ qname-wait-recurse boolean ]  # v9.10
    [ recursive-only boolean ]
    [ nsip-enable boolean ]  # v9.12
    [ nsdname-enable boolean ]  # v9.12
    [ dnsrps-enable boolean ]  # v9.12
    [ dnsrps-options { unspecified-text } ]  # v9.12
};""")

#  rfc2308-type1 <boolean>; [ Opt View ]
optview_stmt_rfc2308_type1 = (
        Keyword('rfc2308-type1').suppress()
        - isc_boolean('rfc2308_type1')
        + semicolon
).setName('rfc2308-type1 <boolean>')

#  root-delegation-only [ exclude { "domain_name"; ... } ];
#  root-delegation-only exclude { "com"; "net" };
optview_stmt_root_delegation_only = (
    Keyword('root-delegation-only').suppress()
    - (
        Optional(
            Keyword('exclude').suppress()
            - lbrack
            - Group(
                OneOrMore(
                    domain_generic_fqdn('')
                    + semicolon
                )('domains')
            )('root_delegation_only')
            - rbrack
        )('')
    )('')
    - semicolon
).setName('root-delegation-only [ exclude { <quoted-fqdn>; ...} ];')

optview_stmt_root_key_sentinel = (
    Keyword('root-key-sentinel').suppress()
    - isc_boolean('root_key_sentinel')
    + semicolon
).setName('root-key-sentinel <boolean>')

optview_class_type = (
    CaselessLiteral('HS')
    | CaselessLiteral('IN')
    | CaselessLiteral('CH')
    | CaselessLiteral('ANY')
).setName('[ IN | CH | HS | ANY')

#  [ class class_name ][ type type_name ][ name "domain_name"] order ordering;
optview_type_type = Word(alphanums + '-', max=16)

optview_ordering_type = (
    Keyword('fixed')
    ^ Keyword('random')
    ^ Keyword('cyclic')
    ^ Keyword('none')
)('order').setName('[ fixed | random | cyclic ]')

optview_order_element_set = (
    (
        Keyword('zone').suppress()
            - dequotable_zone_name('name')
        )
    | (
        Keyword('class').suppress()
        - optview_class_type('class')
    )
    | (
        Keyword('type').suppress()
        - optview_type_type('type')
    )
    | (
        Keyword('name').suppress()
        - dequotable_domain_generic_fqdn('name')
    )
    | (
        Keyword('order').suppress()
        - optview_ordering_type('order')
    )
)
optview_order_element_set.setName('[ class <class> ] [ type <RR_type> ] [ name <domain> ] [ order ( cyclic | random ) ];')

optview_order_element_series = (
    Group(
        OneOrMore(
            optview_order_element_set
        )
    )
)
optview_order_element_series.setName('[ class <class> ] [ type <RR_type> ] [ name <domain> ] [ order ( cyclic | random ) ];')

optview_rrset_order_group_series = (
    Group(
        ZeroOrMore(
            optview_order_element_series
            - semicolon
        )
    )('rrset_order')
)

#  rrset-order { optview_order_spec ; [ optview_order_spec ; ... ]
optview_stmt_rrset_order = (
    Keyword('rrset-order').suppress()
    - (
        lbrack
        - optview_rrset_order_group_series
        - rbrack
    )
    - semicolon
)  # only one (, the last one) 'rrset-order' allowed, so no List [] here
optview_stmt_rrset_order.setName("""rrset-order { [ zone <string> ] [ class <class> ] 
    [ type <rr_type> ] [ name <domain> ] 
    [ order ( cyclic | random); ... };""")

#  optview_stmt_sortlist { aml; ... };
#  optview_stmt_sortlist { {10.2/16; };};
optview_stmt_sortlist = (
    Keyword('sortlist').suppress()
    - Group(
        aml_nesting('')
    )('sortlist')
)('')
optview_stmt_sortlist.setName('sortlist <aml>;')

# optview_stmt_servfail_ttl
optview_stmt_servfail_ttl = (
        Keyword('servfail-ttl').suppress()
        - number_type('servfail_ttl')
        - semicolon
).setName('servfail-ttl <seconds>')
# optview_stmt_stale_answer_client_timeout
optview_stmt_stale_answer_client_timeout = (
    Keyword('stale-answer-client-timeout').suppress()
    - (
        Literal('disabled')
        | Literal('off')
        | number_type
    )('stale_answer_client_timeout')
    - semicolon
).setName('stale-answer-client-timeout ( <second> | disabled | off )')

# optview_stmt_stale_answer_enable
optview_stmt_stale_answer_enable = (
        Keyword('stale-answer-enable').suppress()
        - isc_boolean('stale_answer_enable')
        - semicolon
).setName('stale-answer-enable <boolean>')

# optview_stmt_stale_answer_ttl
optview_stmt_stale_answer_ttl = (
    Keyword('stale-answer-ttl').suppress()
    - number_type('stale_answer_ttl')
    - semicolon
).setName('stale-answer-ttl <seconds>')

# optview_stmt_stale_cache_enable
optview_stmt_stale_cache_enable = (
    Keyword('stale-cache-enable').suppress()
    - isc_boolean('stale_cache_enable')
    - semicolon
).setName('stale-cache-enable <boolean>')

# optview_stmt_stale_refresh_time
optview_stmt_stale_refresh_time = (
    Keyword('stale-refresh-time').suppress()
    - number_type('stale_refresh_time')
    - semicolon
).setName('stale-refresh-time <boolean>')

# optview_stmt_suppress_initial_notify
optview_stmt_suppress_initial_notify = (
    Keyword('suppress-initial-notify').suppress()
    - isc_boolean('suppress_initial_notify')
    - semicolon
).setName('suppress-initial-notify <boolean>')

# optview_stmt_synth_from_dnssec
optview_stmt_synth_from_dnssec = (
   Keyword('synth-from-dnssec').suppress()
   - isc_boolean('synth_from_dnssec')
   - semicolon
).setName('synth-from-dnssec <boolean>')

# optview_stmt_trust_anchor_telemetry
optview_stmt_trust_anchor_telemetry = (
   Keyword('trust-anchor-telemetry').suppress()
   - isc_boolean('trust_anchor_telemetry')
   - semicolon
).setName('trust-anchor-telemetry <boolean>')

# optview_stmt_v6_bias
optview_stmt_v6_bias = (
   Keyword('v6-bias').suppress()
   - number_type('v6_bias')
   - semicolon
).setName('v6-bias <boolean>')

# validate-except { "168.192.in-addr.arpa."; };
optview_validate_except_element_set = (
    dequotable_domain_generic_fqdn
    - semicolon
)

optview_validate_except_element_series = (
    (
        OneOrMore(
            optview_validate_except_element_set
        )
    )('zone')
)

optview_stmt_validate_except = (
    Keyword('validate-except')
    - lbrack
    - optview_validate_except_element_series('validate_except')
    - rbrack
    - semicolon
)

# optview_stmt_zero_no_soa_ttl_cache
optview_stmt_zero_no_soa_ttl_cache = (
    Keyword('zero-no-soa-ttl-cache').suppress()
    - isc_boolean('zero_no_soa_ttl_cache')
    - semicolon
).setName('zero-no-soa-ttl-cache <boolean>')


#

# Keywords are in dictionary-order, but with longest pattern as having been listed firstly
optview_statements_set = (
    optview_stmt_acache_cleaning_interval
    ^ optview_stmt_acache_enable
    ^ optview_stmt_additional_from_auth
    ^ optview_stmt_additional_from_cache
    ^ optview_stmt_allow_new_zones
    ^ optview_stmt_allow_query_cache_on
    ^ optview_stmt_allow_query_cache
    ^ optview_stmt_allow_recursion_on
    ^ optview_stmt_allow_recursion
    ^ optview_stmt_attach_cache
    ^ optview_stmt_auth_nxdomain
    ^ optview_stmt_cache_file
    ^ optview_stmt_check_dup_records
    ^ optview_stmt_check_integrity
    ^ optview_stmt_check_mx_cname
    ^ optview_stmt_check_mx
    ^ optview_stmt_check_names
    ^ optview_stmt_check_spf
    ^ optview_stmt_check_srv_cname
    ^ optview_stmt_check_wildcard
    ^ optview_stmt_cleaning_interval
    ^ optview_stmt_deny_answer_addresses
    ^ optview_stmt_deny_answer_aliases
    ^ optview_stmt_disable_algorithms
    ^ optview_stmt_disable_ds_digests
    ^ optview_stmt_disable_empty_zone
    ^ optview_stmt_dns64_contact
    ^ optview_stmt_dns64_server
    ^ optview_stmt_dns64
    ^ optview_stmt_dnsrps_enable
    ^ optview_stmt_dnsrps_options
    ^ optview_stmt_dnssec_accept_expired
    ^ optview_stmt_dnssec_enable
    ^ optview_stmt_dnssec_lookaside
    ^ optview_stmt_dnssec_must_be_secure
    ^ optview_stmt_dnssec_validation
    ^ optview_stmt_dnstap
    ^ optview_stmt_dual_stack_servers
    ^ optview_stmt_empty_contact
    ^ optview_stmt_empty_server
    ^ optview_stmt_empty_zones_enable
    ^ optview_stmt_fetch_glue
    ^ optview_stmt_fetch_quota_params
    ^ optview_stmt_fetches_per_server
    ^ optview_stmt_fetches_per_zone
    ^ optview_stmt_files
    ^ optview_stmt_heartbeat_interval
    ^ optview_stmt_hostname
    ^ optview_stmt_ipv4only_contact
    ^ optview_stmt_ipv4only_enable
    ^ optview_stmt_ipv4only_server
    ^ optview_stmt_lame_ttl
    ^ optview_stmt_lmdb_mapsize
    ^ optview_stmt_managed_keys_directory
    ^ optview_stmt_max_cache_size
    ^ optview_stmt_max_cache_ttl
    ^ optview_stmt_max_ncache_ttl
    ^ optview_stmt_max_recursion_depth
    ^ optview_stmt_max_recursion_queries
    ^ optview_stmt_max_refresh_time
    ^ optview_stmt_max_stale_ttl
    ^ optview_stmt_max_udp_size
    ^ optview_stmt_max_zone_ttl
    ^ optview_stmt_message_compression
    ^ optview_stmt_min_cache_ttl
    ^ optview_stmt_min_ncache_ttl
    ^ optview_stmt_min_refresh_time
    ^ optview_stmt_min_retry_time
    ^ optview_stmt_minimal_any
    ^ optview_stmt_minimal_responses
    ^ optview_stmt_new_zones_directory
    ^ optview_stmt_no_case_compress
    ^ optview_stmt_notify_rate
    ^ optview_stmt_nsec3_test_zone
    ^ optview_stmt_nta_lifetime
    ^ optview_stmt_nta_recheck
    ^ optview_stmt_nxdomain_redirect
    ^ optview_stmt_parental_source
    ^ optview_stmt_parental_source_v6
    ^ optview_stmt_preferred_glue
    ^ optview_stmt_query_source_v6
    ^ optview_stmt_query_source
    ^ optview_stmt_qname_minimization
    ^ optview_stmt_rate_limit
    ^ optview_stmt_recursion
    ^ optview_stmt_require_server_cookie
    ^ optview_stmt_resolver_nonbackoff_tries
    ^ optview_stmt_resolver_retry_interval
    ^ optview_stmt_response_padding
    ^ optview_stmt_response_policy
    ^ optview_stmt_rfc2308_type1
    ^ optview_stmt_root_delegation_only
    ^ optview_stmt_root_key_sentinel
    ^ optview_stmt_rrset_order
    ^ optview_stmt_sortlist
    ^ optview_stmt_servfail_ttl
    ^ optview_stmt_stale_answer_client_timeout
    ^ optview_stmt_stale_answer_enable
    ^ optview_stmt_stale_answer_ttl
    ^ optview_stmt_stale_cache_enable
    ^ optview_stmt_stale_refresh_time
    ^ optview_stmt_suppress_initial_notify
    ^ optview_stmt_synth_from_dnssec
    ^ optview_stmt_trust_anchor_telemetry
    ^ optview_stmt_v6_bias
    ^ optview_stmt_validate_except
    ^ optview_stmt_zero_no_soa_ttl_cache
)

optview_statements_series = (
    ZeroOrMore(
        optview_statements_set
    )
)

optview_multiple_stmt_disable_ds_digests = ZeroOrMore(
    optview_stmt_disable_ds_digests
)('disable_ds_digests')

optview_multiple_stmt_disable_algorithms = ZeroOrMore(
    optview_stmt_disable_algorithms
)('disable_algorithms')
